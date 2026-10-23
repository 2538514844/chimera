package dev.chimera.transform.encrypt;

import dev.chimera.crypto.Crypto;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * S5: turns one class file into an encrypted, chunked resource payload.
 *
 * <p>The payload is AES-256-GCM encrypted chunk-by-chunk. Keys are derived from the product
 * ResourceKey exactly like the existing op9 DECRYPT_DATA contract:</p>
 * <pre>
 * kek     = HKDF(ResourceKey, salt = "chimera-kek-v1", info = "kek", 32)
 * itemKey = HKDF(kek, salt = envSalt, info = "chimera/v1/class/&lt;payloadId&gt;", 32)
 * </pre>
 *
 * <p>Payload layout (big-endian, {@link DataOutputStream}):</p>
 * <pre>
 * int magic("CHCP" = 0x43484350), int version(1), int payloadId,
 * int chunkSize, int totalLength, int chunkCount
 * repeat chunkCount:
 *   byte[12] nonce, int ctLength, byte[ctLength] ciphertext|tag
 * AAD(i) = "chimera/s5/class/&lt;payloadId&gt;/&lt;i&gt;/&lt;totalLength&gt;/&lt;chunkCount&gt;"
 * </pre>
 *
 * <p>Mixin classes are skipped (the caller must leave the original class untouched), so their
 * {@code Signature} attribute and debug information never pass through this builder. For classes
 * that are encrypted, the internal name and self-references are first remapped into
 * {@link #HIDDEN_NAME_PREFIX} + payloadId (required by {@code defineHiddenClass}, which only accepts
 * bytes in the lookup class's package). ASM remaps signatures/frames/descriptors and copies
 * SourceFile, LineNumberTable and LocalVariableTable, so debug information is preserved; only the
 * class name changes (callers must pass the returned {@link Class} around, never resolve the old
 * name).</p>
 */
public final class ClassPayloadBuilder {

    /** "CHCP" - payload magic; must match {@code ChimeraHiddenLoader.MAGIC}. */
    public static final int MAGIC = 0x43484350;
    /** Payload format version; must match {@code ChimeraHiddenLoader.VERSION}. */
    public static final int VERSION = 1;
    /** op9 kind string (at most 16 bytes in the native payload contract). */
    public static final String KIND = "class";
    /** Default plaintext bytes per AES-GCM chunk. */
    public static final int DEFAULT_CHUNK_SIZE = 8 * 1024;
    /** Upper bound for one class file payload. */
    public static final int MAX_TOTAL_BYTES = 16 * 1024 * 1024;
    /** Native op9 rejects ciphertext chunks above 48 KiB. */
    public static final int MAX_CHUNK_SIZE = 48 * 1024;
    public static final int MIN_CHUNK_SIZE = 256;
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;

    /** Existing HKDF labels used by ChimeraEngine/ChimeraRuntime for the build KEK. */
    public static final String KEK_SALT = "chimera-kek-v1";
    public static final String KEK_INFO = "kek";

    /** SpongePowered Mixin annotation descriptor (checked without a Mixin dependency). */
    public static final String MIXIN_DESCRIPTOR = "Lorg/spongepowered/asm/mixin/Mixin;";
    /** Prefix of the jar resource that holds an encrypted class payload. */
    public static final String RESOURCE_PREFIX = "chimera/classes/";
    public static final String RESOURCE_SUFFIX = ".bin";
    /**
     * Every hidden class is renamed into the loader's runtime package before it is encrypted:
     * {@code MethodHandles.Lookup.defineHiddenClass} requires the class file package to equal the
     * lookup class package. The internal name also stops the payload from leaking the original
     * class name. Self-references (descriptors/signatures/frames) are remapped; debug info and
     * non-class-signature attributes are copied verbatim.
     */
    public static final String HIDDEN_NAME_PREFIX = "dev/chimera/runtime/ChimeraHidden_";

    private ClassPayloadBuilder() {
    }

    /**
     * Result of {@link #encrypt}: {@code mixinSkipped == true} means the caller must keep the
     * original class file untouched and must not write an encrypted resource.
     */
    public record EncryptedClass(String resourceName, byte[] payload, int payloadId,
                                 boolean mixinSkipped, String skipReason) {
        /** True when an encrypted resource was produced. */
        public boolean encrypted() {
            return payload != null;
        }
    }

    /** Encrypts one class with the default chunk size. */
    public static EncryptedClass encrypt(byte[] classBytes, byte[] resourceKey, byte[] envSalt,
                                         int payloadId) {
        return encrypt(classBytes, resourceKey, envSalt, payloadId, DEFAULT_CHUNK_SIZE);
    }

    /**
     * Encrypts one class file. Mixin classes are detected and returned as skipped: no payload is
     * produced, and the input array is never modified.
     */
    public static EncryptedClass encrypt(byte[] classBytes, byte[] resourceKey, byte[] envSalt,
                                         int payloadId, int chunkSize) {
        if (classBytes == null || classBytes.length < 10) {
            throw new IllegalArgumentException("classBytes must be a class file");
        }
        validateKeyMaterial(resourceKey, envSalt);
        if (payloadId < 0) throw new IllegalArgumentException("payloadId must be >= 0");
        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
            throw new IllegalArgumentException("chunkSize must be in [" + MIN_CHUNK_SIZE + ", "
                    + MAX_CHUNK_SIZE + "]: " + chunkSize);
        }
        if (classBytes.length > MAX_TOTAL_BYTES) {
            throw new IllegalArgumentException("class file too large for a hidden-class payload: "
                    + classBytes.length);
        }
        String internalName = classInternalName(classBytes);
        if (isMixinClass(classBytes)) {
            return new EncryptedClass(null, null, payloadId, true, "@Mixin is not encrypted");
        }
        // defineHiddenClass only accepts bytes whose package matches the lookup class
        // (dev.chimera.runtime), so rewrite the internal name (and every self-reference) first.
        byte[] hiddenBytes = renameForHiddenClass(classBytes, payloadId);

        byte[] itemKey = derivePayloadKey(resourceKey, envSalt, payloadId);
        try {
            int totalLength = hiddenBytes.length;
            int chunkCount = (totalLength + chunkSize - 1) / chunkSize;
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(totalLength + chunkCount * 40);
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(payloadId);
            out.writeInt(chunkSize);
            out.writeInt(totalLength);
            out.writeInt(chunkCount);
            for (int index = 0; index < chunkCount; index++) {
                int offset = index * chunkSize;
                int length = Math.min(chunkSize, totalLength - offset);
                byte[] plain = Arrays.copyOfRange(hiddenBytes, offset, offset + length);
                byte[] nonce = Crypto.random(NONCE_LENGTH);
                byte[] ciphertext = Crypto.aesGcmEncrypt(itemKey, nonce, plain,
                        chunkAad(payloadId, index, totalLength, chunkCount));
                Arrays.fill(plain, (byte) 0);
                out.write(nonce);
                out.writeInt(ciphertext.length);
                out.write(ciphertext);
            }
            out.flush();
            byte[] payload = buffer.toByteArray();
            String resourceName = RESOURCE_PREFIX + internalName + RESOURCE_SUFFIX;
            return new EncryptedClass(resourceName, payload, payloadId, false, null);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("class payload encoding failed", e);
        } finally {
            Arrays.fill(itemKey, (byte) 0);
        }
    }

    /**
     * True when the class carries a SpongePowered {@code @Mixin} annotation (visible or invisible).
     * Such classes must never be encrypted: Fabric/Mixin needs the original bytes and attributes.
     */
    public static boolean isMixinClass(byte[] classBytes) {
        if (classBytes == null || classBytes.length < 10) {
            throw new IllegalArgumentException("classBytes must be a class file");
        }
        final boolean[] mixin = {false};
        ClassReader reader = new ClassReader(classBytes);
        reader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public org.objectweb.asm.AnnotationVisitor visitAnnotation(String descriptor,
                                                                      boolean visible) {
                if (MIXIN_DESCRIPTOR.equals(descriptor)) mixin[0] = true;
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return mixin[0];
    }

    /** Hidden internal name used for the encrypted payload of one class. */
    public static String hiddenInternalName(int payloadId) {
        if (payloadId < 0) throw new IllegalArgumentException("payloadId must be >= 0");
        return HIDDEN_NAME_PREFIX + payloadId;
    }

    /**
     * Rewrites the class internal name (and every self-reference) into
     * {@link #HIDDEN_NAME_PREFIX} + payloadId. Signature attributes are remapped by ASM;
     * SourceFile/LineNumberTable/LocalVariableTable and unknown attributes are preserved.
     */
    public static byte[] renameForHiddenClass(byte[] classBytes, int payloadId) {
        if (classBytes == null || classBytes.length < 10) {
            throw new IllegalArgumentException("classBytes must be a class file");
        }
        ClassReader reader = new ClassReader(classBytes);
        String originalName = reader.getClassName();
        String hiddenName = hiddenInternalName(payloadId);
        ClassWriter writer = new ClassWriter(reader, 0);
        reader.accept(new ClassRemapper(writer, new Remapper() {
            @Override
            public String map(String internalName) {
                return originalName.equals(internalName) ? hiddenName : internalName;
            }
        }), 0);
        return writer.toByteArray();
    }

    /** Internal class name (for example {@code fixtures/Lic}); used for the resource name. */
    public static String classInternalName(byte[] classBytes) {
        if (classBytes == null) throw new IllegalArgumentException("classBytes must not be null");
        return new ClassReader(classBytes).getClassName();
    }

    /** Jar resource name for one encrypted class, e.g. {@code chimera/classes/fixtures/Lic.bin}. */
    public static String resourceName(byte[] classBytes) {
        return RESOURCE_PREFIX + classInternalName(classBytes) + RESOURCE_SUFFIX;
    }

    // ------------------------------------------------------------------ native registration digest

    /**
     * One method's {@code Code} payload digest as consumed by the native hidden-class registry.
     *
     * <p>Native contract (native-pipeline, 2026-10-20): parse the <b>original</b> class file, take
     * the {@code code[]} bytes of each method's {@code Code} attribute
     * ({@code u2 max_stack, u2 max_locals, u4 code_length, code[code_length]}), and SHA-256 the
     * {@code code[]} bytes only - no length prefix, no method name, no endian transform, one digest
     * per method. Renaming the class into the hidden package rewrites only the constant pool, so the
     * digest stays valid after {@link #renameForHiddenClass}.</p>
     */
    public record MethodCodeDigest(String methodName, String descriptor, byte[] sha256) {
    }

    /** Digests of every method that has a {@code Code} attribute (abstract/native methods skipped). */
    public static List<MethodCodeDigest> methodCodeDigests(byte[] classBytes) {
        if (classBytes == null || classBytes.length < 10) {
            throw new IllegalArgumentException("classBytes must be a class file");
        }
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(classBytes));
            if (in.readInt() != (int) 0xCAFEBABEL) {
                throw new IllegalArgumentException("bad class magic");
            }
            in.readUnsignedShort(); // minor
            in.readUnsignedShort(); // major
            String[] utf8 = readConstantPool(in);
            in.skipBytes(6); // access_flags, this_class, super_class
            int interfaces = in.readUnsignedShort();
            skip(in, (long) interfaces * 2);
            int fields = in.readUnsignedShort();
            for (int i = 0; i < fields; i++) skipMember(in);
            int methods = in.readUnsignedShort();
            List<MethodCodeDigest> digests = new ArrayList<>();
            for (int i = 0; i < methods; i++) {
                in.skipBytes(2); // access_flags
                int nameIndex = in.readUnsignedShort();
                int descriptorIndex = in.readUnsignedShort();
                int attributeCount = in.readUnsignedShort();
                String methodName = utf8[nameIndex];
                String descriptor = utf8[descriptorIndex];
                for (int a = 0; a < attributeCount; a++) {
                    int attributeNameIndex = in.readUnsignedShort();
                    long attributeLength = in.readInt() & 0xFFFFFFFFL;
                    String attributeName = utf8[attributeNameIndex];
                    if (!"Code".equals(attributeName)) {
                        skip(in, attributeLength);
                        continue;
                    }
                    if (attributeLength < 8) throw new IllegalArgumentException("Code attribute too short");
                    in.readUnsignedShort(); // max_stack
                    in.readUnsignedShort(); // max_locals
                    long codeLength = in.readInt() & 0xFFFFFFFFL;
                    if (codeLength > 65535L) {
                        throw new IllegalArgumentException("code_length exceeds JVMS limit");
                    }
                    byte[] code = new byte[(int) codeLength];
                    in.readFully(code);
                    digests.add(new MethodCodeDigest(methodName, descriptor, Crypto.sha256(code)));
                    long remaining = attributeLength - 8L - codeLength;
                    if (remaining < 0) throw new IllegalArgumentException("bad Code attribute length");
                    skip(in, remaining); // exception table + code attributes
                }
            }
            int classAttributes = in.readUnsignedShort();
            for (int i = 0; i < classAttributes; i++) {
                in.readUnsignedShort();
                skip(in, in.readInt() & 0xFFFFFFFFL);
            }
            if (in.available() != 0) throw new IllegalArgumentException("trailing class bytes");
            return digests;
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("class file parsing failed", e);
        }
    }

    /** Digest for one method; {@code descriptor} may be {@code null} to match by name only. */
    public static byte[] methodCodeSha256(byte[] classBytes, String methodName, String descriptor) {
        if (methodName == null) throw new IllegalArgumentException("methodName must not be null");
        for (MethodCodeDigest digest : methodCodeDigests(classBytes)) {
            if (digest.methodName().equals(methodName)
                    && (descriptor == null || digest.descriptor().equals(descriptor))) {
                return digest.sha256().clone();
            }
        }
        throw new IllegalArgumentException("method Code digest not found: " + methodName
                + (descriptor == null ? "" : descriptor));
    }

    /** Convenience overload: first method matching the name (any descriptor). */
    public static byte[] methodCodeSha256(byte[] classBytes, String methodName) {
        return methodCodeSha256(classBytes, methodName, null);
    }

    private static String[] readConstantPool(DataInputStream in) throws java.io.IOException {
        int count = in.readUnsignedShort();
        if (count <= 0) throw new IllegalArgumentException("bad constant pool count");
        String[] utf8 = new String[count];
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            switch (tag) {
                case 1: // Utf8
                    utf8[i] = in.readUTF();
                    break;
                case 3: // Integer
                case 4: // Float
                    skip(in, 4);
                    break;
                case 5: // Long
                case 6: // Double
                    skip(in, 8);
                    i++; // takes two constant pool slots
                    break;
                case 7: // Class
                case 8: // String
                case 16: // MethodType
                case 19: // Module
                case 20: // Package
                    skip(in, 2);
                    break;
                case 9: // Fieldref
                case 10: // Methodref
                case 11: // InterfaceMethodref
                case 12: // NameAndType
                case 17: // Dynamic
                case 18: // InvokeDynamic
                    skip(in, 4);
                    break;
                case 15: // MethodHandle
                    skip(in, 3);
                    break;
                default:
                    throw new IllegalArgumentException("unsupported constant pool tag: " + tag);
            }
        }
        return utf8;
    }

    private static void skipMember(DataInputStream in) throws java.io.IOException {
        in.readUnsignedShort(); // access_flags
        in.readUnsignedShort(); // name_index
        in.readUnsignedShort(); // descriptor_index
        int attributeCount = in.readUnsignedShort();
        for (int i = 0; i < attributeCount; i++) {
            in.readUnsignedShort(); // attribute_name_index
            skip(in, in.readInt() & 0xFFFFFFFFL);
        }
    }

    private static void skip(DataInputStream in, long length) throws java.io.IOException {
        if (length < 0 || length > in.available()) {
            throw new IllegalArgumentException("truncated class file (need " + length
                    + " bytes, have " + in.available() + ")");
        }
        int remaining = (int) length;
        while (remaining > 0) {
            int skipped = in.skipBytes(remaining);
            if (skipped <= 0) throw new IllegalArgumentException("truncated class file");
            remaining -= skipped;
        }
    }

    /**
     * Derives the per-payload item key used for every chunk:
     * {@code HKDF(HKDF(ResourceKey, "chimera-kek-v1", "kek"), envSalt, "chimera/v1/class/<id>")}.
     */
    public static byte[] derivePayloadKey(byte[] resourceKey, byte[] envSalt, int payloadId) {
        validateKeyMaterial(resourceKey, envSalt);
        byte[] kek = Crypto.hkdf(resourceKey,
                KEK_SALT.getBytes(StandardCharsets.UTF_8),
                KEK_INFO.getBytes(StandardCharsets.UTF_8), 32);
        try {
            return Crypto.hkdf(kek, envSalt,
                    ("chimera/v1/" + KIND + "/" + payloadId).getBytes(StandardCharsets.UTF_8), 32);
        } finally {
            Arrays.fill(kek, (byte) 0);
        }
    }

    /** AAD bound to the payload/chunk, mirrors the loader and native op9 contract. */
    public static byte[] chunkAad(int payloadId, int index, int totalLength, int chunkCount) {
        return ("chimera/s5/class/" + payloadId + "/" + index + "/" + totalLength + "/" + chunkCount)
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Build/test-only helper: reverses {@link #encrypt(byte[], byte[], byte[], int, int)} so tests
     * can assert attribute preservation. Never used by the shipped runtime loader.
     */
    static byte[] decryptForVerification(byte[] payload, byte[] resourceKey, byte[] envSalt) {
        if (payload == null || payload.length < 6 * 4) {
            throw new IllegalArgumentException("payload too short");
        }
        validateKeyMaterial(resourceKey, envSalt);
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
            int magic = in.readInt();
            int version = in.readInt();
            int payloadId = in.readInt();
            int chunkSize = in.readInt();
            int totalLength = in.readInt();
            int chunkCount = in.readInt();
            if (magic != MAGIC || version != VERSION) {
                throw new IllegalArgumentException("bad payload header");
            }
            if (totalLength <= 0 || totalLength > MAX_TOTAL_BYTES
                    || chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE
                    || chunkCount != (totalLength + chunkSize - 1) / chunkSize) {
                throw new IllegalArgumentException("bad payload geometry");
            }
            byte[] itemKey = derivePayloadKey(resourceKey, envSalt, payloadId);
            try {
                byte[] plaintext = new byte[totalLength];
                for (int index = 0; index < chunkCount; index++) {
                    byte[] nonce = new byte[NONCE_LENGTH];
                    in.readFully(nonce);
                    int ciphertextLength = in.readInt();
                    int expected = Math.min(chunkSize, totalLength - index * chunkSize);
                    if (ciphertextLength != expected + TAG_LENGTH) {
                        throw new IllegalArgumentException("bad chunk ciphertext length");
                    }
                    byte[] ciphertext = new byte[ciphertextLength];
                    in.readFully(ciphertext);
                    byte[] plain = Crypto.aesGcmDecrypt(itemKey, nonce, ciphertext,
                            chunkAad(payloadId, index, totalLength, chunkCount));
                    System.arraycopy(plain, 0, plaintext, index * chunkSize, plain.length);
                    Arrays.fill(plain, (byte) 0);
                }
                if (in.available() != 0) throw new IllegalArgumentException("trailing payload bytes");
                return plaintext;
            } finally {
                Arrays.fill(itemKey, (byte) 0);
            }
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("payload decoding failed", e);
        }
    }

    private static void validateKeyMaterial(byte[] resourceKey, byte[] envSalt) {
        if (resourceKey == null || resourceKey.length != 32) {
            throw new IllegalArgumentException("resourceKey must be 32 bytes");
        }
        if (envSalt == null || envSalt.length > 64) {
            throw new IllegalArgumentException("envSalt must be 0..64 bytes");
        }
    }
}
