package dev.chimera.transform.encrypt;

import dev.chimera.crypto.Crypto;
import dev.chimera.runtime.ChimeraHiddenLoader;
import dev.chimera.runtime.ChimeraRuntime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S5: encrypted class payloads + hidden-class loading.
 *
 * <p>Covers: ciphertext is not a parseable class file, same-key load/invoke works, wrong key and
 * tampered payload fail closed, @Mixin classes are skipped untouched, and Signature/debug
 * attributes survive the encrypt/decrypt round-trip.</p>
 */
class ClassPayloadBuilderTest {

    private static final byte[] RESOURCE_KEY = Crypto.sha256(
            "s5-class-resource-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] OTHER_KEY = Crypto.sha256(
            "s5-class-other-key".getBytes(StandardCharsets.UTF_8));
    private static final byte[] ENV_SALT = new byte[16];
    static {
        for (int i = 0; i < ENV_SALT.length; i++) ENV_SALT[i] = (byte) (i * 7 + 3);
    }

    private byte[] previousSalt;
    private boolean previousEnvLoaded;

    @BeforeEach
    void installRuntimeKey() throws Exception {
        Field saltField = ChimeraRuntime.class.getDeclaredField("envSalt");
        saltField.setAccessible(true);
        previousSalt = (byte[]) saltField.get(null);
        Field loadedField = ChimeraRuntime.class.getDeclaredField("envLoaded");
        loadedField.setAccessible(true);
        previousEnvLoaded = loadedField.getBoolean(null);
        saltField.set(null, ENV_SALT.clone());
        loadedField.setBoolean(null, true);
        ChimeraHiddenLoader.resetPoisonForTests();
        ChimeraRuntime.setResourceKey(RESOURCE_KEY);
    }

    @AfterEach
    void restoreRuntimeState() throws Exception {
        ChimeraRuntime.setResourceKey(RESOURCE_KEY);
        ChimeraHiddenLoader.resetPoisonForTests();
        Field saltField = ChimeraRuntime.class.getDeclaredField("envSalt");
        saltField.setAccessible(true);
        saltField.set(null, previousSalt);
        Field loadedField = ChimeraRuntime.class.getDeclaredField("envLoaded");
        loadedField.setAccessible(true);
        loadedField.setBoolean(null, previousEnvLoaded);
    }

    @Test
    void encryptedPayloadIsNotAParsableClassAndRoundTrips() {
        byte[] original = syntheticAdd("s5/Synthetic", false);
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 7);

        assertTrue(encrypted.encrypted());
        assertFalse(encrypted.mixinSkipped());
        assertEquals(7, encrypted.payloadId());
        assertEquals("chimera/classes/s5/Synthetic.bin", encrypted.resourceName());
        assertEquals(ClassPayloadBuilder.MAGIC, ByteBuffer.wrap(encrypted.payload()).getInt(0),
                "payload must start with the CHCP magic, not CAFEBABE");
        assertThrows(RuntimeException.class,
                () -> new ClassReader(encrypted.payload()).getClassName(),
                "encrypted payload must not be directly parseable by ASM");
        assertFalse(Arrays.equals(original, encrypted.payload()));

        byte[] decrypted = ClassPayloadBuilder.decryptForVerification(
                encrypted.payload(), RESOURCE_KEY, ENV_SALT);
        assertArrayEquals(ClassPayloadBuilder.renameForHiddenClass(original, 7), decrypted,
                "decrypting must restore the hidden-class bytes (renamed into the runtime package)");
        assertEquals(ClassPayloadBuilder.hiddenInternalName(7),
                new ClassReader(decrypted).getClassName(),
                "the class must be renamed into the loader package before it is defined");
    }

    @Test
    void loaderDefinesHiddenClassAndInvokesMethod() throws Exception {
        byte[] original = syntheticAdd("s5/Synthetic", false);
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 1);

        Class<?> hidden = ChimeraHiddenLoader.load(encrypted.payload());
        assertNotNull(hidden, "same-key load must succeed: "
                + ChimeraHiddenLoader.lastFailureReason());
        assertTrue(hidden.isHidden(), "class must be a hidden class");
        assertTrue(hidden.getName().startsWith("dev.chimera.runtime.ChimeraHidden_1"),
                "hidden class must live in the loader package, got " + hidden.getName());
        Method add = hidden.getDeclaredMethod("add", int.class, int.class);
        add.setAccessible(true);
        assertEquals(7, add.invoke(null, 3, 4));
        assertEquals(Boolean.TRUE, ChimeraRuntime.isKeyHealthy());
        assertTrue(ChimeraHiddenLoader.wipeCount() >= 1L);
        assertTrue(ChimeraHiddenLoader.lastPlaintextWiped(),
                "decrypted class bytes must be zeroized after defineHiddenClass");
    }

    @Test
    void wrongKeyFailsClosedAndPoisons() throws Exception {
        byte[] original = syntheticAdd("s5/WrongKey", false);
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 2);

        ChimeraRuntime.setResourceKey(OTHER_KEY);
        Class<?> hidden = ChimeraHiddenLoader.load(encrypted.payload());
        assertNull(hidden, "wrong key must not define a class");
        assertTrue(ChimeraHiddenLoader.isPoisoned());
        assertEquals(Boolean.FALSE, ChimeraRuntime.isKeyHealthy(),
                "wrong key must poison the runtime via the existing bridge");
        assertTrue(ChimeraHiddenLoader.lastPlaintextWiped());
    }

    @Test
    void tamperedPayloadFailsClosed() {
        byte[] original = syntheticAdd("s5/Tampered", false);
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 3);

        byte[] tamperedCiphertext = encrypted.payload().clone();
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 0x01;
        assertNull(ChimeraHiddenLoader.load(tamperedCiphertext));

        ChimeraHiddenLoader.resetPoisonForTests();
        byte[] tamperedHeader = encrypted.payload().clone();
        tamperedHeader[3] ^= 0x01;
        assertNull(ChimeraHiddenLoader.load(tamperedHeader));
        assertTrue(ChimeraHiddenLoader.isPoisoned());
    }

    @Test
    void digestMismatchFailsClosed() {
        byte[] original = syntheticAdd("s5/Digest", false);
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 4);
        byte[] wrongDigest = new byte[32];
        assertNull(ChimeraHiddenLoader.load(encrypted.payload(), wrongDigest));
        assertTrue(ChimeraHiddenLoader.isPoisoned());
    }

    @Test
    void mixinClassIsSkippedAndInputUntouched() {
        byte[] mixin = syntheticAdd("s5/MixinSynthetic", true);
        byte[] copy = mixin.clone();
        assertTrue(ClassPayloadBuilder.isMixinClass(mixin));
        ClassPayloadBuilder.EncryptedClass skipped =
                ClassPayloadBuilder.encrypt(mixin, RESOURCE_KEY, ENV_SALT, 5);
        assertTrue(skipped.mixinSkipped());
        assertNull(skipped.payload(), "no encrypted resource for a Mixin class");
        assertNull(skipped.resourceName());
        assertNotNull(skipped.skipReason());
        assertArrayEquals(copy, mixin, "builder must not rewrite the Mixin class bytes");

        byte[] normal = syntheticAdd("s5/NormalSynthetic", false);
        assertFalse(ClassPayloadBuilder.isMixinClass(normal));
        assertTrue(ClassPayloadBuilder.encrypt(normal, RESOURCE_KEY, ENV_SALT, 6).encrypted());
    }

    @Test
    void signatureAndDebugInfoSurviveRoundTrip() {
        byte[] original = syntheticGeneric("s5/Generic");
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(original, RESOURCE_KEY, ENV_SALT, 8);
        byte[] decrypted = ClassPayloadBuilder.decryptForVerification(
                encrypted.payload(), RESOURCE_KEY, ENV_SALT);
        assertArrayEquals(ClassPayloadBuilder.renameForHiddenClass(original, 8), decrypted);

        final String[] signature = new String[1];
        final String[] source = new String[1];
        final int[] lineNumbers = new int[1];
        new ClassReader(decrypted).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(String sourceFile, String debug) {
                source[0] = sourceFile;
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String fieldSignature, Object value) {
                if ("values".equals(name)) signature[0] = fieldSignature;
                return null;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String methodSignature, String[] exceptions) {
                if (!"add".equals(name)) return null;
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitLineNumber(int line, Label start) {
                        lineNumbers[0]++;
                    }
                };
            }
        }, 0);
        assertEquals("Synthetic.java", source[0], "SourceFile attribute must survive");
        assertEquals("Ljava/util/List<Ljava/lang/String;>;", signature[0],
                "generic Signature attribute must survive");
        assertTrue(lineNumbers[0] >= 1, "LineNumberTable must survive");
    }

    @Test
    void largeClassIsSplitIntoMultipleChunksAndStillLoads() throws Exception {
        byte[] big = syntheticManyMethods("s5/Big", 80);
        assertTrue(big.length > 512, "fixture must be large enough for chunking");
        ClassPayloadBuilder.EncryptedClass encrypted =
                ClassPayloadBuilder.encrypt(big, RESOURCE_KEY, ENV_SALT, 9, 256);
        int chunkCount = ByteBuffer.wrap(encrypted.payload()).getInt(20);
        assertTrue(chunkCount >= 2, "expected multiple AES-GCM chunks, got " + chunkCount);

        Class<?> hidden = ChimeraHiddenLoader.load(encrypted.payload());
        assertNotNull(hidden, "chunked load must succeed: "
                + ChimeraHiddenLoader.lastFailureReason());
        Method first = hidden.getDeclaredMethod("m0", int.class);
        first.setAccessible(true);
        assertEquals(5, first.invoke(null, 5));
    }

    @Test
    void loaderConstantsMatchBuilderContract() {
        assertEquals(ClassPayloadBuilder.MAGIC, ChimeraHiddenLoader.MAGIC);
        assertEquals(ClassPayloadBuilder.VERSION, ChimeraHiddenLoader.VERSION);
        assertEquals(ClassPayloadBuilder.KIND, ChimeraHiddenLoader.KIND);
        assertEquals(ClassPayloadBuilder.NONCE_LENGTH, ChimeraHiddenLoader.NONCE_LENGTH);
        assertEquals(ClassPayloadBuilder.TAG_LENGTH, ChimeraHiddenLoader.TAG_LENGTH);
        assertArrayEquals(ClassPayloadBuilder.chunkAad(3, 1, 4096, 2),
                ChimeraHiddenLoader.chunkAad(3, 1, 4096, 2));
    }

    @Test
    void invalidInputsAreRejectedAtBuildTime() {
        byte[] normal = syntheticAdd("s5/Invalid", false);
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.encrypt(normal, new byte[16], ENV_SALT, 1));
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.encrypt(normal, RESOURCE_KEY, new byte[65], 1));
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.encrypt(normal, RESOURCE_KEY, ENV_SALT, -1));
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.encrypt(normal, RESOURCE_KEY, ENV_SALT, 1, 128));
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.isMixinClass(new byte[]{1, 2, 3}));
    }

    @Test
    void methodCodeDigestMatchesNativeRegistrationContract() {
        byte[] original = syntheticAdd("s5/DigestContract", false);
        // syntheticAdd code[] = ILOAD_0(0x1a) ILOAD_1(0x1b) IADD(0x60) IRETURN(0xac)
        byte[] expectedCode = new byte[]{(byte) 0x1a, (byte) 0x1b, 0x60, (byte) 0xac};
        byte[] expected = Crypto.sha256(expectedCode);
        assertArrayEquals(expected,
                ClassPayloadBuilder.methodCodeSha256(original, "add", "(II)I"),
                "digest must be SHA-256(code[]) only (no prefix/name/endian transform)");
        assertArrayEquals(expected, ClassPayloadBuilder.methodCodeSha256(original, "add"));

        List<ClassPayloadBuilder.MethodCodeDigest> digests =
                ClassPayloadBuilder.methodCodeDigests(original);
        assertEquals(1, digests.size());
        assertEquals("add", digests.get(0).methodName());
        assertEquals("(II)I", digests.get(0).descriptor());
        assertArrayEquals(expected, digests.get(0).sha256());
    }

    @Test
    void methodCodeDigestIsStableAcrossHiddenRename() {
        byte[] original = syntheticAdd("s5/DigestRename", false);
        byte[] renamed = ClassPayloadBuilder.renameForHiddenClass(original, 11);
        assertArrayEquals(ClassPayloadBuilder.methodCodeSha256(original, "add", "(II)I"),
                ClassPayloadBuilder.methodCodeSha256(renamed, "add", "(II)I"),
                "renaming only rewrites the constant pool; code[] must keep the same digest");
        assertEquals(ClassPayloadBuilder.hiddenInternalName(11),
                new ClassReader(renamed).getClassName());
    }

    @Test
    void methodCodeDigestSkipsMethodsWithoutCode() {
        byte[] bytes = syntheticAbstract("s5/Abstracted");
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.methodCodeSha256(bytes, "noCode", "()V"),
                "abstract/native methods have no Code attribute");
        assertThrows(IllegalArgumentException.class,
                () -> ClassPayloadBuilder.methodCodeSha256(bytes, "missing", "()V"));
        assertEquals(1, ClassPayloadBuilder.methodCodeDigests(bytes).size(),
                "only the method with a Code attribute must be reported");
    }

    // ------------------------------------------------------------------ synthetic classes

    private static byte[] syntheticAdd(String internalName, boolean mixin) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, internalName, null,
                "java/lang/Object", null);
        if (mixin) {
            AnnotationVisitor annotation = cw.visitAnnotation(
                    ClassPayloadBuilder.MIXIN_DESCRIPTOR, false);
            annotation.visitEnd();
        }
        cw.visitSource("Synthetic.java", null);
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "add", "(II)I", null, null);
        mv.visitCode();
        Label start = new Label();
        mv.visitLabel(start);
        mv.visitLineNumber(10, start);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Adds a generic field (Signature attribute) plus the {@code add} method with line numbers. */
    private static byte[] syntheticGeneric(String internalName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, internalName, null,
                "java/lang/Object", null);
        cw.visitSource("Synthetic.java", null);
        FieldVisitor field = cw.visitField(Opcodes.ACC_PRIVATE, "values",
                "Ljava/util/List;", "Ljava/util/List<Ljava/lang/String;>;", null);
        field.visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "add", "(II)I", null, null);
        mv.visitCode();
        Label start = new Label();
        mv.visitLabel(start);
        mv.visitLineNumber(7, start);
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** One concrete method plus one abstract method without a Code attribute. */
    private static byte[] syntheticAbstract(String internalName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, internalName, null,
                "java/lang/Object", null);
        MethodVisitor abstractMethod = cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "noCode", "()V", null, null);
        abstractMethod.visitEnd();
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "add", "(II)I", null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ILOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 1);
        mv.visitInsn(Opcodes.IADD);
        mv.visitInsn(Opcodes.IRETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Enough methods to exceed one 256-byte chunk. */
    private static byte[] syntheticManyMethods(String internalName, int methods) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, internalName, null,
                "java/lang/Object", null);
        for (int i = 0; i < methods; i++) {
            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "m" + i, "(I)I", null, null);
            mv.visitCode();
            Label start = new Label();
            mv.visitLabel(start);
            mv.visitLineNumber(100 + i, start);
            mv.visitVarInsn(Opcodes.ILOAD, 0);
            mv.visitLdcInsn(i);
            mv.visitInsn(Opcodes.IADD);
            mv.visitInsn(Opcodes.IRETURN);
            mv.visitMaxs(2, 1);
            mv.visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }
}
