package dev.chimera.runtime;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * M9 runtime for virtualized {@code @ChimeraVM} methods (format version 2, streaming decode).
 *
 * <p>Each virtualized method was replaced by {@code ChimeraVmRuntime.execute(id, args)}; the
 * original instruction stream is stored as an encrypted blob at
 * {@code /chimera/vm/vm_<id>.bin}. Format v2 never decrypts the whole instruction stream:</p>
 *
 * <ul>
 *   <li>the blob is encrypted with an AES-256 CTR-style keystream and authenticated with
 *       HMAC-SHA256 over the ciphertext;</li>
 *   <li>at load time only the small plaintext header (descriptor, instruction count, frame
 *       limits, code length) and the instruction offsets table are decrypted, then wiped;</li>
 *   <li>the interpreter decrypts exactly one instruction (at most 12 bytes) per step into a
 *       reusable buffer, decodes opcode+operands, wipes the buffer immediately, then executes.</li>
 * </ul>
 *
 * <p>The ciphertext and the offsets table stay in memory (ciphertext is not readable without the
 * session key); no full plaintext instruction stream is ever materialized. This raises the cost
 * of a heap dump compared with a single decrypted program array, but it is not a security
 * boundary: an attacker who can dump memory also owns the session key. See {@code docs/M9-VM.md}.</p>
 *
 * <p>Failure policy (M2/M9): missing key, tampered blob, MAC mismatch, bad structure, unknown
 * opcode, division by zero or any runtime fault never throws to user code. The runtime marks the
 * global poison flag via {@code ChimeraRuntime} and returns a type-neutral poison value; the
 * generated call site substitutes the type-correct poison ({@code -1} / {@code -1L} / NaN).</p>
 *
 * <p>This class is injected into the protected jar together with {@code ChimeraRuntime}. It must
 * stay a single class file (no nested classes, no lambdas) and may only use java.base plus
 * {@code ChimeraRuntime}'s package-private bridges. Opcode numbers and the blob layout are
 * documented in {@code docs/M9-VM.md} and duplicated from the build-time classes
 * {@code dev.chimera.vm.VmOpcode} / {@code dev.chimera.vm.VmCompiler}; keep them in sync.</p>
 */
public final class ChimeraVmRuntime {

    /** "CHVB" - vm blob resource. */
    private static final int RESOURCE_MAGIC = 0x43485642;
    /** "CHVM" - decrypted plaintext header. */
    private static final int PLAIN_MAGIC = 0x4348564D;
    /** Plaintext header version: CTR keystream + HMAC-SHA256 + per-instruction decoding. */
    private static final int PLAIN_FORMAT_VERSION = 5;
    /** Outer resource versions accepted on load. */
    private static final int OUTER_VERSION_LEGACY = 5;
    /** KI-28: v6 adds a ResourceKey-wrapped copy of the per-blob VM item key. */
    private static final int OUTER_VERSION_WRAPPED_KEY = 6;
    private static final String VM_WRAP_KIND = "vm-wrap";
    /** AES-GCM(32-byte item key) = 32-byte ciphertext + 16-byte tag; the nonce is stored separately. */
    private static final int WRAPPED_KEY_LENGTH = 32 + 16;

    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH = 32;
    private static final int TAG_LENGTH = 32;
    private static final int MAX_BLOCK_LENGTH = 1 << 20;
    private static final int MAX_DESCRIPTOR_LENGTH = 4096;
    private static final int MAX_INSTRUCTIONS = 0xffff;
    /** Maximum encoded size of one VM instruction (PUSH_B256 carries a 32-byte immediate). */
    private static final int MAX_INSTRUCTION_BYTES = 64;
    /** Fixed byte width of unsigned 256-bit integers carried on the VM stack (big-endian). */
    private static final int U256_BYTES = 32;

    /** Type codes shared with the compiler. */
    private static final int TYPE_I = 0;
    private static final int TYPE_L = 1;
    private static final int TYPE_D = 2;
    private static final int TYPE_O = 3;
    private static final int TYPE_V = 4;

    /** Opcode numbers shared with {@code dev.chimera.vm.VmOpcode}. */
    private static final int OP_PUSH_I = 1;
    private static final int OP_PUSH_L = 2;
    private static final int OP_PUSH_D = 3;
    private static final int OP_LOAD = 4;
    private static final int OP_STORE = 5;
    private static final int OP_IINC = 6;
    private static final int OP_IADD = 10;
    private static final int OP_ISUB = 11;
    private static final int OP_IMUL = 12;
    private static final int OP_IDIV = 13;
    private static final int OP_IREM = 14;
    private static final int OP_INEG = 15;
    private static final int OP_IAND = 16;
    private static final int OP_IOR = 17;
    private static final int OP_IXOR = 18;
    private static final int OP_LADD = 20;
    private static final int OP_LSUB = 21;
    private static final int OP_LMUL = 22;
    private static final int OP_LDIV = 23;
    private static final int OP_LREM = 24;
    private static final int OP_LNEG = 25;
    private static final int OP_LAND = 26;
    private static final int OP_LOR = 27;
    private static final int OP_LXOR = 28;
    private static final int OP_DADD = 30;
    private static final int OP_DSUB = 31;
    private static final int OP_DMUL = 32;
    private static final int OP_DDIV = 33;
    private static final int OP_DREM = 34;
    private static final int OP_DNEG = 35;
    private static final int OP_DCMPG = 36;
    private static final int OP_DCMPL = 37;
    private static final int OP_I2L = 40;
    private static final int OP_I2D = 41;
    private static final int OP_L2I = 42;
    private static final int OP_L2D = 43;
    private static final int OP_D2I = 44;
    private static final int OP_D2L = 45;
    private static final int OP_LCMP = 46;
    private static final int OP_RET = 50;
    private static final int OP_GOTO = 60;
    private static final int OP_IFEQ = 61;
    private static final int OP_IFNE = 62;
    private static final int OP_IFLT = 63;
    private static final int OP_IFGE = 64;
    private static final int OP_IFGT = 65;
    private static final int OP_IFLE = 66;
    private static final int OP_IF_ICMPEQ = 67;
    private static final int OP_IF_ICMPNE = 68;
    private static final int OP_IF_ICMPLT = 69;
    private static final int OP_IF_ICMPGE = 70;
    private static final int OP_IF_ICMPGT = 71;
    private static final int OP_IF_ICMPLE = 72;
    private static final int OP_ISHL = 73;
    private static final int OP_ISHR = 74;
    private static final int OP_IUSHR = 75;
    private static final int OP_LSHL = 76;
    private static final int OP_LSHR = 77;
    private static final int OP_LUSHR = 78;
    private static final int OP_I2B = 79;
    private static final int OP_I2C = 80;
    private static final int OP_I2S = 81;
    private static final int OP_GETFIELD = 90;
    private static final int OP_GETSTATIC = 91;
    private static final int OP_INVOKESTATIC = 92;
    private static final int OP_PUTFIELD = 93;
    private static final int OP_PUTSTATIC = 94;
    private static final int OP_INVOKEVIRTUAL = 95;

    // --- B7 step 1: VM ISA extension (canonical numbers shared with dev.chimera.vm.VmOpcode):
    // PUSH_B256 / POP_B256 / LOAD_BYTE / CMP_U256 / CALL_NATIVE / VERIFY_DECISION. They are
    // reached only through the build-time randomized raw->canonical opcode table, exactly like
    // the v5 opcodes above; no second plaintext dispatch chain is added.
    private static final int OP_PUSH_B256 = 200;
    private static final int OP_POP_B256 = 201;
    private static final int OP_LOAD_BYTE = 202;
    private static final int OP_CMP_U256 = 203;
    private static final int OP_CALL_NATIVE = 204;
    private static final int OP_VERIFY_DECISION = 205;

    // B7 step 2: nativeCompute op bytes (params[0]) understood by the native-pipeline C++ side.
    // op6 = CALL_NATIVE(index,args...), op7 = VERIFY_DECISION(tag), op8 = AOT differential
    // reference, op9 reserved for native DECRYPT_DATA (not emitted by the VM yet).
    private static final int NATIVE_OP_VM_CALL = 6;
    private static final int NATIVE_OP_VERIFY_DECISION = 7;
    private static final int NATIVE_OP_AOT_VERIFY_TAG_REF = 8;
    private static final int NATIVE_OP_DECRYPT_DATA = 9;
    /** B7 step 2: release PENDING closure; native re-verifies stored transcript/sig internally. */
    private static final int NATIVE_OP_RUN_DECISION_PROGRAM = 10;

    /**
     * A decoded program is an Object[] with this layout. Only ciphertext + offsets + descriptor
     * are kept; the keystream cipher is shared by memoized programs.
     */
    private static final int P_ARG_KINDS = 0;
    private static final int P_RETURN_KIND = 1;
    private static final int P_ARG_COUNT = 2;
    private static final int P_ARG_SLOTS = 3;
    private static final int P_OFFSETS = 4;
    private static final int P_CIPHER = 5;
    private static final int P_CIPHERTEXT = 6;
    private static final int P_NONCE = 7;
    private static final int P_CODE_START = 8;
    private static final int P_MAX_STACK = 9;
    private static final int P_MAX_LOCALS = 10;
    private static final int P_INSTRUCTION_COUNT = 11;
    private static final int P_MEMBER_KINDS = 12;
    private static final int P_MEMBER_OWNERS = 13;
    private static final int P_MEMBER_NAMES = 14;
    private static final int P_MEMBER_DESCS = 15;
    private static final int P_FIELD_CACHE = 16;
    private static final int P_HANDLE_CACHE = 17;
    private static final int P_RECORDS = 18;
    private static final int P_OPCODE_TABLE = 19;
    private static final int P_LENGTH = 20;
    private static final int MAX_MEMBERS = 4096;

    private static final Object[] EMPTY_ARGS = new Object[0];
    private static final ConcurrentHashMap<Integer, Object[]> CACHE = new ConcurrentHashMap<>();

    /**
     * B7 step 1: build-time encoded native index -> host handler. The VM instruction carries the
     * opaque index, never a function address; step 2 populates this table from the native
     * function table preallocated in JNI_OnLoad instead of Java registration.
     */
    private static final ConcurrentHashMap<Integer, java.util.function.Function<Object[], Object>>
            NATIVE_HANDLERS = new ConcurrentHashMap<>();

    /** B7 step 1 placeholder for VERIFY_DECISION: VM/handle semantic state only. */
    private static volatile int verifyDecisionState;
    private static volatile int verifyDecisionWrites;
    /**
     * B7 step 2: cached reflective accessor for ChimeraRuntime.nativeSessionHandle. The runtime
     * classes are not renamed/obfuscated and ChimeraRuntime is owned by another module, so the VM
     * side reads the current handle without adding an API to that class (lead-approved for this
     * step; a package bridge will replace it during integration).
     */
    private static volatile java.lang.reflect.Field sessionHandleField;

    private ChimeraVmRuntime() {
    }

    /**
     * Executes the virtualized method identified by {@code id}. Never throws: decryption or
     * interpreter failures poison the runtime and return {@code Integer.valueOf(-1)} as a
     * type-neutral value.
     */
    public static Object execute(int id, Object[] args) {
        ChimeraRuntime.verifyRuntimeHashBridge();
        if (ChimeraRuntime.isPoisonedBridge()) {
            return Integer.valueOf(-1);
        }
        try {
            Object[] program = CACHE.get(Integer.valueOf(id));
            if (program == null) {
                program = load(id);
                Object[] previous = CACHE.putIfAbsent(Integer.valueOf(id), program);
                if (previous != null) {
                    program = previous;
                }
            }
            return run(program, args == null ? EMPTY_ARGS : args);
        } catch (Throwable t) {
            ChimeraRuntime.markPoisonBridge();
            return Integer.valueOf(-1);
        }
    }

    /** True once the runtime has detected a missing key, tampered blob or VM fault. */
    public static boolean isPoisoned() {
        return ChimeraRuntime.isPoisonedBridge();
    }

    // ------------------------------------------------------------------ B7 step 1 hooks

    /**
     * B7 step 1: registers a host handler for {@code CALL_NATIVE}. The VM instruction carries an
     * opaque build-time encoded {@code u16} index, never a function address. Step 2 replaces this
     * Java registry with the native function table preallocated in {@code JNI_OnLoad}; the lookup
     * shape (index -> handler, no address exposure) stays the same.
     */
    public static void registerNativeHandler(int nativeIndex,
                                             java.util.function.Function<Object[], Object> handler) {
        if (handler == null) {
            NATIVE_HANDLERS.remove(Integer.valueOf(nativeIndex));
        } else {
            NATIVE_HANDLERS.put(Integer.valueOf(nativeIndex), handler);
        }
    }

    /** B7 step 1: clears all registered native handlers (tests / re-initialization). */
    public static void clearNativeHandlers() {
        NATIVE_HANDLERS.clear();
    }

    /**
     * B7 step 1 placeholder accessor for the VERIFY_DECISION state. This is not a Java-visible
     * decision value: it only proves the opcode wrote VM/handle semantic state without producing a
     * stack/return value. Step 2 moves the state into the native handle and removes this hook.
     */
    public static int verifyDecisionStateForTest() {
        return verifyDecisionState;
    }

    /** B7 step 1: number of VERIFY_DECISION instructions executed in this process. */
    public static int verifyDecisionWritesForTest() {
        return verifyDecisionWrites;
    }

    /** B7 step 1: resets the placeholder decision state (tests only). */
    public static void resetVerifyDecisionForTest() {
        verifyDecisionState = 0;
        verifyDecisionWrites = 0;
    }

    // ------------------------------------------------------------------ B7 step 2 hooks

    /**
     * B7 step 2 (op10): asks the native side to run RUN_DECISION_PROGRAM for a PENDING
     * SessionHandle. transcript/signature/verify_result stay in native memory; the native
     * handler re-verifies independently and promotes PENDING -> VALID or POISONs the handle.
     *
     * <p>This method returns only whether the native call completed; it is NOT a decision
     * oracle (the native call always returns a fixed 32-byte zero shape). Callers must still
     * observe the handle through the canary path (op5), exactly like the AOT activation path.</p>
     */
    public static boolean runDecisionProgram(long handle) {
        if (handle == 0L) {
            return false;
        }
        try {
            byte[] shape = ChimeraRuntime.nativeCompute(handle,
                    new byte[]{(byte) NATIVE_OP_RUN_DECISION_PROGRAM, 0});
            return shape != null;
        } catch (Throwable t) {
            // fail-closed for the caller; do not turn a missing/failed op10 into a Java exception.
            return false;
        }
    }

    /** Convenience for the activation path: runs op10 for the currently installed handle. */
    public static boolean runDecisionProgramForCurrentSession() {
        long handle = currentNativeHandle();
        return handle != 0L && runDecisionProgram(handle);
    }

    // A4: non-sentinel poison values are implemented in ChimeraRuntime; these delegating methods
    // keep the generated call sites inside the injected VM runtime class.
    public static int vmPoisonInt() {
        return ChimeraRuntime.vmPoisonInt();
    }

    public static long vmPoisonLong() {
        return ChimeraRuntime.vmPoisonLong();
    }

    public static double vmPoisonDouble() {
        return ChimeraRuntime.vmPoisonDouble();
    }

    // ------------------------------------------------------------------ blob loading

    private static Object[] load(int id) throws Exception {
        byte[] resource = readResource(id);
        if (resource == null) {
            throw new IllegalStateException("vm resource missing: " + id);
        }
        if (resource.length < 64 + TAG_LENGTH) {
            throw new IllegalStateException("vm resource truncated: " + id);
        }
        int macOffset = resource.length - TAG_LENGTH;
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(resource));
        if (in.readInt() != RESOURCE_MAGIC) {
            throw new IllegalStateException("bad vm resource magic: " + id);
        }
        if (in.readInt() != id) {
            throw new IllegalStateException("vm resource id mismatch: " + id);
        }
        int version = in.readInt();
        if (version != OUTER_VERSION_LEGACY && version != OUTER_VERSION_WRAPPED_KEY) {
            throw new IllegalStateException("unsupported vm format version: " + id);
        }
        int nonceLength = in.readInt();
        if (nonceLength != NONCE_LENGTH) {
            throw new IllegalStateException("bad vm nonce length: " + nonceLength);
        }
        byte[] nonce = new byte[nonceLength];
        in.readFully(nonce);
        byte[] wrapNonce = null;
        byte[] wrappedKey = null;
        if (version == OUTER_VERSION_WRAPPED_KEY) {
            int wrapNonceLength = in.readInt();
            if (wrapNonceLength != NONCE_LENGTH) {
                throw new IllegalStateException("bad vm wrap nonce length: " + wrapNonceLength);
            }
            wrapNonce = new byte[wrapNonceLength];
            in.readFully(wrapNonce);
            int wrappedKeyLength = in.readInt();
            if (wrappedKeyLength != WRAPPED_KEY_LENGTH) {
                throw new IllegalStateException("bad vm wrapped key length: " + wrappedKeyLength);
            }
            wrappedKey = new byte[wrappedKeyLength];
            in.readFully(wrappedKey);
        }
        int plainLength = in.readInt();
        int headerLength = in.readInt();
        int offsetsLength = in.readInt();
        int recordsLength = in.readInt();
        if (plainLength <= 0 || plainLength > MAX_BLOCK_LENGTH
                || headerLength <= 32 || headerLength > plainLength
                || offsetsLength <= 0 || offsetsLength > plainLength
                || headerLength + offsetsLength != plainLength
                || recordsLength <= 0 || recordsLength > MAX_BLOCK_LENGTH) {
            throw new IllegalStateException("bad vm block lengths: " + id);
        }
        int outerHeader = version == OUTER_VERSION_WRAPPED_KEY
                ? 4 * 10 + nonceLength + wrapNonce.length + wrappedKey.length
                : 4 * 8 + nonceLength;
        if (macOffset != outerHeader + plainLength + recordsLength) {
            throw new IllegalStateException("vm resource layout mismatch: " + id);
        }
        byte[] ciphertext = new byte[plainLength];
        in.readFully(ciphertext);
        byte[] records = new byte[recordsLength];
        in.readFully(records);
        byte[] expectedMac = new byte[TAG_LENGTH];
        System.arraycopy(resource, macOffset, expectedMac, 0, TAG_LENGTH);

        // KI-28: v6 blobs carry the per-blob item key wrapped with a ResourceKey-derived item key.
        // Native authorized mode opens it through op9; in the dev/no-handle path decryptItemBridge
        // falls back to the Java-derived key. v5 test/legacy blobs keep the direct derivation.
        byte[] itemKey;
        if (version == OUTER_VERSION_WRAPPED_KEY) {
            itemKey = ChimeraRuntime.decryptItemBridge(VM_WRAP_KIND, id, wrapNonce, wrappedKey,
                    (VM_WRAP_KIND + "/" + id).getBytes(StandardCharsets.UTF_8));
        } else {
            itemKey = ChimeraRuntime.deriveItemKeyBridge("vm", id);
        }
        if (itemKey == null || itemKey.length != KEY_LENGTH) {
            throw new IllegalStateException("vm key unavailable: " + id);
        }
        byte[] encKey = hkdf(itemKey, nonce,
                "chimera/vm/enc/v3".getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
        byte[] macKey = hkdf(itemKey, nonce,
                "chimera/vm/mac/v3".getBytes(StandardCharsets.UTF_8), KEY_LENGTH);
        Arrays.fill(itemKey, (byte) 0);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        mac.update(resource, 0, macOffset);
        byte[] actualMac = mac.doFinal();
        if (!constantTimeEquals(expectedMac, actualMac)) {
            throw new IllegalStateException("vm blob authentication failed: " + id);
        }
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"));
        Arrays.fill(encKey, (byte) 0);
        Arrays.fill(macKey, (byte) 0);

        byte[] struct = new byte[plainLength];
        byte[] counter = new byte[16];
        byte[] keystream = new byte[16];
        int[] blockState = new int[]{-1};
        decryptRange(cipher, nonce, ciphertext, 0, plainLength, struct, counter, keystream, blockState);
        try {
            DataInputStream plain = new DataInputStream(new ByteArrayInputStream(struct));
            if (plain.readInt() != PLAIN_MAGIC) {
                throw new IllegalStateException("bad vm plaintext magic");
            }
            if (plain.readInt() != PLAIN_FORMAT_VERSION) {
                throw new IllegalStateException("unsupported vm plaintext version");
            }
            if (plain.readInt() != id) {
                throw new IllegalStateException("vm plaintext id mismatch");
            }
            int descriptorLength = plain.readInt();
            if (descriptorLength <= 0 || descriptorLength > MAX_DESCRIPTOR_LENGTH) {
                throw new IllegalStateException("bad vm descriptor length: " + descriptorLength);
            }
            byte[] descriptorBytes = new byte[descriptorLength];
            plain.readFully(descriptorBytes);
            String descriptor = new String(descriptorBytes, StandardCharsets.UTF_8);
            Arrays.fill(descriptorBytes, (byte) 0);
            int instructionCount = plain.readInt();
            int maxStack = plain.readInt();
            int maxLocals = plain.readInt();
            if (instructionCount <= 0 || instructionCount > MAX_INSTRUCTIONS
                    || maxStack <= 0 || maxStack > 0xffff || maxLocals < 0 || maxLocals > 0xffff) {
                throw new IllegalStateException("bad vm program limits");
            }
            int memberCount = plain.readInt();
            if (memberCount < 0 || memberCount > MAX_MEMBERS) {
                throw new IllegalStateException("bad vm member count: " + memberCount);
            }
            int[] memberKinds = new int[memberCount];
            String[] memberOwners = new String[memberCount];
            String[] memberNames = new String[memberCount];
            String[] memberDescs = new String[memberCount];
            for (int i = 0; i < memberCount; i++) {
                int kind = plain.readUnsignedByte();
                if (kind != 0 && kind != 1 && kind != 2) {
                    throw new IllegalStateException("bad vm member kind: " + kind);
                }
                memberKinds[i] = kind;
                memberOwners[i] = readUtf(plain, 512);
                memberNames[i] = readUtf(plain, 512);
                memberDescs[i] = readUtf(plain, 4096);
            }
            byte[] opcodeTable = new byte[256];
            plain.readFully(opcodeTable);
            if (plain.available() != offsetsLength) {
                throw new IllegalStateException("trailing vm header bytes");
            }
            int[] recordOffsets = new int[instructionCount + 1];
            DataInputStream offsetIn = new DataInputStream(new ByteArrayInputStream(
                    struct, headerLength, offsetsLength));
            for (int i = 0; i < recordOffsets.length; i++) {
                recordOffsets[i] = offsetIn.readInt();
            }
            if (recordOffsets[0] != 0 || recordOffsets[instructionCount] != recordsLength) {
                throw new IllegalStateException("bad vm record offsets");
            }
            for (int i = 0; i < instructionCount; i++) {
                int length = recordOffsets[i + 1] - recordOffsets[i];
                if (length < 3 || length > 0xffff) {
                    throw new IllegalStateException("bad vm record length: " + length);
                }
            }
            int[] descriptorInfo = parseDescriptor(descriptor);
            int argCount = descriptorInfo[0];
            int returnKind = descriptorInfo[1];
            int argSlots = descriptorInfo[2];
            int[] argKinds = new int[argCount];
            System.arraycopy(descriptorInfo, 3, argKinds, 0, argCount);

            Object[] program = new Object[P_LENGTH];
            program[P_ARG_KINDS] = argKinds;
            program[P_RETURN_KIND] = Integer.valueOf(returnKind);
            program[P_ARG_COUNT] = Integer.valueOf(argCount);
            program[P_ARG_SLOTS] = Integer.valueOf(argSlots);
            program[P_OFFSETS] = recordOffsets;
            program[P_CIPHER] = cipher;
            program[P_CIPHERTEXT] = ciphertext;
            program[P_NONCE] = nonce;
            program[P_CODE_START] = Integer.valueOf(0);
            program[P_MAX_STACK] = Integer.valueOf(maxStack);
            program[P_MAX_LOCALS] = Integer.valueOf(maxLocals);
            program[P_INSTRUCTION_COUNT] = Integer.valueOf(instructionCount);
            program[P_MEMBER_KINDS] = memberKinds;
            program[P_MEMBER_OWNERS] = memberOwners;
            program[P_MEMBER_NAMES] = memberNames;
            program[P_MEMBER_DESCS] = memberDescs;
            program[P_FIELD_CACHE] = new Object[memberCount];
            program[P_HANDLE_CACHE] = new Object[memberCount];
            program[P_RECORDS] = records;
            program[P_OPCODE_TABLE] = opcodeTable;
            return program;
        } finally {
            Arrays.fill(struct, (byte) 0);
            Arrays.fill(counter, (byte) 0);
            Arrays.fill(keystream, (byte) 0);
        }
    }

    private static String readUtf(DataInputStream in, int maxLength) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > maxLength) {
            throw new IllegalStateException("bad vm string length: " + length);
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] readResource(int id) {
        String name = "/chimera/vm/vm_" + id + ".bin";
        try (InputStream in = ChimeraVmRuntime.class.getResourceAsStream(name)) {
            if (in == null) {
                return null;
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream(256);
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("vm resource read failed: " + name, e);
        }
    }

    // ------------------------------------------------------------------ CTR keystream

    /**
     * Decrypts the byte range {@code [start,end)} with the CTR keystream, reusing the caller's
     * counter/keystream/block buffers so no plaintext beyond {@code out} is produced. The cipher
     * is shared by the memoized program and guarded by its monitor.
     */
    private static void decryptRange(Cipher cipher, byte[] nonce, byte[] ciphertext,
                                     int start, int end, byte[] out,
                                     byte[] counter, byte[] keystream, int[] blockState) throws Exception {
        synchronized (cipher) {
            for (int position = start; position < end; position++) {
                int block = position >>> 4;
                int offset = position & 15;
                if (blockState[0] != block) {
                    System.arraycopy(nonce, 0, counter, 0, NONCE_LENGTH);
                    counter[12] = (byte) (block >>> 24);
                    counter[13] = (byte) (block >>> 16);
                    counter[14] = (byte) (block >>> 8);
                    counter[15] = (byte) block;
                    int produced = cipher.update(counter, 0, 16, keystream, 0);
                    if (produced != 16) {
                        throw new IllegalStateException("vm keystream failure");
                    }
                    blockState[0] = block;
                }
                out[position - start] = (byte) (ciphertext[position] ^ keystream[offset]);
            }
        }
    }

    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream out = new ByteArrayOutputStream(length);
        byte[] previous = new byte[0];
        int counter = 1;
        while (out.size() < length) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) counter);
            previous = mac.doFinal();
            int take = Math.min(previous.length, length - out.size());
            out.write(previous, 0, take);
            counter++;
        }
        Arrays.fill(prk, (byte) 0);
        return out.toByteArray();
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length; i++) {
            difference |= a[i] ^ b[i];
        }
        return difference == 0;
    }

    // ------------------------------------------------------------------ descriptor parsing

    private static int[] parseDescriptor(String descriptor) {
        if (descriptor == null || descriptor.length() < 3 || descriptor.charAt(0) != '(') {
            throw new IllegalStateException("bad vm descriptor: " + descriptor);
        }
        int close = descriptor.indexOf(')');
        if (close < 0) {
            throw new IllegalStateException("bad vm descriptor: " + descriptor);
        }
        int[] kinds = new int[descriptor.length()];
        int argCount = 0;
        int argSlots = 0;
        int i = 1;
        while (i < close) {
            char c = descriptor.charAt(i);
            if (c == 'L') {
                int semicolon = descriptor.indexOf(';', i);
                if (semicolon < 0 || semicolon > close) {
                    throw new IllegalStateException("bad vm object descriptor: " + descriptor);
                }
                kinds[argCount++] = TYPE_O;
                argSlots += 1;
                i = semicolon + 1;
            } else {
                int kind = kindOf(c);
                kinds[argCount++] = kind;
                argSlots += width(kind);
                i++;
            }
        }
        char returnChar = descriptor.charAt(close + 1);
        int returnKind;
        if (returnChar == 'L') {
            if (!descriptor.endsWith(";") || descriptor.indexOf(';', close + 1) != descriptor.length() - 1) {
                throw new IllegalStateException("bad vm object return: " + descriptor);
            }
            returnKind = TYPE_O;
        } else {
            if (close + 2 != descriptor.length()) {
                throw new IllegalStateException("bad vm descriptor: " + descriptor);
            }
            returnKind = kindOf(returnChar);
        }
        int[] info = new int[3 + argCount];
        info[0] = argCount;
        info[1] = returnKind;
        info[2] = argSlots;
        System.arraycopy(kinds, 0, info, 3, argCount);
        return info;
    }

    private static int kindOf(char descriptorChar) {
        switch (descriptorChar) {
            case 'I':
                return TYPE_I;
            case 'J':
                return TYPE_L;
            case 'D':
                return TYPE_D;
            default:
                throw new IllegalStateException("unsupported vm type: " + descriptorChar);
        }
    }

    private static int width(int kind) {
        return kind == TYPE_I || kind == TYPE_O ? 1 : 2;
    }

    // ------------------------------------------------------------------ interpreter

    private static Object run(Object[] program, Object[] args) throws Exception {
        int[] argKinds = (int[]) program[P_ARG_KINDS];
        int returnKind = ((Integer) program[P_RETURN_KIND]).intValue();
        int argCount = ((Integer) program[P_ARG_COUNT]).intValue();
        int maxStack = ((Integer) program[P_MAX_STACK]).intValue();
        int maxLocals = ((Integer) program[P_MAX_LOCALS]).intValue();
        int instructionCount = ((Integer) program[P_INSTRUCTION_COUNT]).intValue();
        int[] offsets = (int[]) program[P_OFFSETS];
        int[] memberKinds = (int[]) program[P_MEMBER_KINDS];
        String[] memberOwners = (String[]) program[P_MEMBER_OWNERS];
        String[] memberNames = (String[]) program[P_MEMBER_NAMES];
        String[] memberDescs = (String[]) program[P_MEMBER_DESCS];
        Object[] fieldCache = (Object[]) program[P_FIELD_CACHE];
        Object[] handleCache = (Object[]) program[P_HANDLE_CACHE];
        int memberCount = memberKinds.length;
        Cipher cipher = (Cipher) program[P_CIPHER];
        byte[] nonce = (byte[]) program[P_NONCE];
        byte[] records = (byte[]) program[P_RECORDS];
        byte[] opcodeTable = (byte[]) program[P_OPCODE_TABLE];

        if (args.length != argCount) {
            throw new IllegalStateException("vm argument count mismatch: " + args.length + " != " + argCount);
        }
        int localIntMask = (int) ChimeraRuntime.dynamicKey();
        long localLongMask = ChimeraRuntime.dynamicKey() | 1L;
        Object[] locals = new Object[maxLocals < 1 ? 1 : maxLocals];
        for (int i = 0; i < argCount; i++) {
            checkKind(args[i], argKinds[i]);
            int slot = 0;
            for (int j = 0; j < i; j++) {
                slot += width(argKinds[j]);
            }
            locals[slot] = maskLocal(args[i], argKinds[i], localIntMask, localLongMask);
        }

        Object[] stack = new Object[maxStack < 1 ? 1 : maxStack];
        int sp = 0;
        int pc = 0;
        int previousPc = -1;
        byte[] instruction = new byte[MAX_INSTRUCTION_BYTES];
        byte[] counter = new byte[16];
        byte[] keystream = new byte[16];
        long stepCounter = 0L;
        // CPU-time probe: wall-clock time is deliberately not used. Blocking, GC pauses, screen
        // switches and CPU frequency scaling do not consume this thread's CPU time, so they can
        // never false-positive. Default mode is telemetry; see ChimeraVmProbe.
        boolean probeEnabled = ChimeraVmProbe.mode() != ChimeraVmProbe.MODE_OFF
                && ChimeraVmProbe.clockAvailable();
        long probeInterval = ChimeraVmProbe.interval();
        if (probeInterval < 1L) probeInterval = 1L;
        long lastProbe = probeEnabled ? ChimeraVmProbe.cpuNanos() : 0L;
        while (true) {
            if (pc < 0 || pc >= instructionCount) {
                throw new IllegalStateException("vm program counter out of range");
            }
            if (probeEnabled && ++stepCounter % probeInterval == 0L) {
                long current = ChimeraVmProbe.cpuNanos();
                if (ChimeraVmProbe.evaluate(current - lastProbe)) {
                    throw new IllegalStateException("vm timing anomaly (instrumented execution)");
                }
                lastProbe = current;
            }

            int recordStart = offsets[pc];
            int recordEnd = offsets[pc + 1];
            if (recordStart < 0 || recordEnd > records.length || recordEnd <= recordStart) {
                throw new IllegalStateException("bad vm record bounds");
            }
            DataInputStream recordIn = new DataInputStream(
                    new ByteArrayInputStream(records, recordStart, recordEnd - recordStart));
            int predecessorCount = recordIn.readUnsignedShort();
            int length = -1;
            for (int i = 0; i < predecessorCount; i++) {
                int predecessorPc = recordIn.readInt();
                int encryptedLength = recordIn.readUnsignedByte();
                if (encryptedLength <= 0 || encryptedLength > MAX_INSTRUCTION_BYTES) {
                    throw new IllegalStateException("bad vm edge length");
                }
                if (predecessorPc == previousPc && length < 0) {
                    recordIn.readFully(instruction, 0, encryptedLength);
                    length = encryptedLength;
                } else {
                    recordIn.skipBytes(encryptedLength);
                }
            }
            if (length < 0) {
                // No ciphertext copy for this (previous pc -> pc) edge: the interpreter state or
                // the control-flow graph was tampered with.
                throw new IllegalStateException("vm missing edge chain state");
            }
            edgeDecrypt(cipher, nonce, previousPc, pc, instruction, length, counter, keystream);
            int rawOpcode = instruction[0] & 0xff;
            int opcode = opcodeTable[rawOpcode] & 0xff;
            if (opcode == 0) {
                Arrays.fill(instruction, (byte) 0);
                throw new IllegalStateException("unknown polymorphic opcode: " + rawOpcode);
            }
            int operandSize = operandSize(opcode);
            if (operandSize < 0 || length != 1 + operandSize) {
                Arrays.fill(instruction, (byte) 0);
                throw new IllegalStateException("vm instruction size mismatch: len=" + length
                        + " pc=" + pc + " opcode=" + opcode);
            }
            long operand;
            int meta;
            int memberIndex = -1;
            int memberKind = 0;
            int memberArgumentCount = 0;
            int memberReturnKind = 0;
            // B7 step 1 operand slots (parsed before the instruction buffer is wiped).
            byte[] pushedBytes = null;
            int nativeIndex = -1;
            int nativeArgumentCount = 0;
            int nativeReturnKind = 0;
            int byteIndex = 0;
            switch (opcode) {
                case OP_PUSH_I:
                    operand = readInt(instruction, 1);
                    meta = 0;
                    break;
                case OP_PUSH_L:
                case OP_PUSH_D:
                    operand = readLong(instruction, 1);
                    meta = 0;
                    break;
                case OP_LOAD:
                case OP_STORE: {
                    int kind = instruction[1] & 0xff;
                    int slot = readShort(instruction, 2);
                    meta = (kind << 16) | slot;
                    operand = 0L;
                    break;
                }
                case OP_IINC: {
                    int slot = readShort(instruction, 1);
                    int delta = instruction[3];
                    meta = slot;
                    operand = delta;
                    break;
                }
                case OP_GOTO:
                case OP_IFEQ:
                case OP_IFNE:
                case OP_IFLT:
                case OP_IFGE:
                case OP_IFGT:
                case OP_IFLE:
                case OP_IF_ICMPEQ:
                case OP_IF_ICMPNE:
                case OP_IF_ICMPLT:
                case OP_IF_ICMPGE:
                case OP_IF_ICMPGT:
                case OP_IF_ICMPLE: {
                    int target = readShort(instruction, 1);
                    if (target < 0 || target >= instructionCount) {
                        Arrays.fill(instruction, (byte) 0);
                        throw new IllegalStateException("vm jump target out of range: " + target);
                    }
                    operand = target;
                    meta = 0;
                    break;
                }
                case OP_GETFIELD:
                case OP_GETSTATIC:
                    memberIndex = readShort(instruction, 1);
                    memberKind = instruction[3] & 0xff;
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_INVOKESTATIC:
                case OP_INVOKEVIRTUAL:
                    memberIndex = readShort(instruction, 1);
                    memberArgumentCount = instruction[3] & 0xff;
                    memberReturnKind = instruction[4] & 0xff;
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_PUTFIELD:
                case OP_PUTSTATIC:
                    memberIndex = readShort(instruction, 1);
                    memberKind = instruction[3] & 0xff;
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_PUSH_B256:
                    pushedBytes = Arrays.copyOfRange(instruction, 1, 1 + U256_BYTES);
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_CALL_NATIVE:
                    nativeIndex = readShort(instruction, 1);
                    nativeArgumentCount = instruction[3] & 0xff;
                    nativeReturnKind = instruction[4] & 0xff;
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_LOAD_BYTE:
                    byteIndex = instruction[1] & 0xff;
                    operand = 0L;
                    meta = 0;
                    break;
                case OP_RET: {
                    meta = instruction[1] & 0xff;
                    operand = 0L;
                    break;
                }
                default:
                    operand = 0L;
                    meta = 0;
                    break;
            }
            // Wipe the decrypted instruction bytes before executing it.
            Arrays.fill(instruction, (byte) 0);
            boolean jump = false;
            int nextPc = pc + 1;
            try {
            switch (opcode) {
                case OP_PUSH_I:
                    stack[sp++] = Integer.valueOf((int) operand);
                    break;
                case OP_PUSH_L:
                    stack[sp++] = Long.valueOf(operand);
                    break;
                case OP_PUSH_D:
                    stack[sp++] = Double.valueOf(Double.longBitsToDouble(operand));
                    break;
                case OP_LOAD: {
                    int kind = meta >>> 16;
                    checkKindCode(kind);
                    Object value = unmaskLocal(locals[meta & 0xffff], kind, localIntMask, localLongMask);
                    checkKind(value, kind);
                    stack[sp++] = value;
                    break;
                }
                case OP_STORE: {
                    int kind = meta >>> 16;
                    checkKindCode(kind);
                    Object value = stack[--sp];
                    checkKind(value, kind);
                    locals[meta & 0xffff] = maskLocal(value, kind, localIntMask, localLongMask);
                    break;
                }
                case OP_IINC: {
                    Object value = unmaskLocal(locals[meta], TYPE_I, localIntMask, localLongMask);
                    if (!(value instanceof Integer)) {
                        throw new IllegalStateException("vm iinc type mismatch");
                    }
                    int next = ((Integer) value).intValue() + (int) operand;
                    locals[meta] = maskLocal(Integer.valueOf(next), TYPE_I, localIntMask, localLongMask);
                    break;
                }
                case OP_IADD: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a + b);
                    break;
                }
                case OP_ISUB: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a - b);
                    break;
                }
                case OP_IMUL: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a * b);
                    break;
                }
                case OP_IDIV: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    if (b == 0) {
                        throw new ArithmeticException("vm int division by zero");
                    }
                    stack[sp++] = Integer.valueOf(a / b);
                    break;
                }
                case OP_IREM: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    if (b == 0) {
                        throw new ArithmeticException("vm int remainder by zero");
                    }
                    stack[sp++] = Integer.valueOf(a % b);
                    break;
                }
                case OP_INEG:
                    stack[sp - 1] = Integer.valueOf(-intOf(stack[sp - 1]));
                    break;
                case OP_IAND: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a & b);
                    break;
                }
                case OP_IOR: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a | b);
                    break;
                }
                case OP_IXOR: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a ^ b);
                    break;
                }
                case OP_ISHL: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a << (b & 0x1f));
                    break;
                }
                case OP_ISHR: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a >> (b & 0x1f));
                    break;
                }
                case OP_IUSHR: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a >>> (b & 0x1f));
                    break;
                }
                case OP_I2B:
                    stack[sp - 1] = Integer.valueOf((byte) intOf(stack[sp - 1]));
                    break;
                case OP_I2C:
                    stack[sp - 1] = Integer.valueOf((char) intOf(stack[sp - 1]));
                    break;
                case OP_I2S:
                    stack[sp - 1] = Integer.valueOf((short) intOf(stack[sp - 1]));
                    break;
                case OP_LADD: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a + b);
                    break;
                }
                case OP_LSUB: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a - b);
                    break;
                }
                case OP_LMUL: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a * b);
                    break;
                }
                case OP_LDIV: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    if (b == 0L) {
                        throw new ArithmeticException("vm long division by zero");
                    }
                    stack[sp++] = Long.valueOf(a / b);
                    break;
                }
                case OP_LREM: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    if (b == 0L) {
                        throw new ArithmeticException("vm long remainder by zero");
                    }
                    stack[sp++] = Long.valueOf(a % b);
                    break;
                }
                case OP_LNEG:
                    stack[sp - 1] = Long.valueOf(-longOf(stack[sp - 1]));
                    break;
                case OP_LAND: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a & b);
                    break;
                }
                case OP_LOR: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a | b);
                    break;
                }
                case OP_LXOR: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a ^ b);
                    break;
                }
                case OP_LSHL: {
                    int b = intOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a << (b & 0x3f));
                    break;
                }
                case OP_LSHR: {
                    int b = intOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a >> (b & 0x3f));
                    break;
                }
                case OP_LUSHR: {
                    int b = intOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Long.valueOf(a >>> (b & 0x3f));
                    break;
                }
                case OP_LCMP: {
                    long b = longOf(stack[--sp]);
                    long a = longOf(stack[--sp]);
                    stack[sp++] = Integer.valueOf(a == b ? 0 : (a < b ? -1 : 1));
                    break;
                }
                case OP_DADD: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    stack[sp++] = Double.valueOf(a + b);
                    break;
                }
                case OP_DSUB: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    stack[sp++] = Double.valueOf(a - b);
                    break;
                }
                case OP_DMUL: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    stack[sp++] = Double.valueOf(a * b);
                    break;
                }
                case OP_DDIV: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    stack[sp++] = Double.valueOf(a / b);
                    break;
                }
                case OP_DREM: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    stack[sp++] = Double.valueOf(a % b);
                    break;
                }
                case OP_DNEG:
                    stack[sp - 1] = Double.valueOf(-doubleOf(stack[sp - 1]));
                    break;
                case OP_DCMPG: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    int result;
                    if (a > b) {
                        result = 1;
                    } else if (a < b) {
                        result = -1;
                    } else if (a == b) {
                        result = 0;
                    } else {
                        result = 1;
                    }
                    stack[sp++] = Integer.valueOf(result);
                    break;
                }
                case OP_DCMPL: {
                    double b = doubleOf(stack[--sp]);
                    double a = doubleOf(stack[--sp]);
                    int result;
                    if (a > b) {
                        result = 1;
                    } else if (a < b) {
                        result = -1;
                    } else if (a == b) {
                        result = 0;
                    } else {
                        result = -1;
                    }
                    stack[sp++] = Integer.valueOf(result);
                    break;
                }
                case OP_I2L:
                    stack[sp - 1] = Long.valueOf((long) intOf(stack[sp - 1]));
                    break;
                case OP_I2D:
                    stack[sp - 1] = Double.valueOf((double) intOf(stack[sp - 1]));
                    break;
                case OP_L2I:
                    stack[sp - 1] = Integer.valueOf((int) longOf(stack[sp - 1]));
                    break;
                case OP_L2D:
                    stack[sp - 1] = Double.valueOf((double) longOf(stack[sp - 1]));
                    break;
                case OP_D2I:
                    stack[sp - 1] = Integer.valueOf((int) doubleOf(stack[sp - 1]));
                    break;
                case OP_D2L:
                    stack[sp - 1] = Long.valueOf((long) doubleOf(stack[sp - 1]));
                    break;
                case OP_GOTO:
                    nextPc = (int) operand;
                    jump = true;
                    break;
                case OP_IFEQ:
                    nextPc = intOf(stack[--sp]) == 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IFNE:
                    nextPc = intOf(stack[--sp]) != 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IFLT:
                    nextPc = intOf(stack[--sp]) < 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IFGE:
                    nextPc = intOf(stack[--sp]) >= 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IFGT:
                    nextPc = intOf(stack[--sp]) > 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IFLE:
                    nextPc = intOf(stack[--sp]) <= 0 ? (int) operand : nextPc;
                    jump = true;
                    break;
                case OP_IF_ICMPEQ: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a == b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_IF_ICMPNE: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a != b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_IF_ICMPLT: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a < b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_IF_ICMPGE: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a >= b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_IF_ICMPGT: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a > b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_IF_ICMPLE: {
                    int b = intOf(stack[--sp]);
                    int a = intOf(stack[--sp]);
                    nextPc = a <= b ? (int) operand : nextPc;
                    jump = true;
                    break;
                }
                case OP_GETFIELD: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 0) {
                        throw new IllegalStateException("vm bad field reference");
                    }
                    Field field = resolveField(memberIndex, memberOwners, memberNames, fieldCache);
                    Object target = stack[--sp];
                    stack[sp++] = convertMemberValue(field.get(target), memberKind);
                    break;
                }
                case OP_GETSTATIC: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 0) {
                        throw new IllegalStateException("vm bad static field reference");
                    }
                    Field field = resolveField(memberIndex, memberOwners, memberNames, fieldCache);
                    stack[sp++] = convertMemberValue(field.get(null), memberKind);
                    break;
                }
                case OP_PUTFIELD: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 0) {
                        throw new IllegalStateException("vm bad field reference");
                    }
                    Field field = resolveField(memberIndex, memberOwners, memberNames, fieldCache);
                    Object value = stack[--sp];
                    Object target = stack[--sp];
                    field.set(target, convertMemberValue(value, memberKind));
                    break;
                }
                case OP_PUTSTATIC: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 0) {
                        throw new IllegalStateException("vm bad static field reference");
                    }
                    Field field = resolveField(memberIndex, memberOwners, memberNames, fieldCache);
                    Object value = stack[--sp];
                    field.set(null, convertMemberValue(value, memberKind));
                    break;
                }
                case OP_INVOKESTATIC: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 1) {
                        throw new IllegalStateException("vm bad static method reference");
                    }
                    MethodHandle handle = resolveHandle(memberIndex, memberOwners, memberNames,
                            memberDescs, handleCache, 1);
                    if (memberArgumentCount < 0 || memberArgumentCount > sp) {
                        throw new IllegalStateException("vm bad call argument count");
                    }
                    Object[] callArguments = new Object[memberArgumentCount];
                    for (int i = memberArgumentCount - 1; i >= 0; i--) {
                        callArguments[i] = stack[--sp];
                    }
                    Object result;
                    try {
                        result = handle.invokeWithArguments(callArguments);
                    } catch (Throwable t) {
                        throw new IllegalStateException("vm static call failed: "
                                + memberNames[memberIndex], t);
                    }
                    if (memberReturnKind != TYPE_V) {
                        stack[sp++] = convertMemberValue(result, memberReturnKind);
                    }
                    break;
                }
                case OP_INVOKEVIRTUAL: {
                    if (memberIndex < 0 || memberIndex >= memberCount || memberKinds[memberIndex] != 2) {
                        throw new IllegalStateException("vm bad virtual method reference");
                    }
                    MethodHandle handle = resolveHandle(memberIndex, memberOwners, memberNames,
                            memberDescs, handleCache, 2);
                    if (memberArgumentCount < 0 || memberArgumentCount + 1 > sp) {
                        throw new IllegalStateException("vm bad call argument count");
                    }
                    Object[] callArguments = new Object[memberArgumentCount + 1];
                    for (int i = memberArgumentCount - 1; i >= 0; i--) {
                        callArguments[i + 1] = stack[--sp];
                    }
                    callArguments[0] = stack[--sp];
                    Object result;
                    try {
                        result = handle.invokeWithArguments(callArguments);
                    } catch (Throwable t) {
                        throw new IllegalStateException("vm virtual call failed: "
                                + memberNames[memberIndex], t);
                    }
                    if (memberReturnKind != TYPE_V) {
                        stack[sp++] = convertMemberValue(result, memberReturnKind);
                    }
                    break;
                }
                // ------------------------------------------------------ B7 step 1: ISA extension
                case OP_PUSH_B256: {
                    if (pushedBytes == null || pushedBytes.length != U256_BYTES) {
                        throw new IllegalStateException("vm PUSH_B256 operand missing");
                    }
                    stack[sp++] = pushedBytes;
                    break;
                }
                case OP_POP_B256:
                    requireU256(stack[--sp]);
                    break;
                case OP_LOAD_BYTE: {
                    byte[] value = requireU256(stack[--sp]);
                    if (byteIndex < 0 || byteIndex >= U256_BYTES) {
                        throw new IllegalStateException("vm LOAD_BYTE index out of bounds: " + byteIndex);
                    }
                    stack[sp++] = Integer.valueOf(value[byteIndex] & 0xff);
                    break;
                }
                case OP_CMP_U256: {
                    byte[] b = requireU256(stack[--sp]);
                    byte[] a = requireU256(stack[--sp]);
                    stack[sp++] = Integer.valueOf(compareU256(a, b));
                    break;
                }
                case OP_CALL_NATIVE: {
                    if (nativeArgumentCount < 0 || nativeArgumentCount > sp) {
                        throw new IllegalStateException("vm native argument count out of range: "
                                + nativeArgumentCount);
                    }
                    Object[] callArguments = new Object[nativeArgumentCount];
                    for (int i = nativeArgumentCount - 1; i >= 0; i--) {
                        callArguments[i] = stack[--sp];
                    }
                    long nativeHandle = currentNativeHandle();
                    if (nativeHandle != 0L) {
                        // B7 step 2 production path: opaque u16 index -> C++ function table. No
                        // function address ever crosses the VM/JNI boundary.
                        byte[] params = encodeNativeVmCall(nativeIndex, callArguments, nativeReturnKind);
                        byte[] nativeResult;
                        try {
                            nativeResult = ChimeraRuntime.nativeCompute(nativeHandle, params);
                        } catch (Throwable t) {
                            throw new IllegalStateException("vm native call failed: " + nativeIndex, t);
                        }
                        if (nativeReturnKind != TYPE_V) {
                            stack[sp++] = decodeNativeResult(nativeResult, nativeReturnKind);
                        }
                        break;
                    }
                    // No active native session (dev/test): Java handler registry from step 1.
                    java.util.function.Function<Object[], Object> handler =
                            NATIVE_HANDLERS.get(Integer.valueOf(nativeIndex));
                    if (handler == null) {
                        throw new IllegalStateException("vm native handler missing: " + nativeIndex);
                    }
                    Object result;
                    try {
                        result = handler.apply(callArguments);
                    } catch (Throwable t) {
                        // fail-closed: handler faults never escape to Java callers, they poison.
                        throw new IllegalStateException("vm native handler failed: " + nativeIndex, t);
                    }
                    if (nativeReturnKind != TYPE_V) {
                        stack[sp++] = convertMemberValue(result, nativeReturnKind);
                    }
                    break;
                }
                case OP_VERIFY_DECISION: {
                    // No stack result and no return path: only VM/handle semantic state is written.
                    byte[] tag = requireU256(stack[--sp]);
                    long decisionHandle = currentNativeHandle();
                    if (decisionHandle != 0L) {
                        // B7 step 2: the native side recomputes the expected tag, promotes the
                        // pending handle to valid only on match, and returns a fixed no-decision
                        // shape that the VM intentionally ignores.
                        byte[] params = new byte[1 + U256_BYTES];
                        params[0] = (byte) NATIVE_OP_VERIFY_DECISION;
                        System.arraycopy(tag, 0, params, 1, U256_BYTES);
                        try {
                            ChimeraRuntime.nativeCompute(decisionHandle, params);
                        } catch (Throwable t) {
                            throw new IllegalStateException("vm verify decision native call failed", t);
                        }
                    } else {
                        // Step 1 placeholder for no-session unit tests: Java-visible state only.
                        verifyDecisionState = mixDecision(tag);
                        verifyDecisionWrites = verifyDecisionWrites + 1;
                    }
                    break;
                }
                case OP_RET: {
                    Object value = stack[--sp];
                    checkKind(value, meta);
                    if (sp != 0) {
                        throw new IllegalStateException("vm return stack not empty");
                    }
                    if (meta != returnKind) {
                        throw new IllegalStateException("vm return type mismatch");
                    }
                    return value;
                }
                default:
                    throw new IllegalStateException("unknown vm opcode: " + opcode);
            }
                if (jump) {
                    throw new ChimeraVmJump(nextPc);
                }
            } catch (ChimeraVmJump signal) {
                // Exception-based control flow: jumps do not appear as a regular switch assignment.
                previousPc = pc;
                pc = signal.target;
                continue;
            }
            previousPc = pc;
            pc = nextPc;
        }
    }

    private static Class<?> loadMemberClass(String internalName) throws ClassNotFoundException {
        ClassLoader loader = ChimeraVmRuntime.class.getClassLoader();
        if (loader == null) {
            loader = ClassLoader.getSystemClassLoader();
        }
        return Class.forName(internalName.replace('/', '.'), false, loader);
    }

    private static Field resolveField(int index, String[] owners, String[] names, Object[] cache)
            throws Exception {
        Field field = (Field) cache[index];
        if (field != null) {
            return field;
        }
        field = loadMemberClass(owners[index]).getDeclaredField(names[index]);
        try {
            field.setAccessible(true);
        } catch (Throwable ignored) {
            // public fields remain accessible without setAccessible
        }
        cache[index] = field;
        return field;
    }

    private static MethodHandle resolveHandle(int index, String[] owners, String[] names,
                                              String[] descs, Object[] cache, int memberKind)
            throws Exception {
        MethodHandle handle = (MethodHandle) cache[index];
        if (handle != null) {
            return handle;
        }
        ClassLoader loader = ChimeraVmRuntime.class.getClassLoader();
        if (loader == null) {
            loader = ClassLoader.getSystemClassLoader();
        }
        Class<?> owner = loadMemberClass(owners[index]);
        MethodType type = MethodType.fromMethodDescriptorString(descs[index], loader);
        if (memberKind == 2) {
            // INVOKEVIRTUAL: virtual dispatch through the runtime receiver type (handles overrides).
            handle = MethodHandles.publicLookup().findVirtual(owner, names[index], type);
        } else {
            handle = MethodHandles.publicLookup().findStatic(owner, names[index], type);
        }
        cache[index] = handle;
        return handle;
    }

    private static Object convertMemberValue(Object value, int kind) {
        switch (kind) {
            case TYPE_I:
                if (value instanceof Integer) {
                    return value;
                }
                throw new IllegalStateException("vm field type mismatch: expected int");
            case TYPE_L:
                if (value instanceof Long) {
                    return value;
                }
                throw new IllegalStateException("vm field type mismatch: expected long");
            case TYPE_D:
                if (value instanceof Double) {
                    return value;
                }
                throw new IllegalStateException("vm field type mismatch: expected double");
            case TYPE_O:
                return value;
            case TYPE_V:
                return null;
            default:
                throw new IllegalStateException("bad vm member kind: " + kind);
        }
    }

    /** Per-edge keystream: the decryption key for instruction pc depends on the previous pc. */
    private static void edgeDecrypt(Cipher cipher, byte[] nonce, int previousPc, int pc,
                                    byte[] instruction, int length,
                                    byte[] counter, byte[] keystream) throws Exception {
        int block = edgeBlock(previousPc, pc);
        int cached = -1;
        synchronized (cipher) {
            for (int i = 0; i < length; i++) {
                int index = block + (i >>> 4);
                int offset = i & 15;
                if (index != cached) {
                    System.arraycopy(nonce, 0, counter, 0, 12);
                    counter[12] = (byte) (index >>> 24);
                    counter[13] = (byte) (index >>> 16);
                    counter[14] = (byte) (index >>> 8);
                    counter[15] = (byte) index;
                    if (cipher.update(counter, 0, 16, keystream, 0) != 16) {
                        throw new IllegalStateException("vm edge keystream failure");
                    }
                    cached = index;
                }
                instruction[i] = (byte) (instruction[i] ^ keystream[offset]);
            }
        }
    }

    private static int edgeBlock(int previousPc, int pc) {
        int mixed = previousPc * 0x9E3779B1 ^ pc * 0x85EBCA77;
        mixed ^= mixed >>> 16;
        return mixed & 0x7fffffff;
    }

    /** Locals are stored with a dynamic mask so a memory dump does not reveal intermediate state. */
    private static Object maskLocal(Object value, int kind, int intMask, long longMask) {
        switch (kind) {
            case TYPE_I:
                return Integer.valueOf(((Integer) value).intValue() ^ intMask);
            case TYPE_L:
                return Long.valueOf(((Long) value).longValue() ^ longMask);
            case TYPE_D:
                return Double.valueOf(Double.longBitsToDouble(
                        Double.doubleToRawLongBits(((Double) value).doubleValue()) ^ longMask));
            default:
                return value;
        }
    }

    private static Object unmaskLocal(Object value, int kind, int intMask, long longMask) {
        if (value == null) return null;
        switch (kind) {
            case TYPE_I:
                return Integer.valueOf(((Integer) value).intValue() ^ intMask);
            case TYPE_L:
                return Long.valueOf(((Long) value).longValue() ^ longMask);
            case TYPE_D:
                return Double.valueOf(Double.longBitsToDouble(
                        Double.doubleToRawLongBits(((Double) value).doubleValue()) ^ longMask));
            default:
                return value;
        }
    }

    private static int operandSize(int opcode) {
        switch (opcode) {
            case OP_PUSH_I:
                return 4;
            case OP_PUSH_L:
            case OP_PUSH_D:
                return 8;
            case OP_LOAD:
            case OP_STORE:
                return 3;
            case OP_IINC:
                return 3;
            case OP_GOTO:
            case OP_IFEQ:
            case OP_IFNE:
            case OP_IFLT:
            case OP_IFGE:
            case OP_IFGT:
            case OP_IFLE:
            case OP_IF_ICMPEQ:
            case OP_IF_ICMPNE:
            case OP_IF_ICMPLT:
            case OP_IF_ICMPGE:
            case OP_IF_ICMPGT:
            case OP_IF_ICMPLE:
                return 2;
            case OP_RET:
                return 1;
            case OP_GETFIELD:
            case OP_GETSTATIC:
            case OP_PUTFIELD:
            case OP_PUTSTATIC:
                return 3;
            case OP_INVOKESTATIC:
            case OP_INVOKEVIRTUAL:
                return 4;
            case OP_PUSH_B256:
                return 32;
            case OP_LOAD_BYTE:
                return 1;
            case OP_CALL_NATIVE:
                return 4;
            case OP_POP_B256:
            case OP_CMP_U256:
            case OP_VERIFY_DECISION:
                return 0;
            case OP_IADD:
            case OP_ISUB:
            case OP_IMUL:
            case OP_IDIV:
            case OP_IREM:
            case OP_INEG:
            case OP_IAND:
            case OP_IOR:
            case OP_IXOR:
            case OP_ISHL:
            case OP_ISHR:
            case OP_IUSHR:
            case OP_I2B:
            case OP_I2C:
            case OP_I2S:
            case OP_LADD:
            case OP_LSUB:
            case OP_LMUL:
            case OP_LDIV:
            case OP_LREM:
            case OP_LNEG:
            case OP_LAND:
            case OP_LOR:
            case OP_LXOR:
            case OP_LSHL:
            case OP_LSHR:
            case OP_LUSHR:
            case OP_LCMP:
            case OP_DADD:
            case OP_DSUB:
            case OP_DMUL:
            case OP_DDIV:
            case OP_DREM:
            case OP_DNEG:
            case OP_DCMPG:
            case OP_DCMPL:
            case OP_I2L:
            case OP_I2D:
            case OP_L2I:
            case OP_L2D:
            case OP_D2I:
            case OP_D2L:
                return 0;
            default:
                return -1;
        }
    }

    // ------------------------------------------------------------------ B7 step 2 native bridge

    /** Current native SessionHandle (0 when no native auth session is active). */
    private static long currentNativeHandle() {
        try {
            java.lang.reflect.Field field = sessionHandleField;
            if (field == null) {
                field = ChimeraRuntime.class.getDeclaredField("nativeSessionHandle");
                field.setAccessible(true);
                sessionHandleField = field;
            }
            return field.getLong(null);
        } catch (Throwable t) {
            return 0L;
        }
    }

    /**
     * Encodes one CALL_NATIVE request for nativeCompute op6:
     * [6][u16 BE index][u8 argc][u8 returnKind][32B slot per argument]. Numeric slots carry
     * their big-endian 64-bit two's-complement/raw-bits value in the last 8 bytes; byte[32]
     * arguments (256-bit integers) use the full slot. No function address or JNI local ref is
     * passed: the native table resolves the opaque index.
     */
    private static byte[] encodeNativeVmCall(int index, Object[] arguments, int returnKind) {
        byte[] params = new byte[5 + arguments.length * U256_BYTES];
        params[0] = (byte) NATIVE_OP_VM_CALL;
        params[1] = (byte) (index >>> 8);
        params[2] = (byte) index;
        params[3] = (byte) arguments.length;
        params[4] = (byte) returnKind;
        for (int i = 0; i < arguments.length; i++) {
            int offset = 5 + i * U256_BYTES;
            Object argument = arguments[i];
            if (argument instanceof byte[] bytes && bytes.length == U256_BYTES) {
                System.arraycopy(bytes, 0, params, offset, U256_BYTES);
            } else if (argument instanceof Integer intValue) {
                writeNumericSlot(params, offset, intValue.longValue());
            } else if (argument instanceof Long longValue) {
                writeNumericSlot(params, offset, longValue.longValue());
            } else if (argument instanceof Double doubleValue) {
                writeNumericSlot(params, offset, Double.doubleToRawLongBits(doubleValue.doubleValue()));
            } else {
                throw new IllegalStateException("vm native call unsupported argument type");
            }
        }
        return params;
    }

    private static void writeNumericSlot(byte[] out, int offset, long value) {
        for (int i = 0; i < 8; i++) {
            out[offset + U256_BYTES - 1 - i] = (byte) (value >>> (8 * i));
        }
    }

    /**
     * Decodes the nativeCompute op6 result into a VM stack value. The native side returns 4B for
     * int, 8B for long/double (big-endian) and the raw byte[] for object kinds.
     */
    private static Object decodeNativeResult(byte[] result, int kind) {
        if (result == null) {
            throw new IllegalStateException("vm native call returned null");
        }
        if (kind == TYPE_O) {
            return result;
        }
        if (kind == TYPE_I) {
            if (result.length < 4) {
                throw new IllegalStateException("vm native int result length: " + result.length);
            }
            int value = ((result[0] & 0xff) << 24) | ((result[1] & 0xff) << 16)
                    | ((result[2] & 0xff) << 8) | (result[3] & 0xff);
            return Integer.valueOf(value);
        }
        if (result.length < 8) {
            throw new IllegalStateException("vm native numeric result length: " + result.length);
        }
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (result[i] & 0xffL);
        }
        switch (kind) {
            case TYPE_L:
                return Long.valueOf(value);
            case TYPE_D:
                return Double.valueOf(Double.longBitsToDouble(value));
            default:
                throw new IllegalStateException("vm native call bad return kind: " + kind);
        }
    }

    // ------------------------------------------------------------------ B7 step 1 helpers

    private static byte[] requireU256(Object value) {
        if (value instanceof byte[] bytes && bytes.length == U256_BYTES) {
            return bytes;
        }
        throw new IllegalStateException("vm type mismatch: expected 32-byte unsigned integer");
    }

    /** Unsigned big-endian 256-bit comparison: -1 (a&lt;b), 0 (a==b), 1 (a&gt;b). */
    private static int compareU256(byte[] a, byte[] b) {
        for (int i = 0; i < U256_BYTES; i++) {
            int left = a[i] & 0xff;
            int right = b[i] & 0xff;
            if (left != right) {
                return left < right ? -1 : 1;
            }
        }
        return 0;
    }

    /** Placeholder VERIFY_DECISION state derivation (step 2: native handle recomputes the tag). */
    private static int mixDecision(byte[] tag) {
        int state = 0x9E3779B9;
        for (int i = 0; i < tag.length; i++) {
            state = (state ^ (tag[i] & 0xff)) * 0x85EBCA6B;
            state ^= state >>> 13;
        }
        return state == 0 ? 0x6D2B79F5 : state;
    }

    private static int readInt(byte[] code, int offset) {
        return ((code[offset] & 0xff) << 24)
                | ((code[offset + 1] & 0xff) << 16)
                | ((code[offset + 2] & 0xff) << 8)
                | (code[offset + 3] & 0xff);
    }

    private static int readShort(byte[] code, int offset) {
        return ((code[offset] & 0xff) << 8) | (code[offset + 1] & 0xff);
    }

    private static long readLong(byte[] code, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (code[offset + i] & 0xffL);
        }
        return value;
    }

    private static void checkKindCode(int kind) {
        if (kind != TYPE_I && kind != TYPE_L && kind != TYPE_D && kind != TYPE_O) {
            throw new IllegalStateException("bad vm type code: " + kind);
        }
    }

    private static void checkKind(Object value, int kind) {
        switch (kind) {
            case TYPE_I:
                if (!(value instanceof Integer)) {
                    throw new IllegalStateException("vm type mismatch: expected int");
                }
                break;
            case TYPE_L:
                if (!(value instanceof Long)) {
                    throw new IllegalStateException("vm type mismatch: expected long");
                }
                break;
            case TYPE_D:
                if (!(value instanceof Double)) {
                    throw new IllegalStateException("vm type mismatch: expected double");
                }
                break;
            case TYPE_O:
                // null and any reference are valid opaque objects
                break;
            default:
                throw new IllegalStateException("bad vm type code: " + kind);
        }
    }

    private static int intOf(Object value) {
        if (value instanceof Integer integer) {
            return integer.intValue();
        }
        throw new IllegalStateException("vm type mismatch: expected int");
    }

    private static long longOf(Object value) {
        if (value instanceof Long longValue) {
            return longValue.longValue();
        }
        throw new IllegalStateException("vm type mismatch: expected long");
    }

    private static double doubleOf(Object value) {
        if (value instanceof Double doubleValue) {
            return doubleValue.doubleValue();
        }
        throw new IllegalStateException("vm type mismatch: expected double");
    }
}
