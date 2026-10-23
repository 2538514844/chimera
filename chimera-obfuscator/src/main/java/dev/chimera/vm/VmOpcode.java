package dev.chimera.vm;

/**
 * Opcode constants of the M9 stack VM.
 *
 * <p>The numeric values are part of the on-disk blob format and are duplicated in
 * {@code dev.chimera.runtime.ChimeraVmRuntime} (the runtime is injected into the protected jar
 * and must not depend on the build-time obfuscator classes). Any change here requires the same
 * change there and a format version bump.</p>
 *
 * <p>Control flow: {@link #GOTO} and the {@code IF*} opcodes carry a 2-byte big-endian target
 * program counter. Jumps only target instruction boundaries, never byte offsets.</p>
 */
public final class VmOpcode {

    /** Push a 32-bit int immediate (4-byte big-endian operand). */
    public static final int PUSH_I = 1;
    /** Push a 64-bit long immediate (8-byte big-endian operand). */
    public static final int PUSH_L = 2;
    /** Push a 64-bit IEEE-754 double immediate (raw bits, 8-byte big-endian operand). */
    public static final int PUSH_D = 3;
    /** Load a local: 1-byte type (0=int, 1=long, 2=double) + 2-byte big-endian slot index. */
    public static final int LOAD = 4;
    /** Store to a local: 1-byte type + 2-byte slot index. */
    public static final int STORE = 5;
    /** int increment: 2-byte slot + 1-byte signed delta. */
    public static final int IINC = 6;

    public static final int IADD = 10;
    public static final int ISUB = 11;
    public static final int IMUL = 12;
    public static final int IDIV = 13;
    public static final int IREM = 14;
    public static final int INEG = 15;
    public static final int IAND = 16;
    public static final int IOR = 17;
    public static final int IXOR = 18;

    public static final int LADD = 20;
    public static final int LSUB = 21;
    public static final int LMUL = 22;
    public static final int LDIV = 23;
    public static final int LREM = 24;
    public static final int LNEG = 25;
    public static final int LAND = 26;
    public static final int LOR = 27;
    public static final int LXOR = 28;

    public static final int DADD = 30;
    public static final int DSUB = 31;
    public static final int DMUL = 32;
    public static final int DDIV = 33;
    public static final int DREM = 34;
    public static final int DNEG = 35;
    /** double compare (NaN -> +1 / -1); pushes int. */
    public static final int DCMPG = 36;
    public static final int DCMPL = 37;

    public static final int I2L = 40;
    public static final int I2D = 41;
    public static final int L2I = 42;
    public static final int L2D = 43;
    public static final int D2I = 44;
    public static final int D2L = 45;
    /** long compare; pushes int. */
    public static final int LCMP = 46;

    /** Return the top of stack; 1-byte type operand (0=int, 1=long, 2=double). */
    public static final int RET = 50;

    /** Unconditional jump: 2-byte big-endian target pc. */
    public static final int GOTO = 60;
    public static final int IFEQ = 61;
    public static final int IFNE = 62;
    public static final int IFLT = 63;
    public static final int IFGE = 64;
    public static final int IFGT = 65;
    public static final int IFLE = 66;
    public static final int IF_ICMPEQ = 67;
    public static final int IF_ICMPNE = 68;
    public static final int IF_ICMPLT = 69;
    public static final int IF_ICMPGE = 70;
    public static final int IF_ICMPGT = 71;
    public static final int IF_ICMPLE = 72;

    /** int shifts: shift count masked by 0x1f. */
    public static final int ISHL = 73;
    public static final int ISHR = 74;
    public static final int IUSHR = 75;
    /** long shifts: shift count masked by 0x3f. */
    public static final int LSHL = 76;
    public static final int LSHR = 77;
    public static final int LUSHR = 78;
    /** int narrowing conversions (result is a sign-extended int). */
    public static final int I2B = 79;
    public static final int I2C = 80;
    public static final int I2S = 81;

    /** Object field read: 2-byte member index + 1-byte value kind (object receiver popped). */
    public static final int GETFIELD = 90;
    /** Static field read: 2-byte member index + 1-byte value kind. */
    public static final int GETSTATIC = 91;
    /**
     * Static method bridge: 2-byte member index + 1-byte argument count + 1-byte return kind
     * (0=int, 1=long, 2=double, 3=object, 4=void). Invoked through a cached MethodHandle.
     */
    public static final int INVOKESTATIC = 92;
    /** Instance field write: 2-byte member index + 1-byte value kind (object + value popped). */
    public static final int PUTFIELD = 93;
    /** Static field write: 2-byte member index + 1-byte value kind. */
    public static final int PUTSTATIC = 94;
    /** Instance method bridge: 2-byte member index + 1-byte argument count + 1-byte return kind. */
    public static final int INVOKEVIRTUAL = 95;

    // ---------------------------------------------------------------- B7 step 1 (VM ISA extension)

    /** Push a fixed 32-byte big-endian unsigned 256-bit integer immediate. */
    public static final int PUSH_B256 = 200;
    /** Pop and validate a 32-byte unsigned 256-bit integer (stack hygiene). */
    public static final int POP_B256 = 201;
    /** Pop a 32-byte integer, push the unsigned value of one byte: op + u1 index (0..31). */
    public static final int LOAD_BYTE = 202;
    /** Pop two 32-byte integers, push int: -1 if a &lt; b, 0 if a == b, 1 if a &gt; b (unsigned). */
    public static final int CMP_U256 = 203;
    /**
     * Call a host-registered native handler by build-time encoded index: op + u2 index +
     * u1 argument count + u1 return kind (0=int, 1=long, 2=double, 3=object, 4=void).
     */
    public static final int CALL_NATIVE = 204;
    /** Pop a 32-byte decision tag, write VM/handle semantic state; no stack result. */
    public static final int VERIFY_DECISION = 205;

    /** Operand type codes used by LOAD/STORE/RET. */
    public static final int TYPE_I = 0;
    public static final int TYPE_L = 1;
    public static final int TYPE_D = 2;
    /** Opaque object reference (no arrays; fields/methods are resolved at runtime). */
    public static final int TYPE_O = 3;
    /** Return kind used by INVOKESTATIC for void methods. */
    public static final int TYPE_V = 4;

    private VmOpcode() {
    }

    /** Human readable opcode name, for diagnostics and documentation. */
    public static String name(int opcode) {
        switch (opcode) {
            case PUSH_I: return "PUSH_I";
            case PUSH_L: return "PUSH_L";
            case PUSH_D: return "PUSH_D";
            case LOAD: return "LOAD";
            case STORE: return "STORE";
            case IINC: return "IINC";
            case IADD: return "IADD";
            case ISUB: return "ISUB";
            case IMUL: return "IMUL";
            case IDIV: return "IDIV";
            case IREM: return "IREM";
            case INEG: return "INEG";
            case IAND: return "IAND";
            case IOR: return "IOR";
            case IXOR: return "IXOR";
            case LADD: return "LADD";
            case LSUB: return "LSUB";
            case LMUL: return "LMUL";
            case LDIV: return "LDIV";
            case LREM: return "LREM";
            case LNEG: return "LNEG";
            case LAND: return "LAND";
            case LOR: return "LOR";
            case LXOR: return "LXOR";
            case DADD: return "DADD";
            case DSUB: return "DSUB";
            case DMUL: return "DMUL";
            case DDIV: return "DDIV";
            case DREM: return "DREM";
            case DNEG: return "DNEG";
            case DCMPG: return "DCMPG";
            case DCMPL: return "DCMPL";
            case I2L: return "I2L";
            case I2D: return "I2D";
            case L2I: return "L2I";
            case L2D: return "L2D";
            case D2I: return "D2I";
            case D2L: return "D2L";
            case LCMP: return "LCMP";
            case RET: return "RET";
            case GOTO: return "GOTO";
            case IFEQ: return "IFEQ";
            case IFNE: return "IFNE";
            case IFLT: return "IFLT";
            case IFGE: return "IFGE";
            case IFGT: return "IFGT";
            case IFLE: return "IFLE";
            case IF_ICMPEQ: return "IF_ICMPEQ";
            case IF_ICMPNE: return "IF_ICMPNE";
            case IF_ICMPLT: return "IF_ICMPLT";
            case IF_ICMPGE: return "IF_ICMPGE";
            case IF_ICMPGT: return "IF_ICMPGT";
            case IF_ICMPLE: return "IF_ICMPLE";
            case ISHL: return "ISHL";
            case ISHR: return "ISHR";
            case IUSHR: return "IUSHR";
            case LSHL: return "LSHL";
            case LSHR: return "LSHR";
            case LUSHR: return "LUSHR";
            case I2B: return "I2B";
            case I2C: return "I2C";
            case I2S: return "I2S";
            case GETFIELD: return "GETFIELD";
            case GETSTATIC: return "GETSTATIC";
            case INVOKESTATIC: return "INVOKESTATIC";
            case PUTFIELD: return "PUTFIELD";
            case PUTSTATIC: return "PUTSTATIC";
            case INVOKEVIRTUAL: return "INVOKEVIRTUAL";
            case PUSH_B256: return "PUSH_B256";
            case POP_B256: return "POP_B256";
            case LOAD_BYTE: return "LOAD_BYTE";
            case CMP_U256: return "CMP_U256";
            case CALL_NATIVE: return "CALL_NATIVE";
            case VERIFY_DECISION: return "VERIFY_DECISION";
            default: return "UNKNOWN(" + opcode + ")";
        }
    }
}
