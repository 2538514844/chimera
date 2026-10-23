package dev.chimera.transform;

import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.crypto.Crypto;
import dev.chimera.vm.VmCompiler;
import dev.chimera.vm.VmOpcode;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * M9: virtualizes {@code @ChimeraVM} methods.
 *
 * <p>For every supported method the original body is compiled by {@link VmCompiler} and stored as
 * an AES-GCM encrypted blob ({@code /chimera/vm/vm_<id>.bin}); the method body itself becomes a
 * call to {@code ChimeraVmRuntime.execute(id, args)} followed by a type-correct poison fallback
 * and a {@code Number.xxxValue()} conversion. Methods outside the supported subset are left
 * untouched (annotation and body kept as-is).</p>
 */
public final class VMTransformer implements Transformer {

    /** Descriptor of {@code dev.chimera.annotations.ChimeraVM}. */
    private static final String ANNOTATION_DESC = "Ldev/chimera/annotations/ChimeraVM;";

    private static final String RUNTIME = "dev/chimera/runtime/ChimeraVmRuntime";
    private static final String EXECUTE_NAME = "execute";
    private static final String EXECUTE_DESC = "(I[Ljava/lang/Object;)Ljava/lang/Object;";
    private static final String IS_POISONED_NAME = "isPoisoned";
    private static final String IS_POISONED_DESC = "()Z";

    /** "CHVB" - encrypted resource magic consumed by ChimeraVmRuntime. */
    private static final int RESOURCE_MAGIC = 0x43485642;
    /** "CHVM" - decrypted plaintext header. */
    private static final int PLAIN_MAGIC = 0x4348564D;
    /**
     * Outer resource format 6 (KI-28): after the nonce the blob carries a ResourceKey-wrapped copy
     * of the per-blob VM item key, so an authorized runtime can recover it through native op9
     * DECRYPT_DATA without ever holding the ResourceKey in Java. Version 5 (no wrapped-key block)
     * is still accepted by ChimeraVmRuntime for test-encoded/legacy blobs.
     */
    private static final int FORMAT_VERSION = 6;
    /** Plaintext header version (unchanged by KI-28). */
    private static final int PLAIN_FORMAT_VERSION = 5;
    private static final int NONCE_LENGTH = 12;
    private static final String VM_WRAP_KIND = "vm-wrap";
    /** Maximum encoded VM instruction size; B7 PUSH_B256 instructions carry 32 immediate bytes. */
    private static final int MAX_INSTRUCTION_BYTES = 64;
    private static final String RESOURCE_DIR = "chimera/vm/vm_";
    private static final String RESOURCE_SUFFIX = ".bin";

    /** Ids are allocated per engine run in deterministic class/method iteration order. */
    private final AtomicInteger idSequence = new AtomicInteger();

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) throws Exception {
        if (!ctx.config.vm) {
            return;
        }
        if (node.methods == null || node.methods.isEmpty()) {
            return;
        }
        List<MethodNode> methods = new ArrayList<>(node.methods);
        for (MethodNode method : methods) {
            if (!isCandidate(method)) {
                continue;
            }
            if (ctx.config.strictFabric) {
                // Production remap safety: fail the build instead of generating a native/VM body
                // that references Minecraft/Fabric types (they are remapped at runtime).
                FabricSafetyGuard.check(node, method, "@ChimeraVM");
            }
            VmCompiler.Compiled compiled = VmCompiler.compile(method);
            if (compiled == null) {
                continue; // unsupported subset: leave the Java bytecode untouched
            }
            int id = idSequence.getAndIncrement();
            ctx.sink.put(RESOURCE_DIR + id + RESOURCE_SUFFIX, encodeResource(ctx, id, compiled));
            rewriteMethod(method, id, compiled.descriptor());
            removeVmAnnotation(method);
            ctx.stats.vmMethods++;
        }
    }

    private static boolean isCandidate(MethodNode method) {
        if (method == null || method.instructions == null) {
            return false;
        }
        if ((method.access & Opcodes.ACC_STATIC) == 0) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
            return false;
        }
        if (method.name.startsWith("<")) {
            return false;
        }
        return hasVmAnnotation(method.invisibleAnnotations) || hasVmAnnotation(method.visibleAnnotations);
    }

    private static boolean hasVmAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return false;
        }
        for (AnnotationNode annotation : annotations) {
            if (ANNOTATION_DESC.equals(annotation.desc)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ blob encoding

    /**
     * B7 step 1 test hook: encodes a hand-built {@link VmCompiler.Compiled} program with the
     * production v5 encoder (random opcode table, per-edge chained records, CTR + HMAC). This is
     * build-side only; it is not injected into protected jars.
     */
    public static byte[] encodeProgramForTest(TransformContext ctx, int id, VmCompiler.Compiled compiled)
            throws Exception {
        return encodeResource(ctx, id, compiled);
    }

    private static byte[] encodeResource(TransformContext ctx, int id, VmCompiler.Compiled compiled)
            throws Exception {
        byte[] code = compiled.code();
        int[] boundaries = compiled.offsets();
        int instructionCount = boundaries.length - 1;
        byte[][] instructions = new byte[instructionCount][];
        int[] canonical = new int[instructionCount];
        for (int pc = 0; pc < instructionCount; pc++) {
            int start = boundaries[pc];
            int length = boundaries[pc + 1] - start;
            if (length <= 0 || length > MAX_INSTRUCTION_BYTES) {
                throw new IllegalStateException("bad vm instruction length: " + length);
            }
            instructions[pc] = Arrays.copyOfRange(code, start, boundaries[pc + 1]);
            canonical[pc] = instructions[pc][0] & 0xff;
        }

        // --- polymorphic opcode map: every compilation gets a fresh random raw->canonical table
        int[] rawForCanonical = new int[256];
        Arrays.fill(rawForCanonical, -1);
        List<Integer> used = new ArrayList<>();
        for (int op : canonical) {
            if (rawForCanonical[op] < 0) {
                rawForCanonical[op] = 0;
                used.add(Integer.valueOf(op));
            }
        }
        List<Integer> rawPool = new ArrayList<>();
        for (int i = 1; i < 256; i++) rawPool.add(Integer.valueOf(i));
        SecureRandom random = new SecureRandom();
        for (int i = rawPool.size() - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            Integer tmp = rawPool.get(i);
            rawPool.set(i, rawPool.get(j));
            rawPool.set(j, tmp);
        }
        byte[] opcodeTable = new byte[256];
        for (int i = 0; i < used.size(); i++) {
            int op = used.get(i).intValue();
            int raw = rawPool.get(i).intValue();
            rawForCanonical[op] = raw;
            opcodeTable[raw] = (byte) op;
        }
        for (int pc = 0; pc < instructionCount; pc++) {
            instructions[pc][0] = (byte) rawForCanonical[canonical[pc]];
        }

        // --- control-flow predecessor map (entry predecessor is -1)
        List<List<Integer>> predecessors = new ArrayList<>();
        for (int i = 0; i < instructionCount; i++) predecessors.add(new ArrayList<>());
        predecessors.get(0).add(Integer.valueOf(-1));
        for (int pc = 0; pc < instructionCount; pc++) {
            int op = canonical[pc];
            if (op == VmOpcode.GOTO) {
                addPredecessor(predecessors, jumpTarget(instructions[pc]), pc, instructionCount);
            } else if (isConditionalJump(op)) {
                addPredecessor(predecessors, jumpTarget(instructions[pc]), pc, instructionCount);
                addPredecessor(predecessors, pc + 1, pc, instructionCount);
            } else if (!isReturnOpcode(op)) {
                addPredecessor(predecessors, pc + 1, pc, instructionCount);
            }
        }

        // --- edge-chained records: per-instruction ciphertext copies keyed by previous pc
        byte[] nonce = Crypto.random(NONCE_LENGTH);
        byte[] itemKey = ctx.deriveItemKey("vm", id);
        byte[] encKey = Crypto.hkdf(itemKey, nonce,
                "chimera/vm/enc/v3".getBytes(StandardCharsets.UTF_8), 32);
        byte[] macKey = Crypto.hkdf(itemKey, nonce,
                "chimera/vm/mac/v3".getBytes(StandardCharsets.UTF_8), 32);
        Cipher edgeCipher = Cipher.getInstance("AES/ECB/NoPadding");
        edgeCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"));
        ByteArrayOutputStream recordBuffer = new ByteArrayOutputStream(instructionCount * 24);
        DataOutputStream records = new DataOutputStream(recordBuffer);
        int[] recordOffsets = new int[instructionCount + 1];
        for (int pc = 0; pc < instructionCount; pc++) {
            recordOffsets[pc] = recordBuffer.size();
            List<Integer> preds = predecessors.get(pc);
            if (preds.isEmpty()) {
                throw new IllegalStateException("vm instruction without predecessor: " + pc);
            }
            records.writeShort(preds.size());
            for (Integer predValue : preds) {
                int pred = predValue.intValue();
                byte[] plain = instructions[pc];
                byte[] encrypted = new byte[plain.length];
                edgeCrypt(edgeCipher, nonce, pred, pc, plain, encrypted);
                records.writeInt(pred);
                records.writeByte(encrypted.length);
                records.write(encrypted);
            }
        }
        recordOffsets[instructionCount] = recordBuffer.size();
        records.flush();
        byte[] recordBytes = recordBuffer.toByteArray();
        Arrays.fill(encKey, (byte) 0);

        // KI-28: wrap the per-blob item key with a ResourceKey-derived item key. The runtime
        // recovers it via native op9 (authorized) or directly derives it (legacy/dev path).
        byte[] wrapNonce = Crypto.random(NONCE_LENGTH);
        byte[] wrapKey = ctx.deriveItemKey(VM_WRAP_KIND, id);
        byte[] wrappedKey = Crypto.aesGcmEncrypt(wrapKey, wrapNonce, itemKey,
                (VM_WRAP_KIND + "/" + id).getBytes(StandardCharsets.UTF_8));

        byte[] descriptor = compiled.descriptor().getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream plainBuffer = new ByteArrayOutputStream(256 + recordBytes.length);
        DataOutputStream plain = new DataOutputStream(plainBuffer);
        plain.writeInt(PLAIN_MAGIC);
        plain.writeInt(PLAIN_FORMAT_VERSION);
        plain.writeInt(id);
        plain.writeInt(descriptor.length);
        plain.write(descriptor);
        plain.writeInt(instructionCount);
        plain.writeInt(compiled.maxStack());
        plain.writeInt(compiled.maxLocals());
        plain.writeInt(compiled.members().size());
        for (VmCompiler.Member member : compiled.members()) {
            byte[] owner = member.owner().getBytes(StandardCharsets.UTF_8);
            byte[] name = member.name().getBytes(StandardCharsets.UTF_8);
            byte[] desc = member.desc().getBytes(StandardCharsets.UTF_8);
            plain.writeByte(member.kind());
            plain.writeInt(owner.length);
            plain.write(owner);
            plain.writeInt(name.length);
            plain.write(name);
            plain.writeInt(desc.length);
            plain.write(desc);
        }
        plain.write(opcodeTable);
        int headerLength = plainBuffer.size();
        for (int offset : recordOffsets) {
            plain.writeInt(offset);
        }
        plain.flush();
        byte[] plaintext = plainBuffer.toByteArray();
        byte[] ciphertext = ctrEncrypt(encKeyDebug(ctx, nonce, id), nonce, plaintext);
        Arrays.fill(encKey, (byte) 0);

        ByteArrayOutputStream outerBuffer = new ByteArrayOutputStream(80 + ciphertext.length);
        DataOutputStream outer = new DataOutputStream(outerBuffer);
        outer.writeInt(RESOURCE_MAGIC);
        outer.writeInt(id);
        outer.writeInt(FORMAT_VERSION);
        outer.writeInt(nonce.length);
        outer.write(nonce);
        outer.writeInt(wrapNonce.length);
        outer.write(wrapNonce);
        outer.writeInt(wrappedKey.length);
        outer.write(wrappedKey);
        outer.writeInt(plaintext.length);
        outer.writeInt(headerLength);
        outer.writeInt(4 * (instructionCount + 1));
        outer.writeInt(recordBytes.length);
        outer.flush();
        byte[] outerBytes = outerBuffer.toByteArray();
        ByteArrayOutputStream macInput = new ByteArrayOutputStream(
                outerBytes.length + ciphertext.length + recordBytes.length);
        macInput.write(outerBytes, 0, outerBytes.length);
        macInput.write(ciphertext, 0, ciphertext.length);
        macInput.write(recordBytes, 0, recordBytes.length);
        byte[] mac = Crypto.hmacSha256(macKey, macInput.toByteArray());
        Arrays.fill(macKey, (byte) 0);

        ByteArrayOutputStream resourceBuffer = new ByteArrayOutputStream(
                outerBytes.length + ciphertext.length + recordBytes.length + mac.length);
        resourceBuffer.write(outerBytes, 0, outerBytes.length);
        resourceBuffer.write(ciphertext, 0, ciphertext.length);
        resourceBuffer.write(recordBytes, 0, recordBytes.length);
        resourceBuffer.write(mac, 0, mac.length);
        Arrays.fill(plaintext, (byte) 0);
        return resourceBuffer.toByteArray();
    }

    private static void addPredecessor(List<List<Integer>> predecessors, int target, int from, int count) {
        // target 0 is valid (loops back to the method entry block); the entry edge -1 is added
        // separately, so this never conflicts with it.
        if (target >= 0 && target < count) {
            predecessors.get(target).add(Integer.valueOf(from));
        }
    }

    private static int jumpTarget(byte[] instruction) {
        if (instruction.length < 3) return -1;
        return ((instruction[1] & 0xff) << 8) | (instruction[2] & 0xff);
    }

    private static boolean isReturnOpcode(int op) {
        return op == VmOpcode.RET;
    }

    private static boolean isConditionalJump(int op) {
        return (op >= VmOpcode.IFEQ && op <= VmOpcode.IFLE)
                || (op >= VmOpcode.IF_ICMPEQ && op <= VmOpcode.IF_ICMPLE);
    }

    /** Per-edge keystream: block index depends on (previous pc, current pc), not a global stream. */
    private static void edgeCrypt(Cipher cipher, byte[] nonce, int previousPc, int pc,
                                  byte[] input, byte[] out) throws Exception {
        int block = edgeBlock(previousPc, pc);
        byte[] counter = new byte[16];
        byte[] keystream = new byte[16];
        int cached = -1;
        for (int i = 0; i < input.length; i++) {
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
            out[i] = (byte) (input[i] ^ keystream[offset]);
        }
    }

    private static int edgeBlock(int previousPc, int pc) {
        int mixed = previousPc * 0x9E3779B1 ^ pc * 0x85EBCA77;
        mixed ^= mixed >>> 16;
        return mixed & 0x7fffffff;
    }

    private static byte[] encKeyDebug(TransformContext ctx, byte[] nonce, int id) throws Exception {
        byte[] itemKey = ctx.deriveItemKey("vm", id);
        return Crypto.hkdf(itemKey, nonce,
                "chimera/vm/enc/v3".getBytes(StandardCharsets.UTF_8), 32);
    }

    /**
     * AES-256 CTR-style keystream: counter block = nonce(12) || big-endian 32-bit block index,
     * starting at 0. The same construction is used by the streaming runtime decoder.
     */
    private static byte[] ctrEncrypt(byte[] key, byte[] nonce, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] out = new byte[plaintext.length];
        byte[] counter = new byte[16];
        byte[] keystream = new byte[16];
        for (int position = 0; position < plaintext.length; position++) {
            int offset = position & 15;
            if (offset == 0) {
                int blockIndex = position >>> 4;
                System.arraycopy(nonce, 0, counter, 0, 12);
                counter[12] = (byte) (blockIndex >>> 24);
                counter[13] = (byte) (blockIndex >>> 16);
                counter[14] = (byte) (blockIndex >>> 8);
                counter[15] = (byte) blockIndex;
                if (cipher.update(counter, 0, 16, keystream, 0) != 16) {
                    throw new IllegalStateException("vm keystream failure");
                }
            }
            out[position] = (byte) (plaintext[position] ^ keystream[offset]);
        }
        return out;
    }

    // ------------------------------------------------------------------ method rewriting

    /**
     * Rewrites a supported method as:
     * <pre>
     *   Object result = ChimeraVmRuntime.execute(id, new Object[]{boxed args});
     *   if (ChimeraVmRuntime.isPoisoned()) return -1 / -1L / NaN; // type-correct poison
     *   return ((Number) result).intValue() / longValue() / doubleValue();
     * </pre>
     * The poison branch is necessary because {@code execute(id,args)} does not carry the method
     * descriptor: when the key is missing the blob cannot be decrypted, so the call site itself
     * must supply the type-correct degraded value.
     */
    private static void rewriteMethod(MethodNode method, int id, String descriptor) {
        Type[] arguments = Type.getArgumentTypes(descriptor);
        Type returnType = Type.getReturnType(descriptor);

        InsnList code = new InsnList();
        code.add(new LdcInsnNode(Integer.valueOf(id)));
        pushInt(code, arguments.length);
        code.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        int slot = 0; // static method: first parameter starts at slot 0
        for (int i = 0; i < arguments.length; i++) {
            Type argument = arguments[i];
            code.add(new InsnNode(Opcodes.DUP));
            pushInt(code, i);
            code.add(loadArgument(argument, slot));
            if (argument.getSort() == Type.OBJECT) {
                // objects are passed through as-is; primitives are boxed
                code.add(new InsnNode(Opcodes.NOP));
            } else {
                code.add(box(argument));
            }
            code.add(new InsnNode(Opcodes.AASTORE));
            slot += argument.getSize();
        }
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, EXECUTE_NAME, EXECUTE_DESC, false));
        code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, IS_POISONED_NAME, IS_POISONED_DESC, false));
        LabelNode healthy = new LabelNode();
        code.add(new JumpInsnNode(Opcodes.IFEQ, healthy));

        // Degraded path: discard the type-neutral value and return the method's own poison.
        code.add(new InsnNode(Opcodes.POP));
        // A4: do not return fixed -1/-1L/NaN. A constant is an enumerable "poison" signature;
        // the values below are derived from the poisoned session key and change per call
        // (interim until B1's SessionHandle + nativeCompute handle-poison mode).
        switch (returnType.getSort()) {
            case Type.INT:
                code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                        "vmPoisonInt", "()I", false));
                code.add(new InsnNode(Opcodes.IRETURN));
                break;
            case Type.LONG:
                code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                        "vmPoisonLong", "()J", false));
                code.add(new InsnNode(Opcodes.LRETURN));
                break;
            case Type.DOUBLE:
                code.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                        "vmPoisonDouble", "()D", false));
                code.add(new InsnNode(Opcodes.DRETURN));
                break;
            case Type.OBJECT:
                // Reference types have no generic sentinel; null + poisoned session.
                code.add(new InsnNode(Opcodes.ACONST_NULL));
                code.add(new InsnNode(Opcodes.ARETURN));
                break;
            default:
                throw new IllegalArgumentException("unsupported VM return type: " + returnType);
        }

        // Healthy path: unbox the interpreter result (objects are cast to their declared type).
        code.add(healthy);
        if (returnType.getSort() == Type.OBJECT) {
            code.add(new TypeInsnNode(Opcodes.CHECKCAST, returnType.getInternalName()));
            code.add(new InsnNode(Opcodes.ARETURN));
            method.instructions = code;
            method.tryCatchBlocks = new ArrayList<>();
            if (method.localVariables != null) {
                method.localVariables.clear();
            }
            method.maxStack = 0;
            method.maxLocals = 0;
            return;
        }
        code.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Number"));
        switch (returnType.getSort()) {
            case Type.INT:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "intValue", "()I", false));
                code.add(new InsnNode(Opcodes.IRETURN));
                break;
            case Type.LONG:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "longValue", "()J", false));
                code.add(new InsnNode(Opcodes.LRETURN));
                break;
            case Type.DOUBLE:
                code.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/Number", "doubleValue", "()D", false));
                code.add(new InsnNode(Opcodes.DRETURN));
                break;
            default:
                throw new IllegalArgumentException("unsupported VM return type: " + returnType);
        }

        method.instructions = code;
        method.tryCatchBlocks = new ArrayList<>();
        if (method.localVariables != null) {
            method.localVariables.clear();
        }
        if (method.visibleLocalVariableAnnotations != null) {
            method.visibleLocalVariableAnnotations.clear();
        }
        if (method.invisibleLocalVariableAnnotations != null) {
            method.invisibleLocalVariableAnnotations.clear();
        }
        method.maxStack = 0;
        method.maxLocals = 0;
    }

    private static void pushInt(InsnList code, int value) {
        if (value >= -1 && value <= 5) {
            code.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            code.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            code.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            code.add(new LdcInsnNode(Integer.valueOf(value)));
        }
    }

    private static AbstractInsnNode loadArgument(Type argument, int slot) {
        switch (argument.getSort()) {
            case Type.INT:
                return new VarInsnNode(Opcodes.ILOAD, slot);
            case Type.LONG:
                return new VarInsnNode(Opcodes.LLOAD, slot);
            case Type.DOUBLE:
                return new VarInsnNode(Opcodes.DLOAD, slot);
            case Type.OBJECT:
                return new VarInsnNode(Opcodes.ALOAD, slot);
            default:
                throw new IllegalArgumentException("unsupported VM argument type: " + argument);
        }
    }

    private static AbstractInsnNode box(Type argument) {
        return switch (argument.getSort()) {
            case Type.INT -> new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Integer",
                    "valueOf", "(I)Ljava/lang/Integer;", false);
            case Type.LONG -> new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Long",
                    "valueOf", "(J)Ljava/lang/Long;", false);
            case Type.DOUBLE -> new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double",
                    "valueOf", "(D)Ljava/lang/Double;", false);
            default -> throw new IllegalArgumentException("unsupported VM argument type: " + argument);
        };
    }

    // ------------------------------------------------------------------ annotation cleanup

    private static void removeVmAnnotation(MethodNode method) {
        removeAnnotation(method.invisibleAnnotations);
        removeAnnotation(method.visibleAnnotations);
    }

    private static void removeAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) {
            return;
        }
        Iterator<AnnotationNode> iterator = annotations.iterator();
        while (iterator.hasNext()) {
            if (ANNOTATION_DESC.equals(iterator.next().desc)) {
                iterator.remove();
            }
        }
    }
}
