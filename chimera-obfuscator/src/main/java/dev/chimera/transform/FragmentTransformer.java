package dev.chimera.transform;

import dev.chimera.core.ChimeraClassWriter;
import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import dev.chimera.crypto.Crypto;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.MethodTooLargeException;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Extracts the body of every effective {@code @ChimeraProtected} method into an encrypted
 * hidden-class fragment and replaces the original body with an {@code invokedynamic} call
 * whose bootstrap method is {@code ChimeraRuntime.bootstrapChunk}.
 *
 * <p>Fragment layout: the original bytecode is moved verbatim (minus stack-map frames and line
 * numbers) into a synthetic class {@code <owner>$chimera$<id>} that declares one
 * {@code public static} method {@code run}. For instance methods the receiver becomes the first
 * parameter, so the local-variable slots of the moved bytecode stay identical to the original
 * method.</p>
 */
public final class FragmentTransformer implements Transformer {

    private static final String RUNTIME = "dev/chimera/runtime/ChimeraRuntime";

    /** Descriptor of {@code dev.chimera.annotations.ChimeraProtected}. */
    private static final String PROTECTED_DESC = "Ldev/chimera/annotations/ChimeraProtected;";

    private static final String RUNTIME_CLASS = "dev/chimera/runtime/ChimeraRuntime";
    private static final String BOOTSTRAP_NAME = "bootstrapChunk";
    private static final String BOOTSTRAP_DESC = "(Ljava/lang/invoke/MethodHandles$Lookup;"
            + "Ljava/lang/String;Ljava/lang/invoke/MethodType;ILjava/lang/String;Ljava/lang/String;)"
            + "Ljava/lang/invoke/CallSite;";
    private static final Handle BOOTSTRAP = new Handle(Opcodes.H_INVOKESTATIC, RUNTIME_CLASS,
            BOOTSTRAP_NAME, BOOTSTRAP_DESC, false);

    /** "CHK1" - first field of the encrypted chunk format consumed by ChimeraRuntime. */
    private static final int CHUNK_MAGIC = 0x43484B31;
    private static final int NONCE_LENGTH = 12;
    private static final String CHUNK_DIR = "chimera/chunks/chunk_";
    private static final String CHUNK_SUFFIX = ".bin";
    private static final String CHUNK_HASH_SUFFIX = ".hash";
    /** "CHB1" - magic inside the sealed plaintext record. */
    private static final int CHUNK_HASH_MAGIC = 0x43484231;
    /** "CHB2" - outer sealed record magic (KI-28 ResourceKey path). */
    private static final int CHUNK_HASH_SEALED_MAGIC = 0x43484232;
    private static final int CHUNK_HASH_LENGTH = 32;

    @Override
    public void transform(String internalName, ClassNode node, TransformContext ctx) throws Exception {
        if (!ctx.config.fragmentMethods) return;
        if (node.methods == null || node.methods.isEmpty()) return;

        // Copy: fragment() mutates the method list entries but never the list itself.
        List<MethodNode> methods = new ArrayList<>(node.methods);
        for (MethodNode method : methods) {
            if (!isCandidate(method)) continue;
            if (!isProtected(method)) continue;
            if (hasForeignSuperCall(method, internalName)) continue;
            fragment(internalName, node, method, ctx);
        }
    }

    private static boolean isCandidate(MethodNode method) {
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_SYNCHRONIZED)) != 0) {
            return false;
        }
        return !"<init>".equals(method.name) && !"<clinit>".equals(method.name);
    }

    private static boolean isProtected(MethodNode method) {
        return hasAnnotation(method.invisibleAnnotations)
                || hasAnnotation(method.visibleAnnotations);
    }

    private static boolean hasAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) return false;
        for (AnnotationNode annotation : annotations) {
            if (PROTECTED_DESC.equals(annotation.desc)) return true;
        }
        return false;
    }

    /**
     * A method that performs a super call ({@code invokespecial} to a method other than
     * {@code <init>} on a class other than the owner) cannot be moved into a hidden class that
     * extends {@code java/lang/Object}; such methods are left untouched.
     */
    private static boolean hasForeignSuperCall(MethodNode method, String internalName) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() == Opcodes.INVOKESPECIAL && insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (!internalName.equals(call.owner) && !"<init>".equals(call.name)) return true;
            }
        }
        return false;
    }

    private void fragment(String internalName, ClassNode owner, MethodNode method, TransformContext ctx)
            throws Exception {
        // The id must be reserved before the fragment name is built.
        int id = ctx.nextChunkId();
        String chunkResource = chunkResource(id);
        String callSiteDesc = callSiteDescriptor(internalName, method);
        String fragmentInternalName = internalName + "$chimera$" + id;

        ClassNode fragment = new ClassNode();
        fragment.version = owner.version;
        fragment.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
        fragment.name = fragmentInternalName;
        fragment.superName = "java/lang/Object";
        fragment.interfaces = new ArrayList<>();

        MethodNode run = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", callSiteDesc, null, null);
        // Reuse the instruction list of the original method; its local slots already match the
        // static "run" signature (receiver at slot 0 for instance methods).
        run.instructions = method.instructions;
        removeFramesAndLines(run.instructions);
        run.tryCatchBlocks = method.tryCatchBlocks;
        run.maxStack = method.maxStack;
        run.maxLocals = method.maxLocals;
        fragment.methods.add(run);

        injectHoneypot(run, ctx);

        ClassWriter writer = new ChimeraClassWriter(
                ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, ctx.pool);
        byte[] fragmentBytes;
        try {
            fragment.accept(writer);
            fragmentBytes = writer.toByteArray();
        } catch (MethodTooLargeException e) {
            throw new IllegalStateException("fragment " + fragmentInternalName
                    + " exceeds the 64KB method limit; exclude this method from @ChimeraProtected", e);
        }

        byte[] nonce = Crypto.random(NONCE_LENGTH);
        byte[] key = ctx.deriveItemKey("chunk", id);
        byte[] aad = ("chunk/" + id).getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = Crypto.aesGcmEncrypt(key, nonce, fragmentBytes, aad);
        ctx.sink.put(chunkResource, encodeChunk(id, nonce, ciphertext));
        // B6: publish an authenticated build-time hash of the plaintext fragment class so the
        // runtime can reject a Frida-hooked/replaced class byte[] before defineHiddenClass.
        ctx.sink.put(chunkHashResource(id), encodeChunkHash(id, fragmentBytes,
                ctx.deriveItemKey("chunk-hash", id)));
        ctx.stats.chunksWritten++;
        ctx.stats.methodsFragmented++;

        replaceBody(internalName, method, id, callSiteDesc, chunkResource);
    }

    /**
     * Task 4: inject an unreachable honeypot branch with sensitive-looking strings into small,
     * low-frequency fragments. The branch is guarded by {@code ChimeraRuntime.honeypot()} which
     * always returns false; it only exists to poison static/LLM analysis.
     */
    private static void injectHoneypot(MethodNode run, TransformContext ctx) {
        if (!ctx.config.honeypot) return;
        long estimatedBytes = (long) run.instructions.size() * 6L + 64L;
        if (estimatedBytes > ctx.config.honeypotMaxMethodBytes) return;
        if (run.instructions.size() > ctx.config.honeypotMaxInstructions) return;

        LabelNode dead = new LabelNode();
        InsnList prologue = new InsnList();
        prologue.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "honeypot", "()Z", false));
        prologue.add(new JumpInsnNode(Opcodes.IFNE, dead));
        run.instructions.insert(prologue);

        InsnList deadCode = new InsnList();
        deadCode.add(dead);
        for (String decoy : new String[]{"frida_bypass", "bypass_auth", "license_valid", "isAdmin"}) {
            deadCode.add(new LdcInsnNode(decoy));
            deadCode.add(new InsnNode(Opcodes.POP));
        }
        // If an attacker flips honeypot() to true, execution enters this normally unreachable
        // dead loop instead of the protected body (anti-patch honeypot).
        deadCode.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME, "honeypotTrap", "()V", false));
        appendDefaultReturn(deadCode, run.desc);
        run.instructions.add(deadCode);
        ctx.stats.honeypotInjected++;
    }

    private static void appendDefaultReturn(InsnList code, String descriptor) {
        Type returnType = Type.getReturnType(descriptor);
        switch (returnType.getSort()) {
            case Type.VOID -> code.add(new InsnNode(Opcodes.RETURN));
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> {
                code.add(new InsnNode(Opcodes.ICONST_0));
                code.add(new InsnNode(Opcodes.IRETURN));
            }
            case Type.LONG -> {
                code.add(new InsnNode(Opcodes.LCONST_0));
                code.add(new InsnNode(Opcodes.LRETURN));
            }
            case Type.FLOAT -> {
                code.add(new InsnNode(Opcodes.FCONST_0));
                code.add(new InsnNode(Opcodes.FRETURN));
            }
            case Type.DOUBLE -> {
                code.add(new InsnNode(Opcodes.DCONST_0));
                code.add(new InsnNode(Opcodes.DRETURN));
            }
            default -> {
                code.add(new InsnNode(Opcodes.ACONST_NULL));
                code.add(new InsnNode(Opcodes.ARETURN));
            }
        }
    }

    /** Rewrites the original method as: load receiver + arguments, invokedynamic, return. */
    private static void replaceBody(String internalName, MethodNode method, int id,
                                    String callSiteDesc, String chunkResource) {
        method.instructions = new InsnList();
        method.tryCatchBlocks = new ArrayList<>();
        if (method.localVariables != null) method.localVariables.clear();
        removeProtectedAnnotation(method);

        InsnList code = method.instructions;
        boolean isStatic = (method.access & Opcodes.ACC_STATIC) != 0;
        if (!isStatic) code.add(new VarInsnNode(Opcodes.ALOAD, 0));

        int slot = isStatic ? 0 : 1;
        for (Type argument : Type.getArgumentTypes(method.desc)) {
            code.add(loadInstruction(argument, slot));
            slot += argument.getSize();
        }

        // id / resource / owner are constant-pool bootstrap arguments; they never touch the
        // operand stack (a pushed int would desynchronise the call-site descriptor).
        code.add(new InvokeDynamicInsnNode(method.name, callSiteDesc, BOOTSTRAP,
                Integer.valueOf(id), chunkResource, internalName));
        code.add(returnInstruction(Type.getReturnType(method.desc)));

        method.maxStack = 0;
        method.maxLocals = 0;
    }

    /** Descriptor of the generated {@code run} method; identical to the invokedynamic call-site type. */
    private static String callSiteDescriptor(String internalName, MethodNode method) {
        Type[] arguments = Type.getArgumentTypes(method.desc);
        Type returnType = Type.getReturnType(method.desc);
        if ((method.access & Opcodes.ACC_STATIC) != 0) {
            return Type.getMethodDescriptor(returnType, arguments);
        }
        Type[] withReceiver = new Type[arguments.length + 1];
        withReceiver[0] = Type.getObjectType(internalName);
        System.arraycopy(arguments, 0, withReceiver, 1, arguments.length);
        return Type.getMethodDescriptor(returnType, withReceiver);
    }

    private static AbstractInsnNode loadInstruction(Type type, int slot) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                return new VarInsnNode(Opcodes.ILOAD, slot);
            case Type.LONG:
                return new VarInsnNode(Opcodes.LLOAD, slot);
            case Type.FLOAT:
                return new VarInsnNode(Opcodes.FLOAD, slot);
            case Type.DOUBLE:
                return new VarInsnNode(Opcodes.DLOAD, slot);
            case Type.ARRAY:
            case Type.OBJECT:
                return new VarInsnNode(Opcodes.ALOAD, slot);
            default:
                throw new IllegalArgumentException("unsupported argument type: " + type);
        }
    }

    private static AbstractInsnNode returnInstruction(Type type) {
        switch (type.getSort()) {
            case Type.VOID:
                return new InsnNode(Opcodes.RETURN);
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                return new InsnNode(Opcodes.IRETURN);
            case Type.LONG:
                return new InsnNode(Opcodes.LRETURN);
            case Type.FLOAT:
                return new InsnNode(Opcodes.FRETURN);
            case Type.DOUBLE:
                return new InsnNode(Opcodes.DRETURN);
            case Type.ARRAY:
            case Type.OBJECT:
                return new InsnNode(Opcodes.ARETURN);
            default:
                throw new IllegalArgumentException("unsupported return type: " + type);
        }
    }

    private static void removeFramesAndLines(InsnList instructions) {
        AbstractInsnNode insn = instructions.getFirst();
        while (insn != null) {
            AbstractInsnNode next = insn.getNext();
            if (insn instanceof FrameNode || insn instanceof LineNumberNode) {
                instructions.remove(insn);
            }
            insn = next;
        }
    }

    private static void removeProtectedAnnotation(MethodNode method) {
        removeAnnotation(method.invisibleAnnotations);
        removeAnnotation(method.visibleAnnotations);
    }

    private static void removeAnnotation(List<AnnotationNode> annotations) {
        if (annotations == null) return;
        Iterator<AnnotationNode> iterator = annotations.iterator();
        while (iterator.hasNext()) {
            if (PROTECTED_DESC.equals(iterator.next().desc)) iterator.remove();
        }
    }

    private static String chunkResource(int id) {
        return CHUNK_DIR + id + CHUNK_SUFFIX;
    }

    private static String chunkHashResource(int id) {
        return CHUNK_DIR + id + CHUNK_HASH_SUFFIX;
    }

    /**
     * B6 hash record (KI-28): {@code int magic("CHB2"), nonce[12],
     * AES-GCM(itemKey, plaintext={@code int "CHB1", int id, int hashLen(32), byte[32] sha256})[48]}.
     * The item key is {@code HKDF(kek, envSalt, "chimera/v1/chunk-hash/<id>")} with {@code kek}
     * derived from the product ResourceKey, so the runtime can authenticate the record through
     * native op9 DECRYPT_DATA without holding the key in Java.
     */
    private static byte[] encodeChunkHash(int id, byte[] fragmentBytes, byte[] itemKey) {
        byte[] hash = Crypto.sha256(fragmentBytes);
        ByteBuffer header = ByteBuffer.allocate(4 + 4 + 4 + CHUNK_HASH_LENGTH);
        header.putInt(CHUNK_HASH_MAGIC);
        header.putInt(id);
        header.putInt(CHUNK_HASH_LENGTH);
        header.put(hash);
        byte[] nonce = Crypto.random(NONCE_LENGTH);
        byte[] aad = ("chunk-hash/" + id).getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = Crypto.aesGcmEncrypt(itemKey, nonce, header.array(), aad);
        ByteBuffer record = ByteBuffer.allocate(4 + nonce.length + ciphertext.length);
        record.putInt(CHUNK_HASH_SEALED_MAGIC);
        record.put(nonce);
        record.put(ciphertext);
        return record.array();
    }

    /**
     * Big-endian chunk format: {@code int magic, int id, int nonceLen, nonce,
     * int ciphertextLen, ciphertext} - must stay in sync with ChimeraRuntime.
     */
    private static byte[] encodeChunk(int id, byte[] nonce, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 4 + nonce.length + 4 + ciphertext.length);
        buffer.putInt(CHUNK_MAGIC);
        buffer.putInt(id);
        buffer.putInt(nonce.length);
        buffer.put(nonce);
        buffer.putInt(ciphertext.length);
        buffer.put(ciphertext);
        return buffer.array();
    }
}
