package dev.chimera.core;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Change detection for the engine: fingerprints a {@link ClassNode} without serialising it.
 *
 * <p>Serialising a ClassNode with a throw-away ClassWriter resolves its ASM labels; reusing the
 * same node with a second writer afterwards produced corrupted bytecode (observed as an invalid
 * constant-pool index in generated hidden-class fragments), so the no-op detection must never
 * write class bytes. This visitor only hashes the visited events.</p>
 */
public final class ClassFingerprint {

    private ClassFingerprint() {
    }

    /** @return SHA-256 over every structural event of the node (labels included by identity) */
    public static byte[] digest(ClassNode node) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        node.accept(new HashingVisitor(md));
        return md.digest();
    }

    /**
     * M10 fix: SHA-256 over the control-flow SHAPE only - labels, branch opcodes, switch
     * structure and try-catch ranges. Shape-preserving edits (naming sync, debug strip, indy
     * call-site rewrite - an invokedynamic has the same operand-stack effect as the call it
     * replaces and adds no branches -, harden constant-pool poisoning) leave this digest
     * unchanged, so a class whose shape survived the transformer loop can keep its original
     * StackMapTable: recomputing frames would require the full external hierarchy in the
     * ClassPool and degrade handler-entry merges to {@code java/lang/Object} when a dependency
     * (e.g. gson) is missing (WurstTranslator VerifyError, "Bad type on operand stack").
     */
    public static byte[] shapeDigest(ClassNode node) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        for (org.objectweb.asm.tree.MethodNode method : node.methods) {
            java.util.IdentityHashMap<Object, Integer> labelIds = new java.util.IdentityHashMap<>();
            int[] labelSeq = {0};
            boolean contributes = false;
            if (method.instructions != null) {
                for (org.objectweb.asm.tree.AbstractInsnNode insn : method.instructions) {
                    int type = insn.getType();
                    if (type == org.objectweb.asm.tree.AbstractInsnNode.LABEL) {
                        update(md, 'L');
                        update(md, labelIds.computeIfAbsent(insn, k -> labelSeq[0]++));
                        contributes = true;
                    } else if (type == org.objectweb.asm.tree.AbstractInsnNode.JUMP_INSN) {
                        org.objectweb.asm.tree.JumpInsnNode jump =
                                (org.objectweb.asm.tree.JumpInsnNode) insn;
                        update(md, 'J');
                        update(md, jump.getOpcode());
                        update(md, labelIds.computeIfAbsent(jump.label, k -> labelSeq[0]++));
                        contributes = true;
                    } else if (insn instanceof org.objectweb.asm.tree.TableSwitchInsnNode table) {
                        update(md, 'T');
                        update(md, table.min);
                        update(md, table.max);
                        update(md, labelIds.computeIfAbsent(table.dflt, k -> labelSeq[0]++));
                        for (Object l : table.labels) {
                            update(md, labelIds.computeIfAbsent(l, k -> labelSeq[0]++));
                        }
                        contributes = true;
                    } else if (insn instanceof org.objectweb.asm.tree.LookupSwitchInsnNode lookup) {
                        update(md, 'K');
                        update(md, labelIds.computeIfAbsent(lookup.dflt, k -> labelSeq[0]++));
                        update(md, lookup.keys == null ? 0 : lookup.keys.size());
                        if (lookup.keys != null) {
                            for (int key : lookup.keys) {
                                update(md, key);
                            }
                        }
                        if (lookup.labels != null) {
                            for (Object l : lookup.labels) {
                                update(md, labelIds.computeIfAbsent(l, k -> labelSeq[0]++));
                            }
                        }
                        contributes = true;
                    }
                }
            }
            if (method.tryCatchBlocks != null && !method.tryCatchBlocks.isEmpty()) {
                update(md, 'X');
                update(md, method.tryCatchBlocks.size());
                for (org.objectweb.asm.tree.TryCatchBlockNode block : method.tryCatchBlocks) {
                    update(md, labelIds.computeIfAbsent(block.start, k -> labelSeq[0]++));
                    update(md, labelIds.computeIfAbsent(block.end, k -> labelSeq[0]++));
                    update(md, labelIds.computeIfAbsent(block.handler, k -> labelSeq[0]++));
                    update(md, block.type);
                }
                contributes = true;
            }
            if (contributes) {
                // Only methods with actual control flow take part; branch-less additions (harden
                // dummy methods, decoys) contribute nothing and must not force recomputation.
                update(md, 'M');
                update(md, method.name);
                update(md, method.desc);
            }
        }
        return md.digest();
    }

    private static void update(MessageDigest md, int value) {
        md.update((byte) (value >>> 24));
        md.update((byte) (value >>> 16));
        md.update((byte) (value >>> 8));
        md.update((byte) value);
    }

    private static void update(MessageDigest md, String value) {
        if (value == null) {
            md.update((byte) 0);
            return;
        }
        md.update((byte) 1);
        md.update(value.getBytes(StandardCharsets.UTF_8));
        md.update((byte) 0);
    }

    private static final class HashingVisitor extends ClassVisitor {
        private final MessageDigest md;

        HashingVisitor(MessageDigest md) {
            super(Opcodes.ASM9);
            this.md = md;
        }

        private void s(String value) {
            if (value == null) {
                md.update((byte) 0);
                return;
            }
            md.update((byte) 1);
            md.update(value.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
        }

        private void i(int value) {
            md.update((byte) (value >>> 24));
            md.update((byte) (value >>> 16));
            md.update((byte) (value >>> 8));
            md.update((byte) value);
        }

        private void label(Label label) {
            i(label == null ? 0 : System.identityHashCode(label));
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            i(1);
            i(version);
            i(access);
            s(name);
            s(signature);
            s(superName);
            i(interfaces == null ? 0 : interfaces.length);
            if (interfaces != null) {
                for (String itf : interfaces) {
                    s(itf);
                }
            }
        }

        @Override
        public void visitSource(String source, String debug) {
            i(2);
            s(source);
            s(debug);
        }

        @Override
        public org.objectweb.asm.FieldVisitor visitField(int access, String name, String descriptor,
                                                         String signature, Object value) {
            i(3);
            i(access);
            s(name);
            s(descriptor);
            s(signature);
            s(value == null ? null : String.valueOf(value));
            return null;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            i(4);
            i(access);
            s(name);
            s(descriptor);
            s(signature);
            i(exceptions == null ? 0 : exceptions.length);
            if (exceptions != null) {
                for (String ex : exceptions) {
                    s(ex);
                }
            }
            return new MethodVisitor(Opcodes.ASM9) {
                @Override
                public void visitInsn(int opcode) {
                    i(10);
                    i(opcode);
                }

                @Override
                public void visitIntInsn(int opcode, int operand) {
                    i(11);
                    i(opcode);
                    i(operand);
                }

                @Override
                public void visitVarInsn(int opcode, int varIndex) {
                    i(12);
                    i(opcode);
                    i(varIndex);
                }

                @Override
                public void visitTypeInsn(int opcode, String type) {
                    i(13);
                    i(opcode);
                    s(type);
                }

                @Override
                public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                    i(14);
                    i(opcode);
                    s(owner);
                    s(name);
                    s(descriptor);
                }

                @Override
                public void visitMethodInsn(int opcode, String owner, String name, String descriptor,
                                            boolean isInterface) {
                    i(15);
                    i(opcode);
                    s(owner);
                    s(name);
                    s(descriptor);
                    i(isInterface ? 1 : 0);
                }

                @Override
                public void visitInvokeDynamicInsn(String name, String descriptor,
                                                   org.objectweb.asm.Handle bsm, Object... bsmArgs) {
                    i(16);
                    s(name);
                    s(descriptor);
                    s(bsm == null ? null : bsm.toString());
                    i(bsmArgs == null ? 0 : bsmArgs.length);
                    if (bsmArgs != null) {
                        for (Object arg : bsmArgs) {
                            s(String.valueOf(arg));
                        }
                    }
                }

                @Override
                public void visitJumpInsn(int opcode, Label label) {
                    i(17);
                    i(opcode);
                    label(label);
                }

                @Override
                public void visitLabel(Label label) {
                    i(18);
                    label(label);
                }

                @Override
                public void visitLdcInsn(Object value) {
                    i(19);
                    s(value == null ? null : value.getClass().getName());
                    s(String.valueOf(value));
                }

                @Override
                public void visitIincInsn(int varIndex, int increment) {
                    i(20);
                    i(varIndex);
                    i(increment);
                }

                @Override
                public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
                    i(21);
                    i(min);
                    i(max);
                    label(dflt);
                    i(labels == null ? 0 : labels.length);
                    if (labels != null) {
                        for (Label l : labels) {
                            label(l);
                        }
                    }
                }

                @Override
                public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
                    i(22);
                    label(dflt);
                    i(keys == null ? 0 : keys.length);
                    if (keys != null) {
                        for (int key : keys) {
                            i(key);
                        }
                    }
                    if (labels != null) {
                        for (Label l : labels) {
                            label(l);
                        }
                    }
                }

                @Override
                public void visitMultiANewArrayInsn(String descriptor, int numDimensions) {
                    i(23);
                    s(descriptor);
                    i(numDimensions);
                }

                @Override
                public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
                    i(24);
                    label(start);
                    label(end);
                    label(handler);
                    s(type);
                }

                @Override
                public void visitMaxs(int maxStack, int maxLocals) {
                    i(25);
                    i(maxStack);
                    i(maxLocals);
                }

                @Override
                public void visitEnd() {
                    i(26);
                }
            };
        }

        @Override
        public void visitEnd() {
            i(99);
        }
    }
}
