package dev.chimera.transform.mixinsupport;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.List;

/**
 * Rewrites only the class names in {@code @Mixin(targets = ..., value = ...)}.
 *
 * <p>Every other part of the class file is passed straight through to an ASM
 * {@code ClassWriter(reader, 0)}. Unchanged methods are copied by ASM from the original constant
 * pool, so {@code Signature}, {@code SourceFile}, {@code LineNumberTable},
 * {@code LocalVariableTable} and stack map frames stay intact. Classes whose targets are not
 * renamed are not re-serialized at all by {@link MixinSupport}, which keeps their bytes identical
 * (mixin classes are otherwise frozen by the pipeline).</p>
 */
final class MixinAnnotationRewriter extends ClassVisitor {

    static final String MIXIN_DESCRIPTOR = "Lorg/spongepowered/asm/mixin/Mixin;";

    private static final String TARGETS = "targets";
    private static final String VALUE = "value";

    private final Mappings mappings;
    private final int[] mapped;

    MixinAnnotationRewriter(ClassVisitor delegate, Mappings mappings, int[] mapped) {
        super(Opcodes.ASM9, delegate);
        this.mappings = mappings;
        this.mapped = mapped;
    }

    /**
     * Cheap annotation-only scan: true when at least one {@code @Mixin} target would be renamed.
     * Debug information and code are skipped, so the scan is cheap.
     */
    static boolean hasMappableTarget(byte[] classBytes, Mappings mappings) {
        int[] mapped = {0};
        new ClassReader(classBytes).accept(new MixinAnnotationRewriter(null, mappings, mapped),
                ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return mapped[0] > 0;
    }

    /**
     * Collects the classes this class mixes into ({@code @Mixin(value = ..., targets = ...)}) as
     * internal names, normalising both the {@code Type} and the {@code String} annotation forms.
     */
    static void collectTargets(byte[] classBytes, java.util.Set<String> out) {
        new ClassReader(classBytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                if (!MIXIN_DESCRIPTOR.equals(descriptor)) {
                    return null;
                }
                return new AnnotationVisitor(Opcodes.ASM9) {
                    @Override
                    public void visit(String name, Object value) {
                        if (isTarget(name)) {
                            add(value, out);
                        }
                    }

                    @Override
                    public AnnotationVisitor visitArray(String name) {
                        if (!isTarget(name)) {
                            return null;
                        }
                        return new AnnotationVisitor(Opcodes.ASM9) {
                            @Override
                            public void visit(String ignored, Object value) {
                                add(value, out);
                            }

                            @Override
                            public AnnotationVisitor visitArray(String ignored) {
                                return this;
                            }
                        };
                    }
                };
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }

    private static void add(Object value, java.util.Set<String> out) {
        if (value instanceof Type type && type.getSort() == Type.OBJECT) {
            out.add(type.getInternalName());
        } else if (value instanceof String raw) {
            out.add(normalizeTarget(raw));
        } else if (value instanceof List<?> list) {
            for (Object item : list) {
                add(item, out);
            }
        }
    }

    /** {@code @Mixin(targets = ...)} accepts binary names, internal names and descriptors. */
    private static String normalizeTarget(String raw) {
        String name = raw.trim();
        if (name.length() > 2 && name.startsWith("L") && name.endsWith(";")) {
            name = name.substring(1, name.length() - 1);
        }
        return name.replace('.', '/');
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        AnnotationVisitor delegate = super.visitAnnotation(descriptor, visible);
        if (!MIXIN_DESCRIPTOR.equals(descriptor)) {
            return delegate;
        }
        return new MixinAdapter(delegate);
    }

    private static boolean isTarget(String name) {
        return TARGETS.equals(name) || VALUE.equals(name);
    }

    private final class MixinAdapter extends AnnotationVisitor {

        MixinAdapter(AnnotationVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visit(String name, Object value) {
            super.visit(name, isTarget(name) ? mapTargetValue(value) : value);
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            AnnotationVisitor delegate = super.visitArray(name);
            if (!isTarget(name)) {
                return delegate;
            }
            return new ArrayAdapter(delegate);
        }
    }

    private final class ArrayAdapter extends AnnotationVisitor {

        ArrayAdapter(AnnotationVisitor delegate) {
            super(Opcodes.ASM9, delegate);
        }

        @Override
        public void visit(String name, Object value) {
            super.visit(name, mapTargetValue(value));
        }

        @Override
        public AnnotationVisitor visitArray(String name) {
            return new ArrayAdapter(super.visitArray(name));
        }
    }

    private Object mapTargetValue(Object value) {
        if (value instanceof String name) {
            String mappedName = mappings.mapClass(name);
            if (!mappedName.equals(name)) {
                mapped[0]++;
                return mappedName;
            }
            return value;
        }
        if (value instanceof Type type) {
            if (type.getSort() == Type.OBJECT) {
                String internal = type.getInternalName();
                String mappedInternal = mappings.mapInternal(internal);
                if (!mappedInternal.equals(internal)) {
                    mapped[0]++;
                    return Type.getObjectType(mappedInternal);
                }
            } else if (type.getSort() == Type.ARRAY) {
                String descriptor = type.getDescriptor();
                String mappedDescriptor = mappings.mapDescriptor(descriptor);
                if (!mappedDescriptor.equals(descriptor)) {
                    mapped[0]++;
                    return Type.getType(mappedDescriptor);
                }
            }
            return value;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            boolean changed = false;
            for (Object item : list) {
                Object mappedItem = mapTargetValue(item);
                changed |= mappedItem != item;
                out.add(mappedItem);
            }
            return changed ? out : value;
        }
        return value;
    }
}
