package dev.chimera.core;

import org.objectweb.asm.ClassWriter;

/** ClassWriter that resolves common super classes via the input jar + JDK, never via the plugin classpath. */
public final class ChimeraClassWriter extends ClassWriter {
    private final ClassPool pool;

    public ChimeraClassWriter(int flags, ClassPool pool) {
        super(flags);
        this.pool = pool;
    }

    @Override
    protected String getCommonSuperClass(String type1, String type2) {
        return pool.commonSuperClass(type1, type2);
    }
}
