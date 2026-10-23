package dev.chimera.core;

import org.objectweb.asm.tree.ClassNode;

/** A single bytecode transformation stage applied to one class at a time. */
public interface Transformer {
    void transform(String internalName, ClassNode node, TransformContext ctx) throws Exception;
}
