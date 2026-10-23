package dev.chimera.transform.cfg;

/** S6 control-flow statistics. The Lead maps these to {@code dev.chimera.core.Stats} fields. */
public final class CfgStats {

    public int classesVisited;
    public int classesSkippedMixin;
    public int classesSkippedInterface;
    public int methodsVisited;
    public int methodsFlattened;
    public int methodsPredicated;
    public int constantChains;
    public int opaqueBranches;
    public int skippedConstructor;
    public int skippedClassInit;
    public int skippedTryCatch;
    public int skippedUnsupported;
    public int skippedAnnotated;
    public int skippedTooLarge;
    public int skippedSmall;

    public void add(CfgStats other) {
        if (other == null) return;
        classesVisited += other.classesVisited;
        classesSkippedMixin += other.classesSkippedMixin;
        classesSkippedInterface += other.classesSkippedInterface;
        methodsVisited += other.methodsVisited;
        methodsFlattened += other.methodsFlattened;
        methodsPredicated += other.methodsPredicated;
        constantChains += other.constantChains;
        opaqueBranches += other.opaqueBranches;
        skippedConstructor += other.skippedConstructor;
        skippedClassInit += other.skippedClassInit;
        skippedTryCatch += other.skippedTryCatch;
        skippedUnsupported += other.skippedUnsupported;
        skippedAnnotated += other.skippedAnnotated;
        skippedTooLarge += other.skippedTooLarge;
        skippedSmall += other.skippedSmall;
    }

    @Override
    public String toString() {
        return "cfgClasses=" + classesVisited
                + ", mixinSkipped=" + classesSkippedMixin
                + ", ifaceSkipped=" + classesSkippedInterface
                + ", cfgMethods=" + methodsFlattened
                + ", predicated=" + methodsPredicated
                + ", chains=" + constantChains
                + ", opaqueBranches=" + opaqueBranches
                + ", skipCtor=" + skippedConstructor
                + ", skipClinit=" + skippedClassInit
                + ", skipTryCatch=" + skippedTryCatch
                + ", skipUnsupported=" + skippedUnsupported
                + ", skipAnnotated=" + skippedAnnotated
                + ", skipLarge=" + skippedTooLarge
                + ", skipSmall=" + skippedSmall;
    }
}
