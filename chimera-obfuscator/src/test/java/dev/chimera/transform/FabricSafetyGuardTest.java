package dev.chimera.transform;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ChimeraEngine;
import dev.chimera.core.Stats;
import dev.chimera.crypto.Crypto;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * M4 P0: a native/VM method that references Minecraft/Fabric types must fail the build with an
 * actionable error (the body is compiled at build time and cannot be remapped by Fabric), while
 * pure-logic methods still pass. Also verifies the escape hatch {@code strictFabric=false}.
 */
class FabricSafetyGuardTest {

    private static final String NATIVE_DESC = "Ldev/chimera/annotations/ChimeraNative;";
    private static final String VM_DESC = "Ldev/chimera/annotations/ChimeraVM;";

    private static MethodNode method(String name, String desc, boolean vm) {
        MethodNode method = new MethodNode(Opcodes.ASM9,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
        method.visibleAnnotations = new ArrayList<>();
        method.visibleAnnotations.add(new AnnotationNode(vm ? VM_DESC : NATIVE_DESC));
        return method;
    }

    private static byte[] classBytes(String internalName, MethodNode method) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V17;
        node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
        node.name = internalName;
        node.superName = "java/lang/Object";
        node.methods.add(method);
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    /** @ChimeraNative double deal(net.minecraft...Entity) { return 0.0; } */
    private static byte[] badNativeClass() {
        MethodNode m = method("deal", "(Lnet/minecraft/world/entity/Entity;)D", false);
        m.instructions.add(new InsnNode(Opcodes.DCONST_0));
        m.instructions.add(new InsnNode(Opcodes.DRETURN));
        m.maxStack = 2;
        m.maxLocals = 1;
        return classBytes("bad/BadNative", m);
    }

    /** @ChimeraVM int deal(net.minecraft...Entity) { return 0; } */
    private static byte[] badVmClass() {
        MethodNode m = method("deal", "(Lnet/minecraft/world/entity/Entity;)I", true);
        m.instructions.add(new InsnNode(Opcodes.ICONST_0));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        m.maxStack = 1;
        m.maxLocals = 1;
        return classBytes("bad/BadVm", m);
    }

    /** @ChimeraNative double add(int,int) { return (double)(a+b); } */
    private static MethodNode cleanNativeMethod() {
        MethodNode m = method("add", "(II)D", false);
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        m.instructions.add(new InsnNode(Opcodes.IADD));
        m.instructions.add(new InsnNode(Opcodes.I2D));
        m.instructions.add(new InsnNode(Opcodes.DRETURN));
        m.maxStack = 2;
        m.maxLocals = 2;
        return m;
    }

    private static MethodNode cleanVmMethod() {
        MethodNode m = method("calc", "(I)I", true);
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new InsnNode(Opcodes.ICONST_1));
        m.instructions.add(new InsnNode(Opcodes.IADD));
        m.instructions.add(new InsnNode(Opcodes.IRETURN));
        m.maxStack = 2;
        m.maxLocals = 1;
        return m;
    }

    private static Path jarWith(Path dir, String name, byte[] classBytes) throws Exception {
        Files.createDirectories(dir);
        Path jar = dir.resolve(name + ".jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            zos.putNextEntry(new ZipEntry(name.replace('.', '/') + ".class"));
            zos.write(classBytes);
            zos.closeEntry();
        }
        return jar;
    }

    private static ChimeraConfig config(Path in, Path out, boolean strictFabric) {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.inputJar = in;
        cfg.outputJar = out;
        cfg.keyMaterial = Crypto.sha256("fabric-guard-test".getBytes(StandardCharsets.UTF_8));
        cfg.integrityManifest = false;
        cfg.strictFabric = strictFabric;
        return cfg;
    }

    @Test
    void guardAcceptsPureLogicAndRejectsMinecraftReferences() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/Math";

        MethodNode clean = cleanNativeMethod();
        assertNull(FabricSafetyGuard.inspect(clean));
        assertNull(FabricSafetyGuard.check(owner, clean, "@ChimeraNative"));

        MethodNode bad = cleanNativeMethod();
        bad.desc = "(Lnet/minecraft/world/entity/Entity;)D";
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, bad, "@ChimeraNative"));
        assertTrue(error.getMessage().contains("Fabric production remap check failed"), error.getMessage());
        assertTrue(error.getMessage().contains("net.minecraft"), error.getMessage());
        assertTrue(error.getMessage().contains("ChimeraNative"), error.getMessage());
    }

    @Test
    void mixinClassIsRejected() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/MixinBridge";
        owner.visibleAnnotations = new ArrayList<>();
        owner.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;"));
        MethodNode clean = cleanNativeMethod();
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, clean, "@ChimeraNative"));
        assertTrue(error.getMessage().contains("Mixin"), error.getMessage());
    }

    @Test
    void mixinCallbackMethodIsRejected() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/Callback";
        MethodNode method = cleanNativeMethod();
        method.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/injection/Inject;"));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, method, "@ChimeraNative"));
        assertTrue(error.getMessage().contains("Mixin"), error.getMessage());
    }

    @Test
    void classInRemappedNamespaceIsRejected() {
        ClassNode owner = new ClassNode();
        owner.name = "net/minecraft/world/ProtectedLogic";
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, cleanNativeMethod(), "@ChimeraNative"));
        assertTrue(error.getMessage().contains("net.minecraft"), error.getMessage());
    }

    @Test
    void superclassInRemappedNamespaceIsRejected() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/Subclass";
        owner.superName = "net/minecraft/world/entity/Entity";
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, cleanNativeMethod(), "@ChimeraNative"));
        assertTrue(error.getMessage().contains("superclass"), error.getMessage());
    }

    @Test
    void methodHandleAndCondyAndSlashStringsAreDetected() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/Handles";
        MethodNode handle = cleanNativeMethod();
        handle.instructions.add(new org.objectweb.asm.tree.LdcInsnNode(new org.objectweb.asm.Handle(
                org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                "net/minecraft/client/MinecraftClient", "getInstance",
                "()Lnet/minecraft/client/MinecraftClient;", false)));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, handle, "@ChimeraNative"))
                .getMessage().contains("method handle"), "handle owner must be flagged");

        MethodNode slashed = cleanNativeMethod();
        slashed.instructions.add(new org.objectweb.asm.tree.LdcInsnNode("net/minecraft/world/Entity"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, slashed, "@ChimeraNative"))
                .getMessage().contains("net/minecraft"), "slash-form strings must be flagged");

        MethodNode tryCatch = cleanNativeMethod();
        tryCatch.tryCatchBlocks.add(new org.objectweb.asm.tree.TryCatchBlockNode(
                new org.objectweb.asm.tree.LabelNode(), new org.objectweb.asm.tree.LabelNode(),
                new org.objectweb.asm.tree.LabelNode(), "net/minecraft/world/entity/Entity"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, tryCatch, "@ChimeraNative"))
                .getMessage().contains("try/catch"), "try/catch types must be flagged");
    }

    @Test
    void guardDetectsMethodBodyReferencesNotOnlyDescriptors() {
        ClassNode owner = new ClassNode();
        owner.name = "demo/McBridge";
        MethodNode m = method("deal", "(I)D", false);
        m.instructions.add(new VarInsnNode(Opcodes.ILOAD, 0));
        m.instructions.add(new InsnNode(Opcodes.I2D));
        m.instructions.add(new InsnNode(Opcodes.DRETURN));
        m.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                "net/minecraft/client/MinecraftClient", "getInstance",
                "()Lnet/minecraft/client/MinecraftClient;", false));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> FabricSafetyGuard.check(owner, m, "@ChimeraNative"));
        assertTrue(error.getMessage().contains("net.minecraft"), error.getMessage());
    }

    @Test
    void engineFailsBuildForNativeMethodReferencingMinecraft() throws Exception {
        Path work = Files.createTempDirectory("chimera-fabric-native");
        Path in = jarWith(work.resolve("in"), "bad.BadNative", badNativeClass());
        Path out = work.resolve("out.jar");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, out, true)).run());
        assertTrue(error.getMessage().contains("net.minecraft"), error.getMessage());
    }

    @Test
    void engineFailsBuildForVmMethodReferencingMinecraft() throws Exception {
        Path work = Files.createTempDirectory("chimera-fabric-vm");
        Path in = jarWith(work.resolve("in"), "bad.BadVm", badVmClass());
        Path out = work.resolve("out.jar");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> new ChimeraEngine(config(in, out, true)).run());
        assertTrue(error.getMessage().contains("net.minecraft"), error.getMessage());
    }

    @Test
    void escapeHatchAllowsNonProductionBuilds() throws Exception {
        Path work = Files.createTempDirectory("chimera-fabric-nostrict");
        Path in = jarWith(work.resolve("in"), "bad.BadNative", badNativeClass());
        Path out = work.resolve("out.jar");
        Stats stats = new ChimeraEngine(config(in, out, false)).run();
        assertTrue(stats.classesWritten > 0);
        assertTrue(Files.isRegularFile(out));
    }

    @Test
    void cleanProjectStillBuildsAndTransforms() throws Exception {
        Path work = Files.createTempDirectory("chimera-fabric-clean");
        Path dir = work.resolve("in");
        Files.createDirectories(dir);
        Path in = dir.resolve("clean.jar");
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(in))) {
            zos.putNextEntry(new ZipEntry("clean/Math.class"));
            ClassNode node = new ClassNode();
            node.version = Opcodes.V17;
            node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER;
            node.name = "clean/Math";
            node.superName = "java/lang/Object";
            node.methods.add(cleanNativeMethod());
            node.methods.add(cleanVmMethod());
            ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            node.accept(writer);
            zos.write(writer.toByteArray());
            zos.closeEntry();
        }
        Path out = work.resolve("out.jar");
        Stats stats = new ChimeraEngine(config(in, out, true)).run();
        assertTrue(stats.methodsNativeStubbed >= 1, "clean native method should be stubbed");
        assertTrue(stats.vmMethods >= 1, "clean VM method should be virtualized");
    }
}
