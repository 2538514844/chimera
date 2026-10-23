package dev.chimera.transform.cfg;

import dev.chimera.core.ChimeraClassWriter;
import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.core.Transformer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S6 executable tests: flattening / opaque predicates / constant chains keep method behaviour and
 * produce verifiable frames; Mixin classes and unsafe methods are skipped and counted.
 */
class CfgTransformTest {

    private static final String FIXTURE = "dev/chimera/transform/cfg/CfgFixture";
    private static final String FIXTURE_BINARY = "dev.chimera.transform.cfg.CfgFixture";

    @Test
    void controlFlowFlatteningPreservesBehaviourAndFrames() throws Exception {
        byte[] transformed = transform(fixtureBytes(), new ControlFlowFlattening(true));
        assertFramesValid(transformed);
        assertBehaviourMatches(transformed);

        ControlFlowFlattening flattening = new ControlFlowFlattening(true);
        ClassNode node = read(fixtureBytes());
        flattening.transform(FIXTURE, node, context());
        CfgStats stats = flattening.stats();
        assertTrue(stats.methodsFlattened >= 3, stats.toString());
        assertTrue(stats.skippedConstructor >= 1, stats.toString());
        assertTrue(stats.skippedClassInit >= 1, stats.toString());
        assertTrue(stats.skippedTryCatch >= 1, stats.toString());
    }

    @Test
    void opaquePredicatesPreserveBehaviour() throws Exception {
        byte[] transformed = transform(fixtureBytes(), new OpaquePredicate(true));
        assertFramesValid(transformed);
        assertBehaviourMatches(transformed);
    }

    @Test
    void constantChainsPreserveBehaviour() throws Exception {
        byte[] transformed = transform(fixtureBytes(), new ConstantChain(true));
        assertFramesValid(transformed);
        assertBehaviourMatches(transformed);
    }

    @Test
    void combinedPipelinePreservesBehaviour() throws Exception {
        byte[] transformed = transform(fixtureBytes(),
                new ConstantChain(true), new OpaquePredicate(true), new ControlFlowFlattening(true));
        assertFramesValid(transformed);
        assertBehaviourMatches(transformed);
    }

    @Test
    void mixinClassIsSkippedAndSignatureDebugInfoArePreserved() throws Exception {
        ClassNode mixin = mixinNode();
        int instructions = mixin.methods.get(0).instructions.size();
        String classSignature = mixin.signature;
        String methodSignature = mixin.methods.get(0).signature;
        int locals = mixin.methods.get(0).localVariables.size();

        ControlFlowFlattening flattening = new ControlFlowFlattening(true);
        OpaquePredicate opaque = new OpaquePredicate(true);
        ConstantChain chains = new ConstantChain(true);
        TransformContext ctx = context();
        flattening.transform("test/MixinExample", mixin, ctx);
        opaque.transform("test/MixinExample", mixin, ctx);
        chains.transform("test/MixinExample", mixin, ctx);

        assertEquals(1, flattening.stats().classesSkippedMixin);
        assertEquals(1, opaque.stats().classesSkippedMixin);
        assertEquals(1, chains.stats().classesSkippedMixin);
        assertSame(classSignature, mixin.signature);
        assertSame(methodSignature, mixin.methods.get(0).signature);
        assertEquals(locals, mixin.methods.get(0).localVariables.size());
        assertEquals(instructions, mixin.methods.get(0).instructions.size());
    }

    @Test
    void unsafeMethodsAreSkippedAndCounted() throws Exception {
        ClassNode node = read(fixtureBytes());
        ControlFlowFlattening flattening = new ControlFlowFlattening(true);
        flattening.transform(FIXTURE, node, context());
        CfgStats stats = flattening.stats();
        assertTrue(stats.skippedConstructor >= 1, stats.toString());
        assertTrue(stats.skippedClassInit >= 1, stats.toString());
        assertTrue(stats.skippedTryCatch >= 1, stats.toString());
        assertTrue(stats.methodsFlattened > 0, stats.toString());

        // ConstantChain and OpaquePredicate must not touch a try-catch method either.
        ConstantChain chains = new ConstantChain(true);
        chains.transform(FIXTURE, read(fixtureBytes()), context());
        assertTrue(chains.stats().skippedTryCatch >= 1, chains.stats().toString());
    }

    @Test
    void realCfgJarFramesAreValid() throws Exception {
        Path jar = realCfgJar();
        Assumptions.assumeTrue(jar != null, "real CFG jar not found; pass -Dchimera.cfg.realJar=...");
        List<URL> urls = new ArrayList<>();
        urls.add(jar.toUri().toURL());
        String classpath = System.getProperty("chimera.cfg.realClasspath", "");
        List<Path> libraries = new ArrayList<>();
        if (classpath.isBlank()) {
            libraries.addAll(defaultRealClasspath());
        } else {
            for (String part : classpath.split(File.pathSeparator)) {
                if (!part.isBlank()) libraries.add(Path.of(part.trim()));
            }
        }
        for (Path library : libraries) if (Files.isRegularFile(library)) urls.add(library.toUri().toURL());

        List<String> failures = new ArrayList<>();
        int checked = 0;
        // Load every class through a real URLClassLoader and force linking, exactly like the
        // standalone LoadCheck harness used on the full Wurst jar. CheckClassAdapter is avoided
        // here because it resolves every referenced runtime library (gson etc.); the JVM verifier
        // is the authority for StackMapTable validity.
        try (JarFile jarFile = new JarFile(jar.toFile());
             URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]),
                     ClassLoader.getPlatformClassLoader())) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                checked++;
                String binaryName = entry.getName().substring(0, entry.getName().length() - 6)
                        .replace('/', '.');
                try {
                    Class<?> type = Class.forName(binaryName, false, loader);
                    type.getDeclaredMethods();
                    type.getDeclaredFields();
                    type.getDeclaredConstructors();
                } catch (VerifyError failure) {
                    failures.add(entry.getName() + ": " + failure.getMessage());
                } catch (Throwable ignored) {
                    // Missing optional runtime classes are not frame failures; LoadCheck also
                    // ignores them and only counts VerifyError.
                }
                if (failures.size() >= 5) break;
            }
        }
        assertTrue(checked > 0, "real jar has no class entries");
        assertTrue(failures.isEmpty(), "real CFG jar has invalid frames:\n"
                + String.join("\n---\n", failures));
    }

    private static Path realCfgJar() {
        String configured = System.getProperty("chimera.cfg.realJar", "");
        if (!configured.isBlank() && Files.isRegularFile(Path.of(configured))) {
            return Path.of(configured);
        }
        for (String candidate : new String[]{
                "../work/wurst/cfg/control-cfg-fixed.jar",
                "../work/wurst/cfg/cfg-selective.jar",
                "../work/wurst/cfg/control-cfg.jar"}) {
            Path path = Path.of(candidate).toAbsolutePath().normalize();
            if (Files.isRegularFile(path)) return path;
        }
        return null;
    }

    private static List<Path> defaultRealClasspath() throws Exception {
        List<Path> libraries = new ArrayList<>();
        Path root = Path.of("..").toAbsolutePath().normalize();
        for (String pattern : new String[]{
                "work/bench/game/mods/fabric-api-*.jar",
                "work/bench/game/.fabric/processedMods/*.jar",
                "work/phs/libs/mc-intermediary-*.jar",
                "work/wurst/Wurst-Client-*.jar"}) {
            Path base = root;
            for (String part : pattern.split("/")) {
                if (part.contains("*")) {
                    if (!Files.isDirectory(base)) break;
                    try (var stream = Files.list(base)) {
                        String prefix = part.substring(0, part.indexOf('*'));
                        String suffix = part.substring(part.indexOf('*') + 1);
                        stream.filter(p -> p.getFileName().toString().startsWith(prefix)
                                        && p.getFileName().toString().endsWith(suffix)
                                        && Files.isRegularFile(p))
                                .forEach(libraries::add);
                    }
                    break;
                }
                base = base.resolve(part);
            }
        }
        return libraries;
    }

    // ------------------------------------------------------------------ execution equivalence

    private static void assertBehaviourMatches(byte[] transformed) throws Exception {
        Class<?> original = CfgFixture.class;
        Class<?> changed = new ByteLoader(transformed, FIXTURE_BINARY).loadClass(FIXTURE_BINARY);

        int[] branchInputs = {-10, -1, 0, 3, 4, 100};
        for (int x : branchInputs) {
            assertEquals(invokeInt(original, "branchy", x), invokeInt(changed, "branchy", x), "branchy(" + x + ")");
            assertEquals(invokeInt(original, "switchy", x), invokeInt(changed, "switchy", x), "switchy(" + x + ")");
            assertEquals(invokeInt(original, "callsHelper", x), invokeInt(changed, "callsHelper", x), "callsHelper(" + x + ")");
        }
        for (int n : new int[]{0, 1, 5, 10}) {
            assertEquals(invokeInt(original, "loop", n), invokeInt(changed, "loop", n), "loop(" + n + ")");
        }
        for (int x : new int[]{1, 5, 25}) {
            assertEquals(invokeInt(original, "throwsWhenNegative", x),
                    invokeInt(changed, "throwsWhenNegative", x), "throwsWhenNegative(" + x + ")");
        }
        assertEquals(invokeInt(original, "catches", 0), invokeInt(changed, "catches", 0), "catches(0)");
        assertEquals(invokeInt(original, "catches", 5), invokeInt(changed, "catches", 5), "catches(5)");
        assertEquals(invokeInt(original, "constants"), invokeInt(changed, "constants"));
        assertEquals(invokeLong(original, "constantLong", 0L), invokeLong(changed, "constantLong", 0L));
        assertEquals(invokeLong(original, "constantLong", -7L), invokeLong(changed, "constantLong", -7L));
        assertEquals(invokeBoolean(original, "booleany", true), invokeBoolean(changed, "booleany", true));
        assertEquals(invokeBoolean(original, "booleany", false), invokeBoolean(changed, "booleany", false));
        assertEquals(invokeString(original, "stringy", "abc"), invokeString(changed, "stringy", "abc"));

        InvocationTargetException originalFailure = assertThrows(InvocationTargetException.class,
                () -> original.getMethod("throwsWhenNegative", int.class).invoke(null, -3));
        InvocationTargetException changedFailure = assertThrows(InvocationTargetException.class,
                () -> changed.getMethod("throwsWhenNegative", int.class).invoke(null, -3));
        assertEquals(originalFailure.getCause().getClass(), changedFailure.getCause().getClass());
        assertEquals(originalFailure.getCause().getMessage(), changedFailure.getCause().getMessage());

        setStaticState(original, 0);
        setStaticState(changed, 0);
        original.getMethod("voidLoop", int.class).invoke(null, 10);
        changed.getMethod("voidLoop", int.class).invoke(null, 10);
        assertEquals(getStaticState(original), getStaticState(changed), "voidLoop static state");
    }

    private static int invokeInt(Class<?> type, String name, int argument) throws Exception {
        return ((Integer) type.getMethod(name, int.class).invoke(null, argument)).intValue();
    }

    private static int invokeInt(Class<?> type, String name) throws Exception {
        return ((Integer) type.getMethod(name).invoke(null)).intValue();
    }

    private static long invokeLong(Class<?> type, String name, long argument) throws Exception {
        return ((Long) type.getMethod(name, long.class).invoke(null, argument)).longValue();
    }

    private static boolean invokeBoolean(Class<?> type, String name, boolean argument) throws Exception {
        return ((Boolean) type.getMethod(name, boolean.class).invoke(null, argument)).booleanValue();
    }

    private static String invokeString(Class<?> type, String name, String argument) throws Exception {
        return (String) type.getMethod(name, String.class).invoke(null, argument);
    }

    private static void setStaticState(Class<?> type, int value) throws Exception {
        Field field = type.getDeclaredField("staticState");
        field.setAccessible(true);
        field.setInt(null, value);
    }

    private static int getStaticState(Class<?> type) throws Exception {
        Field field = type.getDeclaredField("staticState");
        field.setAccessible(true);
        return field.getInt(null);
    }

    // ------------------------------------------------------------------ ASM/frames

    private static void assertFramesValid(byte[] bytes) {
        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(bytes), CfgFixture.class.getClassLoader(),
                false, new PrintWriter(diagnostics));
        String text = diagnostics.toString();
        assertTrue(text.isEmpty(), "ASM verification failed:\n" + text);
    }

    // ------------------------------------------------------------------ plumbing

    private static byte[] fixtureBytes() throws Exception {
        try (InputStream in = CfgFixture.class.getResourceAsStream("CfgFixture.class")) {
            assertNotNull(in, "fixture class resource missing");
            return in.readAllBytes();
        }
    }

    private static ClassNode read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static byte[] transform(byte[] bytes, Transformer... transformers) throws Exception {
        ClassNode node = read(bytes);
        TransformContext ctx = context();
        for (Transformer transformer : transformers) {
            transformer.transform(FIXTURE, node, ctx);
        }
        ClassWriter writer = new ChimeraClassWriter(
                ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS, ctx.pool);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static TransformContext context() throws Exception {
        ChimeraConfig config = new ChimeraConfig();
        config.keyMaterial = new byte[32];
        config.resourceKeyMaterial = new byte[32];
        byte[] bytes = fixtureBytes();
        Map<String, byte[]> classes = new HashMap<>();
        classes.put(FIXTURE + ".class", bytes);
        ClassPool pool = new ClassPool(classes);
        return new TransformContext(config, new byte[16], new byte[32], pool,
                (name, data) -> {
                }, new Stats(), "cfg-test");
    }

    private static ClassNode mixinNode() {
        ClassNode node = new ClassNode();
        node.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "test/MixinExample",
                "Ljava/lang/Object;", "java/lang/Object", null);
        node.signature = "Ljava/lang/Object;";
        node.visibleAnnotations = new ArrayList<>();
        node.visibleAnnotations.add(new AnnotationNode("Lorg/spongepowered/asm/mixin/Mixin;"));
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC, "m", "(I)I", "(I)I", null);
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        method.instructions.add(start);
        method.instructions.add(new VarInsnNode(Opcodes.ILOAD, 1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.instructions.add(end);
        method.localVariables = new ArrayList<>(List.of(
                new LocalVariableNode("this", "Ltest/MixinExample;", null, start, end, 0),
                new LocalVariableNode("x", "I", null, start, end, 1)));
        node.methods.add(method);
        return node;
    }

    private static final class ByteLoader extends ClassLoader {
        private final byte[] bytes;
        private final String target;

        ByteLoader(byte[] bytes, String target) {
            super(CfgFixture.class.getClassLoader());
            this.bytes = bytes;
            this.target = target;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!target.equals(name)) return super.loadClass(name, resolve);
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) loaded = defineClass(name, bytes, 0, bytes.length);
                if (resolve) resolveClass(loaded);
                return loaded;
            }
        }
    }
}
