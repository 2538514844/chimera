package dev.chimera.transform.mixinsupport;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Behavioural tests for {@link MixinSupport}: synthetic mixin configs and refmaps, generated
 * {@code @Mixin} classes, fail-closed parsing and byte preservation.
 */
class MixinSupportTest {

    private static final String UTF_8 = StandardCharsets.UTF_8.name();
    private static final String MIXIN = "com/example/mixin/MyMixin";
    private static final String CONFIG = "example.mixins.json";
    private static final String REFMAP = "example-refmap.json";

    @Test
    void rewritesConfigAnnotationsAndRefmap() {
        byte[] myMixin = mixinClass(MIXIN, "<T:Ljava/lang/Object;>Ljava/lang/Object;", false,
                new String[]{"com.example.Target"}, Type.getObjectType("com/example/Other"));
        byte[] otherMixin = mixinClass("com/example/mixin/OtherMixin", null, false,
                new String[]{"java.lang.Object"}, null);
        byte[] visibleMixin = mixinClass("com/example/mixin/VisibleMixin", null, true,
                new String[]{"com.example.Target"}, null);

        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(MIXIN + ".class", myMixin);
        classes.put("com/example/mixin/OtherMixin.class", otherMixin);
        classes.put("com/example/mixin/VisibleMixin.class", visibleMixin);

        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"required\":true,\"package\":\"com.example.mixin\","
                + "\"compatibilityLevel\":\"JAVA_17\",\"mixins\":[\"MyMixin\",\"ExtraMixin\"],"
                + "\"client\":[\"OtherMixin\"],\"refmap\":\"" + REFMAP + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        resources.put(REFMAP, ("{\"mappings\":{\"com/example/mixin/MyMixin\":{"
                + "\"Lcom/example/Target;run()V\":\"run\","
                + "\"Lcom/example/mixin/MyMixin;value:I\":\"value\","
                + "\"com.example.Target\":\"com.example.Target\","
                + "\"Lcom/example/mixin/MyMixin;slot:Lcom/example/Target;\":\"slot\"}},"
                + "\"data\":{\"named\":{\"com/example/mixin/MyMixin\":{\"run\":\"run\"}}}}")
                .getBytes(StandardCharsets.UTF_8));

        MixinSupport.Plan plan = new MixinSupport.Plan()
                .classRename("com/example/Target", "a/b/X")
                .classRename("com/example/Other", "a/b/Y")
                .classRename(MIXIN, "a/b/MyMixin")
                .classRename("com/example/mixin/OtherMixin", "a/b/OtherMixin")
                .classRename("com/example/mixin/VisibleMixin", "a/b/VisibleMixin")
                .classRename("com/example/mixin/ExtraMixin", "a/b/Extra")
                .memberRename(MIXIN, "run()V", "a")
                .memberRename(MIXIN, "value:I", "v")
                .memberRename(MIXIN, "slot:Lcom/example/Target;", "s")
                .stripRefmap(false);

        MixinSupport.Result result = MixinSupport.apply(classes, resources, plan);

        assertEquals(1, result.jsonRewritten(), "one mixin config rewritten");
        assertEquals(1, result.refmapRewritten(), "refmap rewritten");
        assertEquals(0, result.refmapRemoved(), "refmap kept");
        assertEquals(3, result.mixinTargetsMapped(), "targets + value + visible target");

        String configText = new String(result.resources().get(CONFIG), StandardCharsets.UTF_8);
        assertStructurallyValidJson(configText);
        Map<String, Object> config = json(result.resources().get(CONFIG));
        assertEquals("a.b", config.get("package"));
        assertEquals(List.of("MyMixin", "Extra"), config.get("mixins"));
        assertEquals(List.of("OtherMixin"), config.get("client"));
        assertEquals("JAVA_17", config.get("compatibilityLevel"));
        assertEquals(Boolean.TRUE, config.get("required"));
        assertEquals(REFMAP, config.get("refmap"));
        assertFalse(configText.contains("com.example"), "old package leaked: " + configText);

        String refmapText = new String(result.resources().get(REFMAP), StandardCharsets.UTF_8);
        assertStructurallyValidJson(refmapText);
        assertFalse(refmapText.contains("com/example"), "old internal name leaked: " + refmapText);
        assertFalse(refmapText.contains("com.example"), "old binary name leaked: " + refmapText);
        assertTrue(refmapText.contains("a/b/MyMixin"), refmapText);
        assertTrue(refmapText.contains("a.b.X"), refmapText);
        assertTrue(refmapText.contains("La/b/X;"), refmapText);
        assertTrue(refmapText.contains("La/b/MyMixin;v:I"), "field member key renamed: " + refmapText);
        assertTrue(refmapText.contains("La/b/MyMixin;s:La/b/X;"),
                "field key with descriptor renamed: " + refmapText);
        assertTrue(refmapText.contains("\"a\""), "method member value renamed: " + refmapText);
        assertTrue(refmapText.contains("\"v\""), "field member value renamed: " + refmapText);
        assertTrue(refmapText.contains("\"s\""), "field value with descriptor renamed: " + refmapText);

        ClassNode rewritten = parse(result.classes().get(MIXIN + ".class"));
        assertEquals("<T:Ljava/lang/Object;>Ljava/lang/Object;", rewritten.signature,
                "class Signature preserved");
        assertEquals(MIXIN + ".java", rewritten.sourceFile, "SourceFile preserved");
        AnnotationNode annotation = mixinAnnotation(rewritten);
        assertNotNull(annotation, "@Mixin kept");
        assertEquals(List.of("a.b.X"), targets(annotation));
        assertEquals("a/b/Y", valueTarget(annotation));
        assertEquals(1200, annotationValue(annotation, "priority"),
                "unknown @Mixin member preserved");
        assertEquals(Boolean.FALSE, annotationValue(annotation, "remap"),
                "unknown @Mixin member preserved");

        MethodNode hook = method(rewritten, "hook");
        assertNotNull(hook, "method kept");
        assertNotNull(hook.localVariables, "LocalVariableTable kept");
        assertEquals(1, hook.localVariables.size());
        LocalVariableNode local = hook.localVariables.get(0);
        assertEquals("this", local.name);
        assertEquals("L" + MIXIN + ";", local.desc);
        assertEquals(42, firstLine(hook), "LineNumberTable kept");

        ClassNode visible = parse(result.classes().get("com/example/mixin/VisibleMixin.class"));
        assertEquals(List.of("a.b.X"), targets(mixinAnnotation(visible)),
                "visible @Mixin rewritten");

        assertArrayEquals(otherMixin, result.classes().get("com/example/mixin/OtherMixin.class"),
                "class without a mapped target keeps its exact bytes");
    }

    @Test
    void stripRefmapRemovesFieldAndResource() {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(MIXIN + ".class", mixinClass(MIXIN, null, false,
                new String[]{"com.example.Target"}, null));
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"package\":\"com.example.mixin\",\"mixins\":[\"MyMixin\"],"
                + "\"refmap\":\"" + REFMAP + "\"}").getBytes(StandardCharsets.UTF_8));
        resources.put(REFMAP, "{\"mappings\":{\"com/example/mixin/MyMixin\":{}}}"
                .getBytes(StandardCharsets.UTF_8));

        MixinSupport.Result result = MixinSupport.apply(classes, resources,
                new MixinSupport.Plan()
                        .classRename(MIXIN, "a/b/MyMixin")
                        .classRename("com/example/Target", "a/b/X")
                        .stripRefmap(true));

        assertEquals(1, result.jsonRewritten());
        assertEquals(1, result.refmapRemoved(), "refmap resource deleted");
        assertEquals(0, result.refmapRewritten());
        assertFalse(result.resources().containsKey(REFMAP), "refmap entry gone");
        Map<String, Object> config = json(result.resources().get(CONFIG));
        assertFalse(config.containsKey("refmap"), "refmap field removed");
        assertEquals("a.b", config.get("package"));
    }

    @Test
    void emptyPlanLeavesEverythingByteIdentical() {
        byte[] config = "{\"package\":\"com.example.mixin\",\"mixins\":[\"MyMixin\"],\"refmap\":\""
                .concat(REFMAP).concat("\"}").getBytes(StandardCharsets.UTF_8);
        byte[] refmap = "{\"mappings\":{\"x\":{}}}".getBytes(StandardCharsets.UTF_8);
        byte[] clazz = mixinClass(MIXIN, null, false, new String[]{"com.example.Target"}, null);
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(MIXIN + ".class", clazz);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, config);
        resources.put(REFMAP, refmap);

        MixinSupport.Result result = MixinSupport.apply(classes, resources,
                new MixinSupport.Plan().stripRefmap(true));

        assertEquals(0, result.jsonRewritten());
        assertEquals(0, result.refmapRemoved());
        assertEquals(0, result.refmapRewritten());
        assertEquals(0, result.mixinTargetsMapped());
        assertArrayEquals(config, result.resources().get(CONFIG));
        assertArrayEquals(refmap, result.resources().get(REFMAP));
        assertArrayEquals(clazz, result.classes().get(MIXIN + ".class"));
    }

    @Test
    void malformedMixinConfigFailsClosed() {
        byte[] broken = "{\"package\":\"com.example.mixin\",\"mixins\":[\"MyMixin\"]"
                .getBytes(StandardCharsets.UTF_8);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put("broken.mixins.json", broken);

        MixinSupportException error = assertThrows(MixinSupportException.class,
                () -> MixinSupport.apply(new LinkedHashMap<>(), resources,
                        new MixinSupport.Plan().classRename("com/example/mixin/MyMixin", "a/b/M")));
        assertTrue(error.getMessage().contains("broken.mixins.json"), error.getMessage());
        assertNotNull(error.getCause());
        assertArrayEquals(broken, resources.get("broken.mixins.json"), "input not mutated");
    }

    @Test
    void malformedReferencedRefmapFailsClosed() {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"package\":\"com.example.mixin\",\"mixins\":[\"MyMixin\"],"
                + "\"refmap\":\"" + REFMAP + "\"}").getBytes(StandardCharsets.UTF_8));
        byte[] broken = "{\"mappings\":{\"x\":{".getBytes(StandardCharsets.UTF_8);
        resources.put(REFMAP, broken);

        MixinSupportException error = assertThrows(MixinSupportException.class,
                () -> MixinSupport.apply(new LinkedHashMap<>(), resources,
                        new MixinSupport.Plan().classRename(MIXIN, "a/b/M")));
        assertTrue(error.getMessage().contains(REFMAP), error.getMessage());
        assertArrayEquals(broken, resources.get(REFMAP), "input not mutated");
    }

    @Test
    void nonUniformPackagesFallBackToFullyQualifiedEntries() {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"package\":\"com.example.mixin\",\"mixins\":[\"A\",\"B\"]}")
                .getBytes(StandardCharsets.UTF_8));

        MixinSupport.Result result = MixinSupport.apply(new LinkedHashMap<>(), resources,
                new MixinSupport.Plan()
                        .classRename("com/example/mixin/A", "x/A")
                        .classRename("com/example/mixin/B", "y/B"));

        Map<String, Object> config = json(result.resources().get(CONFIG));
        assertEquals("com.example.mixin", config.get("package"), "package kept");
        assertEquals(List.of("x.A", "y.B"), config.get("mixins"), "entries fully qualified");
        assertStructurallyValidJson(new String(result.resources().get(CONFIG),
                StandardCharsets.UTF_8));
    }

    @Test
    void excludesSuppressEveryRewrite() {
        byte[] myMixin = mixinClass(MIXIN, null, false,
                new String[]{"com.example.Target"}, null);
        byte[] config = ("{\"package\":\"com.example.mixin\",\"mixins\":[\"MyMixin\"],"
                + "\"refmap\":\"" + REFMAP + "\"}").getBytes(StandardCharsets.UTF_8);
        byte[] refmap = ("{\"mappings\":{\"com/example/mixin/MyMixin\":{"
                + "\"Lcom/example/Target;run()V\":\"run\"}}}")
                .getBytes(StandardCharsets.UTF_8);
        Map<String, byte[]> classes = new LinkedHashMap<>();
        classes.put(MIXIN + ".class", myMixin);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, config);
        resources.put(REFMAP, refmap);

        MixinSupport.Result result = MixinSupport.apply(classes, resources,
                new MixinSupport.Plan()
                        .classRename(MIXIN, "a/b/MyMixin")
                        .classRename("com/example/Target", "a/b/X")
                        .memberRename(MIXIN, "run()V", "a")
                        .exclude("com/example"));

        assertEquals(0, result.mixinTargetsMapped());
        assertEquals(0, result.jsonRewritten());
        assertEquals(0, result.refmapRewritten());
        assertArrayEquals(myMixin, result.classes().get(MIXIN + ".class"));
        assertArrayEquals(config, result.resources().get(CONFIG));
        assertArrayEquals(refmap, result.resources().get(REFMAP));
    }

    @Test
    void nonMixinJsonIsIgnoredEvenWhenMalformed() {
        byte[] fabric = ("{\"schemaVersion\":1,\"id\":\"fixture\","
                + "\"mixins\":[\"example.mixins.json\"]}").getBytes(StandardCharsets.UTF_8);
        byte[] unrelatedBroken = "{not json".getBytes(StandardCharsets.UTF_8);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put("fabric.mod.json", fabric);
        resources.put("assets/fixture/broken.json", unrelatedBroken);

        MixinSupport.Result result = MixinSupport.apply(new LinkedHashMap<>(), resources,
                new MixinSupport.Plan().classRename("com/example/Target", "a/b/X"));

        assertEquals(0, result.jsonRewritten());
        assertArrayEquals(fabric, result.resources().get("fabric.mod.json"));
        assertArrayEquals(unrelatedBroken, result.resources().get("assets/fixture/broken.json"));
    }

    @Test
    void lenientConfigIsNormalisedToStrictJson() {
        byte[] config = ("{\n"
                + "  // mixin config with Gson lenient syntax\n"
                + "  package: 'com.example.mixin',\n"
                + "  mixins: ['MyMixin',],\n"
                + "  \"client\": [],\n"
                + "  \"priority\": 1200,\n"
                + "}\n").getBytes(StandardCharsets.UTF_8);
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, config);

        MixinSupport.Result result = MixinSupport.apply(new LinkedHashMap<>(), resources,
                new MixinSupport.Plan().classRename(MIXIN, "a/b/MyMixin"));

        String text = new String(result.resources().get(CONFIG), StandardCharsets.UTF_8);
        assertStructurallyValidJson(text);
        assertFalse(text.contains("//"), "comment dropped: " + text);
        assertFalse(text.contains("'"), "single quotes normalised: " + text);
        Map<String, Object> parsed = json(result.resources().get(CONFIG));
        assertEquals("a.b", parsed.get("package"));
        assertEquals(1200L, parsed.get("priority"));
        assertEquals(List.of("MyMixin"), parsed.get("mixins"));
    }

    @Test
    void fullyQualifiedEntryInsidePackageFollowsPackageRename() {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"package\":\"com.example.mixin\","
                + "\"mixins\":[\"com.example.mixin.MyMixin\"]}")
                .getBytes(StandardCharsets.UTF_8));

        MixinSupport.Result result = MixinSupport.apply(new LinkedHashMap<>(), resources,
                new MixinSupport.Plan().classRename(MIXIN, "a/b/MyMixin"));

        Map<String, Object> config = json(result.resources().get(CONFIG));
        assertEquals("a.b", config.get("package"));
        assertEquals(List.of("MyMixin"), config.get("mixins"));
    }

    @Test
    void fullyQualifiedEntryOutsidePackageUsesAbsoluteName() {
        Map<String, byte[]> resources = new LinkedHashMap<>();
        resources.put(CONFIG, ("{\"package\":\"example.mixin\","
                + "\"mixins\":[\"example.ProtectedByConfig\"]}")
                .getBytes(StandardCharsets.UTF_8));

        MixinSupport.Result result = MixinSupport.apply(new LinkedHashMap<>(), resources,
                new MixinSupport.Plan()
                        .classRename("example/ProtectedByConfig", "a/b/ProtectedByConfig"));

        Map<String, Object> config = json(result.resources().get(CONFIG));
        assertEquals("example.mixin", config.get("package"), "package cannot be inferred");
        assertEquals(List.of("a.b.ProtectedByConfig"), config.get("mixins"));
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    private static byte[] mixinClass(String internalName, String signature, boolean visible,
                                     Object targets, Type valueType) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER, internalName,
                signature, "java/lang/Object", null);
        writer.visitSource(internalName + ".java", null);
        AnnotationVisitor annotation = writer.visitAnnotation(
                MixinAnnotationRewriter.MIXIN_DESCRIPTOR, visible);
        if (targets instanceof String[] array) {
            AnnotationVisitor arrayVisitor = annotation.visitArray("targets");
            for (String target : array) {
                arrayVisitor.visit(null, target);
            }
            arrayVisitor.visitEnd();
        }
        if (valueType != null) {
            annotation.visit("value", valueType);
        }
        annotation.visit("priority", 1200);
        annotation.visit("remap", false);
        annotation.visitEnd();

        FieldVisitor field = writer.visitField(Opcodes.ACC_PRIVATE, "target",
                "Lcom/example/Target;", "Lcom/example/Target;", null);
        field.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "hook", "()V", null, null);
        method.visitCode();
        Label start = new Label();
        Label end = new Label();
        method.visitLabel(start);
        method.visitLineNumber(42, start);
        method.visitInsn(Opcodes.RETURN);
        method.visitLabel(end);
        method.visitLocalVariable("this", "L" + internalName + ";", null, start, end, 0);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static ClassNode parse(byte[] bytes) {
        assertNotNull(bytes, "class bytes present");
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static AnnotationNode mixinAnnotation(ClassNode node) {
        List<AnnotationNode> annotations = new ArrayList<>();
        if (node.visibleAnnotations != null) {
            annotations.addAll(node.visibleAnnotations);
        }
        if (node.invisibleAnnotations != null) {
            annotations.addAll(node.invisibleAnnotations);
        }
        for (AnnotationNode annotation : annotations) {
            if (MixinAnnotationRewriter.MIXIN_DESCRIPTOR.equals(annotation.desc)) {
                return annotation;
            }
        }
        return null;
    }

    private static List<String> targets(AnnotationNode annotation) {
        List<String> out = new ArrayList<>();
        if (annotation == null || annotation.values == null) {
            return out;
        }
        for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
            if (!"targets".equals(annotation.values.get(i))) {
                continue;
            }
            Object value = annotation.values.get(i + 1);
            if (value instanceof List<?> list) {
                for (Object item : list) {
                    out.add(String.valueOf(item));
                }
            }
        }
        return out;
    }

    private static Object annotationValue(AnnotationNode annotation, String key) {
        if (annotation == null || annotation.values == null) {
            return null;
        }
        for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
            if (key.equals(annotation.values.get(i))) {
                return annotation.values.get(i + 1);
            }
        }
        return null;
    }

    private static String valueTarget(AnnotationNode annotation) {
        if (annotation == null || annotation.values == null) {
            return null;
        }
        for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
            if (!"value".equals(annotation.values.get(i))) {
                continue;
            }
            Object value = annotation.values.get(i + 1);
            if (value instanceof Type type) {
                return type.getInternalName();
            }
            return String.valueOf(value);
        }
        return null;
    }

    private static MethodNode method(ClassNode node, String name) {
        for (MethodNode method : node.methods) {
            if (name.equals(method.name)) {
                return method;
            }
        }
        return null;
    }

    private static int firstLine(MethodNode method) {
        for (int i = 0; i < method.instructions.size(); i++) {
            if (method.instructions.get(i) instanceof LineNumberNode line) {
                return line.line;
            }
        }
        return -1;
    }

    private static Map<String, Object> json(byte[] data) {
        assertNotNull(data, "resource present");
        String text = new String(data, StandardCharsets.UTF_8);
        assertStructurallyValidJson(text);
        Object parsed = Json.parse(text);
        assertTrue(parsed instanceof Map<?, ?>, "JSON object expected: " + text);
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) parsed;
        return map;
    }

    /**
     * Independent minimal structural check (separate from {@link Json}) so a writer/reader pair
     * bug cannot validate itself: strings are balanced, braces/brackets nest correctly.
     */
    private static void assertStructurallyValidJson(String text) {
        int braces = 0;
        int brackets = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                braces++;
            } else if (c == '}') {
                if (--braces < 0) {
                    fail("unbalanced '}': " + text);
                }
            } else if (c == '[') {
                brackets++;
            } else if (c == ']') {
                if (--brackets < 0) {
                    fail("unbalanced ']': " + text);
                }
            }
        }
        assertFalse(inString, "unterminated string: " + text);
        assertEquals(0, braces, "unbalanced braces: " + text);
        assertEquals(0, brackets, "unbalanced brackets: " + text);
    }
}
