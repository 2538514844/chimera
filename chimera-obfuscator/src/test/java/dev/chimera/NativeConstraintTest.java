package dev.chimera;

import dev.chimera.core.ChimeraConfig;
import dev.chimera.core.ClassPool;
import dev.chimera.core.Stats;
import dev.chimera.core.TransformContext;
import dev.chimera.transform.NativeStubTransformer;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Task 3: native methods must return business values, not boolean/int/void. */
public class NativeConstraintTest {

    private static TransformContext context() {
        ChimeraConfig cfg = new ChimeraConfig();
        cfg.keyMaterial = "test-key-material-0123456789abcd".getBytes(StandardCharsets.UTF_8);
        Stats stats = new Stats();
        return new TransformContext(cfg, new byte[16], new byte[32],
                new ClassPool(Map.of()), (name, data) -> { }, stats, "build-id");
    }

    private static ClassNode nodeWithNative(String name, String desc) {
        ClassNode node = new ClassNode();
        node.version = Opcodes.V17;
        node.access = Opcodes.ACC_PUBLIC;
        node.name = "fixtures/NativeFixture";
        node.superName = "java/lang/Object";
        MethodNode method = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
        method.visibleAnnotations = List.of(new AnnotationNode("Ldev/chimera/annotations/ChimeraNative;"));
        node.methods.add(method);
        return node;
    }

    @Test
    public void booleanNativeIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                new NativeStubTransformer().transform("fixtures/NativeFixture",
                        nodeWithNative("check", "()Z"), context()));
        assertTrue(e.getMessage().contains("business value"), e.getMessage());
    }

    @Test
    public void intNativeIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new NativeStubTransformer().transform("fixtures/NativeFixture",
                        nodeWithNative("judge", "()I"), context()));
    }

    @Test
    public void voidNativeIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new NativeStubTransformer().transform("fixtures/NativeFixture",
                        nodeWithNative("run", "()V"), context()));
    }

    @Test
    public void doubleNativeIsAccepted() {
        assertDoesNotThrow(() ->
                new NativeStubTransformer().transform("fixtures/NativeFixture",
                        nodeWithNative("damage", "(DD)D"), context()));
    }
}
