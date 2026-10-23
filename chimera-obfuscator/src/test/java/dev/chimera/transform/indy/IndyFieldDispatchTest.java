package dev.chimera.transform.indy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.util.CheckClassAdapter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * G3 acceptance: GETFIELD/GETSTATIC are rewritten to {@code invokedynamic} bound to
 * {@code KIND_FIELD}/{@code KIND_STATIC_FIELD}, execute identically to the original bytecode, and
 * their CHMI {@code ENTRY_FIELD} entries round-trip through
 * {@link MemberIdRegistry#loadMemberTable(byte[], ClassLoader, boolean)} including superclass
 * hierarchy resolution. PUT* stays plain and is counted (setter path TODO).
 */
public class IndyFieldDispatchTest implements Opcodes {

    private static final String FIELD_SUBJECT = "sample/FieldSubject";
    private static final String BASE = "sample/FieldBase";
    private static final String SUB = "sample/FieldSub";
    private static final String PRIMITIVE = "sample/PrimitiveFields";
    private static final String OBJECT = "java/lang/Object";

    @BeforeEach
    void reset() {
        MemberIdRegistry.clearForTests();
        ChimeraBootstrap.installCheckHook(CheckHook.DENY);
    }

    @Test
    void getFieldAndGetStaticRewritesExecuteLikeTheOriginal() throws Exception {
        Map<String, byte[]> originals = new LinkedHashMap<>();
        originals.put(FIELD_SUBJECT, fieldSubject());
        IndyIntegration.Result result =
                IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);
        IndyDispatchTransformer.Stats stats = result.stats();

        // Constructor: Object.<init> (skipped) + 2 PUTFIELD (writes TODO).
        assertEquals(1, stats.invokeSites());
        assertEquals(0, stats.rewritten());
        assertEquals(8, stats.fieldAccessSites(), "2 ctor PUTFIELD + 4 GET* + touch PUTFIELD/PUTSTATIC");
        assertEquals(4, stats.fieldReadsRewritten(), "readStatic/readStaticLong/readInstance/readLong");
        assertEquals(4, stats.fieldWritesSkipped(), "PUTFIELD/PUTSTATIC setter path is TODO");
        assertEquals(0, stats.fieldSkippedByPolicy());
        assertEquals(1, stats.classConstantsSkipped(), "LDC class literal is TODO");
        assertEquals(4, result.memberEntries(), "four ENTRY_FIELD entries");
        assertEquals(1, result.classEntries());
        assertEquals(4, result.distinctBsmOwners());

        ClassNode rewritten = readNode(result.classes().get(FIELD_SUBJECT));
        Map<String, String> indyDescriptors = new LinkedHashMap<>();
        int remainingReads = 0;
        int remainingWrites = 0;
        for (MethodNode method : rewritten.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    indyDescriptors.put(indy.name, indy.desc);
                    assertTrue(indy.bsm.getOwner().startsWith("chimera/indy/Bsm"),
                            "field reads must use a dispersed bootstrap owner");
                } else if (insn instanceof FieldInsnNode field) {
                    int opcode = field.getOpcode();
                    if (opcode == GETFIELD || opcode == GETSTATIC) {
                        remainingReads++;
                    } else if (opcode == PUTFIELD || opcode == PUTSTATIC) {
                        remainingWrites++;
                    }
                }
            }
        }
        assertEquals(4, indyDescriptors.size());
        assertEquals(0, remainingReads, "every field read must be rewritten");
        assertEquals(4, remainingWrites, "field writes stay plain");
        // invokedynamic name = original field name; descriptor = field access shape.
        assertEquals("()I", indyDescriptors.get("STATIC_VALUE"));
        assertEquals("()J", indyDescriptors.get("STATIC_LONG"));
        assertEquals("(L" + FIELD_SUBJECT + ";)I", indyDescriptors.get("instanceValue"));
        assertEquals("(L" + FIELD_SUBJECT + ";)J", indyDescriptors.get("longValue"));

        // Raw member table: 1 class entry + 4 field entries, no method entries.
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(result.memberTable()))) {
            assertEquals(MemberIdRegistry.MEMBER_TABLE_MAGIC, in.readInt());
            assertEquals(MemberIdRegistry.MEMBER_TABLE_VERSION, in.readInt());
            assertEquals(5, in.readInt());
            int classEntries = 0;
            int fieldEntries = 0;
            int methodEntries = 0;
            for (int i = 0; i < 5; i++) {
                int kind = in.readUnsignedByte();
                in.readLong();
                in.readLong();
                readUtf(in);
                readUtf(in);
                readUtf(in);
                if (kind == MemberIdRegistry.ENTRY_CLASS) classEntries++;
                if (kind == MemberIdRegistry.ENTRY_FIELD) fieldEntries++;
                if (kind == MemberIdRegistry.ENTRY_METHOD) methodEntries++;
            }
            assertEquals(1, classEntries);
            assertEquals(4, fieldEntries);
            assertEquals(0, methodEntries);
        }

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader, true);
        assertEquals(0, MemberIdRegistry.unresolvedMembers());
        assertEquals(1, MemberIdRegistry.registeredClasses());
        assertEquals(4, MemberIdRegistry.registeredMembers());

        long classId = MemberIdRegistry.classId(FIELD_SUBJECT);
        long instanceId = MemberIdRegistry.memberId(FIELD_SUBJECT, "instanceValue", "I");
        Field instanceField = MemberIdRegistry.c(classId, instanceId);
        assertNotNull(instanceField);
        assertEquals("instanceValue", instanceField.getName());
        assertEquals(FIELD_SUBJECT.replace('/', '.'), instanceField.getDeclaringClass().getName());
        assertEquals(MemberIdRegistry.MEMBER_FIELD, MemberIdRegistry.a(classId, instanceId));
        assertNotNull(MemberIdRegistry.c(classId,
                MemberIdRegistry.memberId(FIELD_SUBJECT, "STATIC_LONG", "J")));

        List<CheckHook.LinkRequest> requests = new ArrayList<>();
        ChimeraBootstrap.installCheckHook(request -> {
            synchronized (requests) {
                requests.add(request);
            }
            return true;
        });

        Class<?> type = Class.forName(FIELD_SUBJECT.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor(int.class, long.class).newInstance(7, 9L);
        assertEquals(41, invokeInt(type, "readStatic"));
        assertEquals(1234567890123L, invokeLong(type, "readStaticLong"));
        assertEquals(7, invokeIntOn(type, "readInstance", instance));
        assertEquals(9L, invokeLongOn(type, "readLong", instance));
        assertEquals(4, requests.size(), "each field-read site links exactly once");
        for (CheckHook.LinkRequest request : requests) {
            assertNull(request.method(), "field links carry a Field, not a Method");
            assertNotNull(request.field());
            assertTrue(request.kind() == ChimeraBootstrap.KIND_FIELD
                    || request.kind() == ChimeraBootstrap.KIND_STATIC_FIELD);
        }

        // Writes stay plain and must still work.
        type.getMethod("touch", int.class).invoke(instance, 99);
        assertEquals(99, invokeIntOn(type, "readInstance", instance));
        assertEquals(99, ((Number) type.getField("mutableStatic").get(null)).intValue());
        assertEquals(4, requests.size(), "linked field sites must not re-run the check");

        StringWriter diagnostics = new StringWriter();
        CheckClassAdapter.verify(new ClassReader(result.classes().get(FIELD_SUBJECT)), loader, false,
                new PrintWriter(diagnostics));
        assertEquals("", diagnostics.toString().trim(), "ASM data-flow verification must pass");
    }

    @Test
    void inheritedFieldResolvesThroughHierarchyAndBadEntriesFailClosed() throws Exception {
        Map<String, byte[]> originals = new LinkedHashMap<>();
        originals.put(BASE, fieldBase());
        originals.put(SUB, fieldSub());
        IndyIntegration.Result result =
                IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);

        assertEquals(2, result.stats().invokeSites(), "Base.<init> and Sub.<init>");
        assertEquals(2, result.stats().skipped(), "constructor calls stay plain");
        assertEquals(1, result.stats().fieldReadsRewritten());
        assertEquals(1, result.stats().fieldWritesSkipped());

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader, true);

        long subClassId = MemberIdRegistry.classId(SUB);
        long fieldId = MemberIdRegistry.memberId(SUB, "baseValue", "I");
        Field resolved = MemberIdRegistry.c(subClassId, fieldId);
        assertNotNull(resolved, "subclass owner entry must resolve a superclass-declared field");
        assertEquals(BASE.replace('/', '.'), resolved.getDeclaringClass().getName());
        assertEquals(MemberIdRegistry.MEMBER_FIELD, MemberIdRegistry.a(subClassId, fieldId));
        assertEquals(0, MemberIdRegistry.unresolvedMembers());

        ChimeraBootstrap.installCheckHook(CheckHook.ALLOW);
        Class<?> sub = Class.forName(SUB.replace('/', '.'), true, loader);
        Object instance = sub.getDeclaredConstructor(int.class).newInstance(13);
        assertEquals(13, invokeIntOn(sub, "readInherited", instance));

        // Wrong descriptor: loadMemberTable rejects the table instead of silently linking.
        MemberIdRegistry.clearForTests();
        byte[] wrongDescriptor = oneFieldTable(SUB, "baseValue", "J");
        IllegalArgumentException descriptorError = assertThrows(IllegalArgumentException.class,
                () -> MemberIdRegistry.loadMemberTable(wrongDescriptor, loader, true));
        assertTrue(descriptorError.getMessage().contains("descriptor"),
                "got " + descriptorError.getMessage());

        // Unknown field: strict mode rejects the table, lenient mode leaves it unresolved and the
        // affected call site still fails closed at link time (never a fabricated success).
        MemberIdRegistry.clearForTests();
        byte[] missingField = oneFieldTable(SUB, "doesNotExist", "I");
        assertThrows(IllegalArgumentException.class,
                () -> MemberIdRegistry.loadMemberTable(missingField, loader, true));
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(missingField, loader);
        assertEquals(1, MemberIdRegistry.unresolvedMembers());
        assertNull(MemberIdRegistry.c(subClassId,
                MemberIdRegistry.memberId(SUB, "doesNotExist", "I")));
    }

    @Test
    void primitiveFieldDescriptorsKeepTheirDeclaredType() throws Exception {
        Map<String, byte[]> originals = new LinkedHashMap<>();
        originals.put(PRIMITIVE, primitiveFields());
        IndyIntegration.Result result =
                IndyIntegration.prepare(originals, IndyIntegration.Options.AGGRESSIVE);

        assertEquals(1, result.stats().invokeSites());
        assertEquals(5, result.stats().fieldReadsRewritten());
        assertEquals(1, result.stats().fieldWritesSkipped());
        assertEquals(6, result.stats().fieldAccessSites());
        assertEquals(5, result.memberEntries());

        ClassNode node = readNode(result.classes().get(PRIMITIVE));
        Map<String, String> descriptors = new LinkedHashMap<>();
        for (MethodNode method : node.methods) {
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    descriptors.put(indy.name, indy.desc);
                }
            }
        }
        // Z/B/C/S all verify as int, so the declared descriptor is kept and the bootstrap handle
        // needs no boolean->int conversion.
        assertEquals("()Z", descriptors.get("FLAG"));
        assertEquals("()B", descriptors.get("SMALL"));
        assertEquals("()C", descriptors.get("LETTER"));
        assertEquals("()S", descriptors.get("SHORT_VALUE"));
        assertEquals("(L" + PRIMITIVE + ";)Z", descriptors.get("instanceFlag"));

        TestByteLoader loader = new TestByteLoader(result.classes(), getClass().getClassLoader());
        MemberIdRegistry.clearForTests();
        MemberIdRegistry.loadMemberTable(result.memberTable(), loader, true);
        ChimeraBootstrap.installCheckHook(CheckHook.ALLOW);

        Class<?> type = Class.forName(PRIMITIVE.replace('/', '.'), true, loader);
        Object instance = type.getDeclaredConstructor().newInstance();
        assertEquals(Boolean.TRUE, type.getMethod("readFlag").invoke(null));
        assertEquals(Byte.valueOf((byte) 5), type.getMethod("readSmall").invoke(null));
        assertEquals(Character.valueOf('A'), type.getMethod("readLetter").invoke(null));
        assertEquals(Short.valueOf((short) 300), type.getMethod("readShort").invoke(null));
        assertEquals(Boolean.TRUE, type.getMethod("readInstanceFlag").invoke(instance));
    }

    // ------------------------------------------------------------------ fixtures

    static byte[] fieldSubject() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, FIELD_SUBJECT, null, OBJECT, null);
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "STATIC_VALUE", "I", null,
                Integer.valueOf(41)).visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "STATIC_LONG", "J", null,
                Long.valueOf(1234567890123L)).visitEnd();
        cw.visitField(ACC_PUBLIC, "instanceValue", "I", null, null).visitEnd();
        cw.visitField(ACC_PUBLIC, "longValue", "J", null, null).visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC, "mutableStatic", "I", null, null).visitEnd();

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "(IJ)V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitFieldInsn(PUTFIELD, FIELD_SUBJECT, "instanceValue", "I");
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(LLOAD, 2);
        mv.visitFieldInsn(PUTFIELD, FIELD_SUBJECT, "longValue", "J");
        mv.visitInsn(RETURN);
        mv.visitMaxs(3, 4);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "readStatic", "()I", null, null);
        mv.visitCode();
        mv.visitFieldInsn(GETSTATIC, FIELD_SUBJECT, "STATIC_VALUE", "I");
        mv.visitInsn(IRETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "readStaticLong", "()J", null, null);
        mv.visitCode();
        mv.visitFieldInsn(GETSTATIC, FIELD_SUBJECT, "STATIC_LONG", "J");
        mv.visitInsn(LRETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC, "readInstance", "()I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, FIELD_SUBJECT, "instanceValue", "I");
        mv.visitInsn(IRETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC, "readLong", "()J", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, FIELD_SUBJECT, "longValue", "J");
        mv.visitInsn(LRETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC, "touch", "(I)V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitFieldInsn(PUTFIELD, FIELD_SUBJECT, "instanceValue", "I");
        mv.visitVarInsn(ILOAD, 1);
        mv.visitFieldInsn(PUTSTATIC, FIELD_SUBJECT, "mutableStatic", "I");
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, "classLiteral", "()Ljava/lang/Class;",
                null, null);
        mv.visitCode();
        mv.visitLdcInsn(Type.getObjectType(FIELD_SUBJECT));
        mv.visitInsn(ARETURN);
        mv.visitMaxs(1, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] fieldBase() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_SUPER, BASE, null, OBJECT, null);
        cw.visitField(ACC_PUBLIC, "baseValue", "I", null, null).visitEnd();
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "(I)V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitFieldInsn(PUTFIELD, BASE, "baseValue", "I");
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] fieldSub() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, SUB, null, BASE, null);
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "(I)V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitMethodInsn(INVOKESPECIAL, BASE, "<init>", "(I)V", false);
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 2);
        mv.visitEnd();

        // FieldInsnNode owner is the subclass even though the field is declared in FieldBase.
        mv = cw.visitMethod(ACC_PUBLIC, "readInherited", "()I", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitFieldInsn(GETFIELD, SUB, "baseValue", "I");
        mv.visitInsn(IRETURN);
        mv.visitMaxs(1, 1);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    static byte[] primitiveFields() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SUPER, PRIMITIVE, null, OBJECT, null);
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "FLAG", "Z", null,
                Integer.valueOf(1)).visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "SMALL", "B", null,
                Integer.valueOf(5)).visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "LETTER", "C", null,
                Integer.valueOf('A')).visitEnd();
        cw.visitField(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "SHORT_VALUE", "S", null,
                Integer.valueOf(300)).visitEnd();
        cw.visitField(ACC_PUBLIC, "instanceFlag", "Z", null, null).visitEnd();

        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, OBJECT, "<init>", "()V", false);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitInsn(ICONST_1);
        mv.visitFieldInsn(PUTFIELD, PRIMITIVE, "instanceFlag", "Z");
        mv.visitInsn(RETURN);
        mv.visitMaxs(2, 1);
        mv.visitEnd();

        primitiveReader(cw, "readFlag", "Z", "FLAG", true);
        primitiveReader(cw, "readSmall", "B", "SMALL", true);
        primitiveReader(cw, "readLetter", "C", "LETTER", true);
        primitiveReader(cw, "readShort", "S", "SHORT_VALUE", true);
        primitiveReader(cw, "readInstanceFlag", "Z", "instanceFlag", false);

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void primitiveReader(ClassWriter cw, String methodName, String fieldDescriptor,
                                        String fieldName, boolean staticField) {
        MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | (staticField ? ACC_STATIC : 0),
                methodName, "()" + fieldDescriptor, null, null);
        mv.visitCode();
        if (staticField) {
            mv.visitFieldInsn(GETSTATIC, PRIMITIVE, fieldName, fieldDescriptor);
        } else {
            mv.visitVarInsn(ALOAD, 0);
            mv.visitFieldInsn(GETFIELD, PRIMITIVE, fieldName, fieldDescriptor);
        }
        mv.visitInsn(IRETURN);
        mv.visitMaxs(1, staticField ? 0 : 1);
        mv.visitEnd();
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] oneFieldTable(String owner, String name, String desc) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(buffer);
        out.writeInt(MemberIdRegistry.MEMBER_TABLE_MAGIC);
        out.writeInt(MemberIdRegistry.MEMBER_TABLE_VERSION);
        out.writeInt(1);
        out.writeByte(MemberIdRegistry.ENTRY_FIELD);
        out.writeLong(MemberIdRegistry.classId(owner));
        out.writeLong(MemberIdRegistry.memberId(owner, name, desc));
        writeUtf(out, owner);
        writeUtf(out, name);
        writeUtf(out, desc);
        out.flush();
        return buffer.toByteArray();
    }

    private static void writeUtf(DataOutputStream out, String value) throws Exception {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readUtf(DataInputStream in) throws Exception {
        byte[] bytes = new byte[in.readInt()];
        in.readFully(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static ClassNode readNode(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return node;
    }

    private static int invokeInt(Class<?> type, String name) throws Exception {
        return ((Number) type.getMethod(name).invoke(null)).intValue();
    }

    private static long invokeLong(Class<?> type, String name) throws Exception {
        return ((Number) type.getMethod(name).invoke(null)).longValue();
    }

    private static int invokeIntOn(Class<?> type, String name, Object target) throws Exception {
        return ((Number) type.getMethod(name).invoke(target)).intValue();
    }

    private static long invokeLongOn(Class<?> type, String name, Object target) throws Exception {
        return ((Number) type.getMethod(name).invoke(target)).longValue();
    }
}
