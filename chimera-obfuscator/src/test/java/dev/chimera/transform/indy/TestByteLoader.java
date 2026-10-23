package dev.chimera.transform.indy;

import java.util.Map;

/** Minimal isolating class loader for ASM-generated fixtures (parent = test/runtime classes). */
final class TestByteLoader extends ClassLoader {

    private final Map<String, byte[]> classes;

    TestByteLoader(Map<String, byte[]> classes, ClassLoader parent) {
        super(parent);
        this.classes = classes;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = classes.get(name.replace('.', '/'));
        if (bytes == null) {
            throw new ClassNotFoundException(name);
        }
        return defineClass(name, bytes, 0, bytes.length);
    }
}
