package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method whose Java bytecode is virtualized into a custom instruction stream executed by
 * {@code ChimeraVmRuntime}. The original bytecode never reaches the JVM.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface ChimeraVM {
}
