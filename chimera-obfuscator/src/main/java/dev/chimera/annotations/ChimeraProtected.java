package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marks a method whose bytecode should be extracted, encrypted and loaded as a hidden class. */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface ChimeraProtected {
}
