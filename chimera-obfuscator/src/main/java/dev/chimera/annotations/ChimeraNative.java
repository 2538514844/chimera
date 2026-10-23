package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marks a pure-computation method that should be sunk into JNI. */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface ChimeraNative {
    /** Logical implementation name, used for the generated C++ template. */
    String value() default "";
}
