package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a method whose numeric computations should be entangled with the runtime key state.
 * With a valid content key the instrumented arithmetic is exactly equivalent; without it the
 * results are poisoned (negative / overflow / NaN) instead of throwing an exception.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface ChimeraEntangle {
}
