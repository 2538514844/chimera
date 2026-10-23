package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a mod entry method that must run the full Chimera pre-game pipeline before the player
 * joins a world: runtime integrity self-check, Java/native anti-debug signals, license
 * activation (native Ed25519/X25519 unwrap). On failure it never throws or shows a dialog; the
 * runtime is poisoned so in-game values become negative/NaN.
 *
 * <p>Since M7 the build injects the check automatically at the start of every annotated method:
 * {@code if (!ChimeraRuntime.preGameCheckWithFallback(account, password, hwid)) return;}. On
 * failure the method returns immediately with a type-neutral default ({@code 0}/{@code null}).
 * Credentials default to the system properties {@code chimera.account}, {@code chimera.password}
 * and {@code chimera.hwid} when the annotation attributes are empty.</p>
 *
 * <p>Recommended call site: Fabric {@code ClientPlayConnectionEvents.JOIN} (or the loader's
 * equivalent), before world/entity logic runs.</p>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ChimeraPreGameCheck {
    /** Account passed to the license server; empty means the {@code chimera.account} property. */
    String account() default "";

    /** Password passed to the license server; empty means the {@code chimera.password} property. */
    String password() default "";

    /** Hardware id passed to the license server; empty means the {@code chimera.hwid} property. */
    String hwid() default "";
}
