package dev.chimera.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Opt-in marker for M7 identifier obfuscation.
 *
 * <p>Put it on a <b>pure-logic</b> class to rename the class to an opaque name (for example
 * {@code DamageCalc} to {@code a$1}), or on a method to rename that method. The build fails when a
 * marked class/method touches runtime-remapped Minecraft/Fabric types, carries a Sponge Mixin
 * annotation, or is registered as a Fabric entrypoint/mixin class: renaming those breaks the mod
 * after Fabric's runtime remapping.</p>
 *
 * <p>Renaming is applied before all other transforms, so string encryption, native stubs and VM
 * programs all see the final names. The annotation itself is stripped from the output.</p>
 */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface ChimeraRename {
}
