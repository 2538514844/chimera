package dev.chimera.transform.mixinsupport;

/**
 * Fail-closed failure raised by {@link MixinSupport}.
 *
 * <p>Mixin metadata is compiled into the mod: a half-rewritten mixin config or refmap turns a
 * working jar into one that crashes during Mixin bootstrap. {@link MixinSupport} therefore never
 * returns a partially rewritten result. Any malformed mixin config, referenced refmap or
 * unreadable class aborts the whole pre-pass with this exception; the input maps are never
 * mutated, so the caller can safely fail the build.</p>
 */
public final class MixinSupportException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MixinSupportException(String message) {
        super(message);
    }

    public MixinSupportException(String message, Throwable cause) {
        super(message, cause);
    }
}
