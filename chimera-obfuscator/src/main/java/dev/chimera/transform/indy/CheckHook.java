package dev.chimera.transform.indy;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;

/**
 * M10: handle/link check invoked exactly once per invokedynamic call site at first linkage.
 *
 * <p>The bootstrap calls {@link #allow(LinkRequest)} after resolving the member but before the
 * {@link java.lang.invoke.CallSite} is installed. Returning {@code false} makes the bootstrap
 * throw {@link BootstrapMethodError}, i.e. fail-closed: a missing/negative check can never be
 * turned into a successful link.</p>
 */
public interface CheckHook {

    /**
     * Per-link request. {@code owner} is the resolved class for {@code classId}. Exactly one of
     * {@code method} (method kinds) and {@code field} (G3 field-read kinds) is non-null.
     * Implementations must not throw for normal negative decisions (throw only for unexpected
     * internal errors; the bootstrap still fails closed).
     */
    record LinkRequest(MethodHandles.Lookup caller,
                       String callSiteName,
                       MethodType callSiteType,
                       long classId,
                       long memberId,
                       int kind,
                       Class<?> owner,
                       Method method,
                       java.lang.reflect.Field field) {

        /** Backward-compatible method-only request (pre-G3 callers and tests). */
        public LinkRequest(MethodHandles.Lookup caller,
                           String callSiteName,
                           MethodType callSiteType,
                           long classId,
                           long memberId,
                           int kind,
                           Class<?> owner,
                           Method method) {
            this(caller, callSiteName, callSiteType, classId, memberId, kind, owner, method, null);
        }
    }

    /** Explicit allow (tests / offline tooling only). */
    CheckHook ALLOW = request -> true;

    /** Explicit deny. */
    CheckHook DENY = request -> false;

    boolean allow(LinkRequest request);
}
