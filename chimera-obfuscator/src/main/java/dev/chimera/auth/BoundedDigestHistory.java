package dev.chimera.auth;

import dev.chimera.crypto.Crypto;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded, thread-safe history of SHA-256 digests used to detect replayed server nonces/tokens.
 * Oldest entries are evicted when the limit is exceeded; eviction only weakens replay detection
 * for very old messages, which are also rejected by the persisted monotonic sequence.
 */
public final class BoundedDigestHistory {

    private final int limit;
    private final Map<String, Boolean> seen = new LinkedHashMap<>();

    public BoundedDigestHistory(int limit) {
        if (limit < 1 || limit > 65_536) {
            throw new IllegalArgumentException("history limit out of range: " + limit);
        }
        this.limit = limit;
    }

    /** @return true when the digest was not present (and is now remembered) */
    public synchronized boolean add(byte[] digest) {
        String key = Crypto.hex(requireDigest(digest));
        if (seen.containsKey(key)) {
            return false;
        }
        seen.put(key, Boolean.TRUE);
        if (seen.size() > limit) {
            Iterator<String> iterator = seen.keySet().iterator();
            iterator.next();
            iterator.remove();
        }
        return true;
    }

    public synchronized boolean contains(byte[] digest) {
        return seen.containsKey(Crypto.hex(requireDigest(digest)));
    }

    public synchronized void clear() {
        seen.clear();
    }

    private static byte[] requireDigest(byte[] digest) {
        if (digest == null || digest.length == 0) {
            throw new IllegalArgumentException("digest must not be empty");
        }
        return digest;
    }
}
