package dev.chimera.auth;

import java.io.IOException;
import java.util.Optional;

/**
 * Persistence for the monotonic v4 sequence/state. Implementations must be tamper-evident:
 * a corrupted or rolled-back state must fail closed rather than silently reset replay counters.
 */
public interface SequenceStore {

    Optional<SequenceState> load() throws IOException;

    void save(SequenceState state) throws IOException;

    void clear() throws IOException;
}
