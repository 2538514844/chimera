package dev.chimera.auth;

import java.io.IOException;
import java.util.Optional;

/** Test sequence store with failure injection. */
final class InMemorySequenceStore implements SequenceStore {

    private SequenceState state;
    boolean failOnLoad;
    boolean failOnSave;

    @Override
    public Optional<SequenceState> load() throws IOException {
        if (failOnLoad) {
            throw new IOException("injected load failure");
        }
        return Optional.ofNullable(state);
    }

    @Override
    public void save(SequenceState state) throws IOException {
        if (failOnSave) {
            throw new IOException("injected save failure");
        }
        this.state = state;
    }

    @Override
    public void clear() {
        this.state = null;
    }

    SequenceState state() {
        return state;
    }

    void setState(SequenceState state) {
        this.state = state;
    }
}
