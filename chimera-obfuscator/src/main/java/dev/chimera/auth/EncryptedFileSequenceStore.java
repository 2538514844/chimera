package dev.chimera.auth;

import dev.chimera.crypto.Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * AES-256-GCM protected sequence store.
 *
 * <p>Files under the configured directory:</p>
 * <ul>
 *   <li>{@code auth-seq.key} — 32B random state key (generated once, chmod 600 best effort);</li>
 *   <li>{@code auth-seq.bin} — {@code "CHSQ1" || 12B nonce || AES-GCM(plaintext, aad)}.</li>
 * </ul>
 *
 * <p>Plaintext = version, account, hwid, sequence, issued_at, SHA-256(token), SHA-256(server_nonce).
 * A copied older state file is still accepted (local rollback cannot be prevented without a server
 * anchor); any bit flip is rejected.</p>
 */
public final class EncryptedFileSequenceStore implements SequenceStore {

    private static final byte[] MAGIC = "CHSQ1".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] FILE_AAD =
            "chimera/auth/sequence/v1".getBytes(StandardCharsets.UTF_8);
    private static final int KEY_BYTES = 32;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final int MAX_TEXT_BYTES = 1024;

    private final Path directory;
    private final Path keyFile;
    private final Path stateFile;
    private final byte[] key;

    public EncryptedFileSequenceStore(Path directory) throws IOException {
        if (directory == null) {
            throw new IllegalArgumentException("directory must not be null");
        }
        this.directory = directory.toAbsolutePath();
        Files.createDirectories(this.directory);
        this.keyFile = this.directory.resolve("auth-seq.key");
        this.stateFile = this.directory.resolve("auth-seq.bin");
        this.key = loadOrCreateKey();
    }

    @Override
    public Optional<SequenceState> load() throws IOException {
        if (!Files.exists(stateFile)) {
            return Optional.empty();
        }
        byte[] blob = Files.readAllBytes(stateFile);
        int minimum = MAGIC.length + GCM_NONCE_BYTES + GCM_TAG_BYTES;
        if (blob.length < minimum) {
            throw new SequenceStoreException("sequence state file is truncated");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                throw new SequenceStoreException("sequence state file has invalid magic");
            }
        }
        byte[] nonce = Arrays.copyOfRange(blob, MAGIC.length, MAGIC.length + GCM_NONCE_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(blob, MAGIC.length + GCM_NONCE_BYTES, blob.length);
        byte[] plaintext;
        try {
            plaintext = Crypto.aesGcmDecrypt(key, nonce, ciphertext, FILE_AAD);
        } catch (RuntimeException e) {
            throw new SequenceStoreException("sequence state authentication failed", e);
        }
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            int version = in.readInt();
            if (version != SequenceState.VERSION) {
                throw new SequenceStoreException("unsupported sequence state version: " + version);
            }
            String account = readText(in);
            String hwid = readText(in);
            long sequence = in.readLong();
            long issuedAt = in.readLong();
            byte[] tokenHash = readFixed(in, 32);
            byte[] serverNonceHash = readFixed(in, 32);
            if (in.available() != 0) {
                throw new SequenceStoreException("trailing bytes in sequence state");
            }
            try {
                return Optional.of(new SequenceState(version, account, hwid, sequence, issuedAt,
                        tokenHash, serverNonceHash));
            } catch (IllegalArgumentException e) {
                throw new SequenceStoreException("invalid sequence state contents", e);
            }
        }
    }

    @Override
    public void save(SequenceState state) throws IOException {
        if (state == null) {
            throw new IllegalArgumentException("state must not be null");
        }
        byte[] plaintext = serialize(state);
        byte[] nonce = Crypto.random(GCM_NONCE_BYTES);
        byte[] ciphertext = Crypto.aesGcmEncrypt(key, nonce, plaintext, FILE_AAD);
        ByteArrayOutputStream blob = new ByteArrayOutputStream(MAGIC.length + nonce.length + ciphertext.length);
        blob.writeBytes(MAGIC);
        blob.writeBytes(nonce);
        blob.writeBytes(ciphertext);
        Path temp = Files.createTempFile(directory, "auth-seq", ".tmp");
        try {
            Files.write(temp, blob.toByteArray(), StandardOpenOption.TRUNCATE_EXISTING);
            restrict(temp);
            try {
                Files.move(temp, stateFile, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, stateFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    @Override
    public void clear() throws IOException {
        Files.deleteIfExists(stateFile);
    }

    private static byte[] serialize(SequenceState state) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(256);
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.writeInt(state.version());
            writeText(out, state.account());
            writeText(out, state.hwid());
            out.writeLong(state.sequence());
            out.writeLong(state.issuedAt());
            out.write(state.tokenHash());
            out.write(state.serverNonceHash());
        }
        return buffer.toByteArray();
    }

    private byte[] loadOrCreateKey() throws IOException {
        if (Files.exists(keyFile)) {
            byte[] existing = Files.readAllBytes(keyFile);
            if (existing.length != KEY_BYTES) {
                throw new SequenceStoreException("sequence key file must be 32 bytes");
            }
            return existing;
        }
        byte[] generated = Crypto.random(KEY_BYTES);
        Files.write(keyFile, generated, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        restrict(keyFile);
        return generated;
    }

    private static void writeText(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static String readText(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_TEXT_BYTES) {
            throw new SequenceStoreException("invalid text length in sequence state: " + length);
        }
        byte[] bytes = readFixed(in, length);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] readFixed(DataInputStream in, int length) throws IOException {
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static void restrict(Path file) {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows / non-POSIX: best effort only
        }
    }
}
