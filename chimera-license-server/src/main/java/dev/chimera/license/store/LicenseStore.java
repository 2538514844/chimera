package dev.chimera.license.store;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** JDBC persistence for accounts, devices, sessions and audit events. */
@Repository
public class LicenseStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;

    public LicenseStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record AccountRow(long id, String account, String passwordHash, String status,
                             String licenseId) {
    }


    public Optional<AccountRow> findAccount(String account) {
        List<AccountRow> rows = jdbc.query(
                "SELECT id, account, password_hash, status, license_id FROM accounts WHERE account = ?",
                (rs, rowNum) -> new AccountRow(rs.getLong("id"), rs.getString("account"),
                        rs.getString("password_hash"), rs.getString("status"),
                        rs.getString("license_id")),
                account);
        return rows.stream().findFirst();
    }

    public Optional<AccountRow> findAccountById(long id) {
        List<AccountRow> rows = jdbc.query(
                "SELECT id, account, password_hash, status, license_id FROM accounts WHERE id = ?",
                (rs, rowNum) -> new AccountRow(rs.getLong("id"), rs.getString("account"),
                        rs.getString("password_hash"), rs.getString("status"),
                        rs.getString("license_id")),
                id);
        return rows.stream().findFirst();
    }

    public void insertAccount(String account, String passwordHash, String status) {
        jdbc.update("INSERT INTO accounts(account, password_hash, status, created_at) VALUES (?,?,?,?)",
                account, passwordHash, status, Timestamp.from(Instant.now()));
    }

    public int updateAccountStatus(String account, String status) {
        return jdbc.update("UPDATE accounts SET status = ? WHERE account = ?", status, account);
    }

    public List<AccountRow> listAccounts() {
        return jdbc.query("SELECT id, account, password_hash, status, license_id FROM accounts ORDER BY id",
                (rs, rowNum) -> new AccountRow(rs.getLong("id"), rs.getString("account"),
                        rs.getString("password_hash"), rs.getString("status"),
                        rs.getString("license_id")));
    }

    /**
     * Returns the account's stable licence identifier, generating and persisting one on first use.
     *
     * <p>The value is what the client receives (signed, see {@code AuthTranscriptV4}) and what the
     * per-licence watermark embeds, so it must be stable for the lifetime of the account and must
     * not be derivable from the account name (that would let anyone compute somebody else's id).
     * Generation is a single {@code UPDATE ... WHERE license_id IS NULL}, so two concurrent
     * activations cannot end up with different ids: the loser re-reads the winner's value.</p>
     */
    public String ensureLicenseId(long accountId) {
        String current = readLicenseId(accountId);
        if (current != null && !current.isBlank()) {
            return current;
        }
        String candidate = newLicenseId();
        jdbc.update("UPDATE accounts SET license_id = ? WHERE id = ? AND license_id IS NULL",
                candidate, accountId);
        String stored = readLicenseId(accountId);
        return stored == null || stored.isBlank() ? candidate : stored;
    }

    private String readLicenseId(long accountId) {
        List<String> rows = jdbc.queryForList("SELECT license_id FROM accounts WHERE id = ?",
                String.class, accountId);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private static String newLicenseId() {
        byte[] raw = new byte[8];
        RANDOM.nextBytes(raw);
        StringBuilder out = new StringBuilder("CHM-");
        for (byte value : raw) {
            out.append(Character.forDigit((value >>> 4) & 0xf, 16))
                    .append(Character.forDigit(value & 0xf, 16));
        }
        return out.toString().toUpperCase(java.util.Locale.ROOT);
    }

    /** Revokes every live v4 session of an account. v3 was removed, so there is only one table. */
    public int revokeSessions(long accountId) {
        return jdbc.update(
                "UPDATE auth_v4_sessions SET revoked = TRUE WHERE account_id = ? AND revoked = FALSE",
                accountId);
    }

    public List<String> devices(long accountId) {
        return jdbc.queryForList("SELECT hwid FROM devices WHERE account_id = ? AND status = 'ACTIVE'",
                String.class, accountId);
    }

    public int deviceCount(long accountId) {
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM devices WHERE account_id = ?",
                Integer.class, accountId);
        return count == null ? 0 : count;
    }

    public void bindDevice(long accountId, String hwid, Instant now) {
        jdbc.update("INSERT INTO devices(account_id, hwid, label, first_seen, last_seen, status) "
                        + "VALUES (?,?,?,?,?,'ACTIVE')",
                accountId, hwid, "auto", Timestamp.from(now), Timestamp.from(now));
    }

    /**
     * Binds a device together with the public half of its DPAPI-sealed key.
     *
     * <p>Red team round 3, finding 3: {@code hwid} is a client-written string, so binding on it
     * alone means anyone who learns a customer's 64 hex can activate on another machine. The
     * private half of {@code devicePub} never leaves that machine in usable form, so the pair is
     * the identity and the string is only a label.</p>
     */
    public void bindDevice(long accountId, String hwid, byte[] devicePub, Instant now) {
        jdbc.update("INSERT INTO devices(account_id, hwid, label, first_seen, last_seen, status, "
                        + "device_pub) VALUES (?,?,?,?,?,'ACTIVE',?)",
                accountId, hwid, "auto", Timestamp.from(now), Timestamp.from(now), devicePub);
    }

    public void touchDevice(long accountId, String hwid, Instant now) {
        jdbc.update("UPDATE devices SET last_seen = ? WHERE account_id = ? AND hwid = ?",
                Timestamp.from(now), accountId, hwid);
    }

    /**
     * The bound device key for {@code (account, hwid)}, or {@code null} when the row predates the
     * column (migration: the next activation adopts the key it is presented).
     */
    public byte[] devicePub(long accountId, String hwid) {
        List<byte[]> found = jdbc.queryForList(
                "SELECT device_pub FROM devices WHERE account_id = ? AND hwid = ? AND status = 'ACTIVE'",
                byte[].class, accountId, hwid);
        return found.isEmpty() ? null : found.get(0);
    }

    /** Adopts the presented key for a row created before {@code device_pub} existed. */
    public void adoptDevicePub(long accountId, String hwid, byte[] devicePub) {
        jdbc.update("UPDATE devices SET device_pub = ? WHERE account_id = ? AND hwid = ? "
                        + "AND device_pub IS NULL",
                devicePub, accountId, hwid);
    }

    /** Operator action: clears the key so the next activation on that machine re-adopts it. */
    public int clearDevicePubs(long accountId) {
        return jdbc.update("UPDATE devices SET device_pub = NULL WHERE account_id = ?", accountId);
    }



    public void audit(Long accountId, String event, String hwidHash, String ipHash) {
        jdbc.update("INSERT INTO audit_logs(account_id, event, hwid_hash, ip_hash, created_at) VALUES (?,?,?,?,?)",
                accountId, event, hwidHash, ipHash, Timestamp.from(Instant.now()));
    }

    /** Test/maintenance helper: unlink all devices of an account. */
    public int deleteDevices(long accountId) {
        return jdbc.update("DELETE FROM devices WHERE account_id = ?", accountId);
    }

    // ------------------------------------------------------- onboarding: pre-registered HWID slots

    public record ReservationRow(String hwid, String note, Long claimedAccountId) {
    }

    /** Operator adds a hardware slot; idempotent so a double paste does not fail. */
    public void reserveHwid(String hwid, String note) {
        jdbc.update("MERGE INTO hwid_reservations(hwid, note, created_at) KEY(hwid) VALUES (?,?,?)",
                hwid, note, Timestamp.from(Instant.now()));
    }

    public Optional<ReservationRow> findReservation(String hwid) {
        List<ReservationRow> rows = jdbc.query(
                "SELECT hwid, note, claimed_account_id FROM hwid_reservations WHERE hwid = ?",
                (rs, rowNum) -> toReservation(rs),
                hwid);
        return rows.stream().findFirst();
    }

    /**
     * Claims a reservation for exactly one account.
     *
     * <p>{@code WHERE claimed_account_id IS NULL} is the concurrency guard: two registrations that
     * present the same HWID race here, and only one gets {@code 1} back. Callers must run this in a
     * transaction with the account insert so the loser leaves no orphan account behind.</p>
     */
    public int claimReservation(String hwid, long accountId, Instant now) {
        return jdbc.update(
                "UPDATE hwid_reservations SET claimed_account_id = ?, claimed_at = ? "
                        + "WHERE hwid = ? AND claimed_account_id IS NULL",
                accountId, Timestamp.from(now), hwid);
    }

    public List<ReservationRow> listReservations() {
        return jdbc.query("SELECT hwid, note, claimed_account_id FROM hwid_reservations "
                        + "ORDER BY created_at",
                (rs, rowNum) -> toReservation(rs));
    }


    /**
     * Maps one reservation row.
     *
     * <p>{@code wasNull()} reports the status of the <b>most recently read</b> column, so it has to
     * be captured immediately after the nullable read. Reading {@code hwid}/{@code note} first made
     * every unclaimed slot look claimed (found by OnboardingApiTest: a fresh reservation already
     * answered 409).</p>
     */
    private static ReservationRow toReservation(java.sql.ResultSet rs) throws java.sql.SQLException {
        long claimedValue = rs.getLong("claimed_account_id");
        Long claimed = rs.wasNull() ? null : claimedValue;
        return new ReservationRow(rs.getString("hwid"), rs.getString("note"), claimed);
    }

    public int deleteReservation(String hwid) {
        return jdbc.update("DELETE FROM hwid_reservations WHERE hwid = ?", hwid);
    }
}
