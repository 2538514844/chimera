package dev.chimera.runtime;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.Locale;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;

/**
 * G7: activation window shown by {@link ChimeraPreLaunch} before Minecraft loads.
 *
 * <p>Deliberately depends only on {@code java.*}/{@code javax.swing.*}: it runs before the game
 * class loader has remapped or transformed anything, so referencing Minecraft classes here would
 * break the launch. All text is plain UI copy (no secrets).</p>
 */
public final class ChimeraActivationPanel {

    /** License activation backend. The v4 client wiring supplies the real implementation. */
    public interface Activator {
        ActivationResult activate(String account, char[] password, String hwid);

        /**
         * Self-service registration against a pre-registered HWID.
         *
         * @return {@code null} on success, otherwise a player-facing message
         */
        default String register(String account, char[] password, String hwid) {
            return "this build does not support self-registration";
        }
    }

    /** Result codes mirror the v4 protocol failure codes. */
    public enum Status {
        ACTIVATED,
        E_NETWORK,
        E_EXPIRED,
        E_CLOCK_ROLLBACK,
        E_HWID,
        E_CREDENTIALS,
        E_STATE,
        E_SIGNATURE,
        // Account banned, session revoked, or the account no longer exists. Terminal: retrying with
        // the same credentials cannot help, so it must not look like a network problem.
        E_REVOKED,
        // The server answered and refused, but with a code this build does not recognise. Also not a
        // network problem - "check your connection" sent users chasing the wrong thing.
        E_REJECTED,
        E_NOT_IMPLEMENTED
    }

    public record ActivationResult(Status status, String detail, long expiresAtEpochSeconds,
                                   String licenseTag) {
        public static ActivationResult ok(long expiresAt, String licenseTag) {
            return new ActivationResult(Status.ACTIVATED, "", expiresAt, licenseTag);
        }

        public static ActivationResult fail(Status status, String detail) {
            return new ActivationResult(status, detail, 0L, "");
        }

        public boolean activated() {
            return status == Status.ACTIVATED;
        }
    }

    private final Activator activator;
    private final String hwid;
    private volatile ActivationResult result;

    public ChimeraActivationPanel(Activator activator, String hwid) {
        this.activator = activator;
        this.hwid = hwid == null ? "" : hwid;
    }

    /** Draws the blocking dialog and returns the activation result (never null). */
    public ActivationResult showBlocking() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            return ActivationResult.fail(Status.E_STATE, "graphics unavailable");
        }
        SwingUtilities.invokeLater(() -> { });
        JFrame frame = new JFrame("Chimera — Activation");
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.setResizable(false);
        frame.setLayout(new BorderLayout(8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(12, 16, 4, 16));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;

        JTextField account = new JTextField(24);
        JPasswordField password = new JPasswordField(24);
        JTextField hwidField = new JTextField(hwid, 24);
        hwidField.setEditable(false);
        JLabel status = new JLabel("");

        addRow(form, c, 0, "Account", account);
        addRow(form, c, 1, "Password", password);
        addRow(form, c, 2, "HWID", hwidField);
        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 2;
        form.add(status, c);

        JButton activate = new JButton("Activate");
        JButton register = new JButton("Register");
        JButton exit = new JButton("Exit");
        JPanel buttons = new JPanel();
        buttons.add(activate);
        buttons.add(register);
        buttons.add(exit);

        // Onboarding: the operator reserved this machine's HWID; the player picks their own account
        // name and password here, then the normal activation path runs with the same credentials.
        register.addActionListener((ActionEvent event) -> {
            register.setEnabled(false);
            activate.setEnabled(false);
            status.setText("Registering...");
            char[] secret = password.getPassword();
            String failure;
            try {
                failure = activator == null ? "no activation backend"
                        : activator.register(account.getText().trim(), secret, hwid);
            } catch (RuntimeException error) {
                failure = String.valueOf(error.getMessage());
            } finally {
                Arrays.fill(secret, '\0');
            }
            if (failure != null) {
                status.setText(failure);
                register.setEnabled(true);
                activate.setEnabled(true);
                return;
            }
            status.setText("Registered - activating...");
            activate.setEnabled(true);
            activate.doClick();
        });

        final String[] errorCopy = new String[1];
        activate.addActionListener((ActionEvent event) -> {
            activate.setEnabled(false);
            status.setText("Activating...");
            char[] secret = password.getPassword();
            ActivationResult outcome;
            try {
                outcome = activator == null
                        ? ActivationResult.fail(Status.E_NOT_IMPLEMENTED, "no activation backend")
                        : activator.activate(account.getText().trim(), secret, hwid);
            } catch (RuntimeException failure) {
                outcome = ActivationResult.fail(Status.E_NETWORK, String.valueOf(failure.getMessage()));
            } finally {
                Arrays.fill(secret, '\0');
            }
            result = outcome;
            if (outcome.activated()) {
                frame.dispose();
                return;
            }
            errorCopy[0] = describe(outcome);
            status.setText(errorCopy[0]);
            password.setText("");
            activate.setEnabled(true);
        });
        exit.addActionListener(event -> {
            if (JOptionPane.showConfirmDialog(frame,
                    "Exit without activation? The game will not start.", "Exit",
                    JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                result = ActivationResult.fail(Status.E_STATE, "cancelled by user");
                frame.dispose();
            }
        });

        frame.add(form, BorderLayout.CENTER);
        frame.add(buttons, BorderLayout.SOUTH);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        try {
            while (frame.isDisplayable() && (result == null || !result.activated())) {
                Thread.sleep(100L);
                if (!frame.isDisplayable()) {
                    break;
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            if (frame.isDisplayable()) {
                frame.dispose();
            }
        }
        return result == null ? ActivationResult.fail(Status.E_STATE, "cancelled") : result;
    }

    private static void addRow(JPanel form, GridBagConstraints c, int row, String label,
                               java.awt.Component field) {
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 1;
        form.add(new JLabel(label), c);
        c.gridx = 1;
        form.add(field, c);
    }

    /** Maps a failure to the user-visible copy (stable codes are kept for support). */
    public static String describe(ActivationResult result) {
        Status status = result == null ? Status.E_STATE : result.status();
        String code = status.name();
        String message = switch (status) {
            case ACTIVATED -> "Activated.";
            case E_NETWORK -> "Cannot reach the license server. Check your connection and retry.";
            case E_EXPIRED -> "This license has expired. Renew it to continue.";
            case E_CLOCK_ROLLBACK -> "System clock is incorrect. Fix the date/time and retry.";
            case E_HWID -> "This license is bound to a different machine.";
            case E_CREDENTIALS -> "Wrong account or password.";
            case E_REVOKED -> "This account is banned or its session was revoked. Contact support.";
            case E_REJECTED -> "The server rejected this request. Contact support.";
            case E_STATE -> "Local authorization state is damaged. Contact support.";
            case E_SIGNATURE -> "Server response failed verification. Contact support.";
            case E_NOT_IMPLEMENTED -> "Activation backend is not wired in this build.";
        };
        return String.format(Locale.ROOT, "%s — %s", code, message);
    }

    /** Test hook: activation result recorded by the last dialog run. */
    ActivationResult lastResult() {
        return result;
    }
}
