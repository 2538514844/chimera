package dev.chimera.license.config;

import dev.chimera.license.crypto.CryptoUtils;
import dev.chimera.license.store.LicenseStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/** Optional development seed account: CHIMERA_SEED_ACCOUNT / CHIMERA_SEED_PASSWORD. */
@Component
public class DemoAccountInitializer implements CommandLineRunner {

    private static final Logger LOG = LoggerFactory.getLogger(DemoAccountInitializer.class);

    private final LicenseStore store;
    private final String seedAccount;
    private final String seedPassword;

    public DemoAccountInitializer(LicenseStore store,
                                  @Value("${CHIMERA_SEED_ACCOUNT:}") String seedAccount,
                                  @Value("${CHIMERA_SEED_PASSWORD:}") String seedPassword) {
        this.store = store;
        this.seedAccount = seedAccount;
        this.seedPassword = seedPassword;
    }

    @Override
    public void run(String... args) {
        if (seedAccount == null || seedAccount.isBlank()
                || seedPassword == null || seedPassword.isBlank()) {
            return;
        }
        if (store.findAccount(seedAccount.trim()).isPresent()) {
            return;
        }
        store.insertAccount(seedAccount.trim(), CryptoUtils.hashPassword(seedPassword), "ACTIVE");
        LOG.info("seeded development account: {}", seedAccount.trim());
    }
}
