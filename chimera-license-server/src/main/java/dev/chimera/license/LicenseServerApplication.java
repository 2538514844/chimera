package dev.chimera.license;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Chimera license server entry point.
 *
 * <p>{@code @EnableScheduling} drives {@link dev.chimera.license.service.SessionReaper}, which keeps
 * the v4 replay tables from growing without bound (red team round 4).</p>
 */
@SpringBootApplication
@EnableScheduling
public class LicenseServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(LicenseServerApplication.class, args);
    }
}
