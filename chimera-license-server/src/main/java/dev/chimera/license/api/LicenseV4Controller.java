package dev.chimera.license.api;

import dev.chimera.license.service.LicenseV4Service;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * License protocol v4 endpoints. v3 ({@code /api/v1/license/activate|heartbeat}) is untouched.
 *
 * <p>v4 signs a binary {@code u32be(len)||UTF-8} transcript (domain first, decimal version second)
 * instead of the v3 JSON canonical string; see
 * {@link dev.chimera.license.crypto.AuthTranscriptV4}.</p>
 */
@RestController
@RequestMapping("/api/v1/license/v4")
public class LicenseV4Controller {

    private final LicenseV4Service service;

    public LicenseV4Controller(LicenseV4Service service) {
        this.service = service;
    }

    @PostMapping("/activate")
    public ApiModels.ActivateV4Response activate(@RequestBody ApiModels.ActivateV4Request request,
                                                 HttpServletRequest http) {
        return service.activate(request, http.getRemoteAddr());
    }

    @PostMapping("/heartbeat")
    public ApiModels.HeartbeatV4Response heartbeat(@RequestBody ApiModels.HeartbeatV4Request request,
                                                   HttpServletRequest http) {
        return service.heartbeat(request, http.getRemoteAddr());
    }
}
