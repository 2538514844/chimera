package dev.chimera.license.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** Maps protocol errors to stable error codes; never leaks stack traces or account existence. */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(LicenseException.class)
    public ResponseEntity<ApiModels.ErrorResponse> handleLicense(LicenseException error) {
        return ResponseEntity.status(error.status()).body(new ApiModels.ErrorResponse(error.code()));
    }

    /**
     * An unmapped path (for example the removed v3 {@code /activate} and {@code /heartbeat}) is a
     * missing resource, not a server failure: report 404 instead of masking it as E_INTERNAL.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiModels.ErrorResponse> handleNoResource(NoResourceFoundException error) {
        return ResponseEntity.status(404).body(new ApiModels.ErrorResponse("E_NOT_FOUND"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiModels.ErrorResponse> handleUnexpected(Exception error) {
        LOG.error("unexpected license server error", error);
        return ResponseEntity.status(500).body(new ApiModels.ErrorResponse("E_INTERNAL"));
    }
}
