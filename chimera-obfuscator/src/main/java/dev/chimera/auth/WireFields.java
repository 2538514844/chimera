package dev.chimera.auth;

import java.util.Map;

/** Small helpers for parsing flat JSON-object field maps without a third-party JSON library. */
final class WireFields {

    private WireFields() {
    }

    static String text(Map<String, String> fields, String name) throws AuthProtocolException {
        String value = fields == null ? null : fields.get(name);
        if (value == null) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE, "missing response field: " + name);
        }
        return value;
    }

    static int integer(Map<String, String> fields, String name) throws AuthProtocolException {
        String value = text(fields, name);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE,
                    "field is not an integer: " + name);
        }
    }

    static long number(Map<String, String> fields, String name) throws AuthProtocolException {
        String value = text(fields, name);
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0) {
                throw new NumberFormatException("negative");
            }
            return parsed;
        } catch (NumberFormatException e) {
            throw new AuthProtocolException(AuthFailure.BAD_RESPONSE,
                    "field is not a number: " + name);
        }
    }
}
