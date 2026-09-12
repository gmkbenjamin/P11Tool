package p11tool.crypto;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.lang.reflect.Field;
import java.util.Locale;

/**
 * Resolve PKCS#11 mechanism symbolic names to numeric codes.
 */
public final class MechanismNames {

    private MechanismNames() {
    }

    public static long resolve(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("mechanism name is required");
        }
        String normalized = name.trim().toUpperCase(Locale.ROOT);
        if (normalized.startsWith("0X")) {
            return Long.parseUnsignedLong(normalized.substring(2), 16);
        }
        if (Character.isDigit(normalized.charAt(0))) {
            return Long.parseUnsignedLong(normalized);
        }
        String fieldName = normalized.startsWith("CKM_") ? normalized : "CKM_" + normalized;
        try {
            Field field = PKCS11Constants.class.getField(fieldName);
            return field.getLong(null);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalArgumentException("unknown mechanism: " + name, ex);
        }
    }
}
