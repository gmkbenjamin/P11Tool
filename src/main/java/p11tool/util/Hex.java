package p11tool.util;

import java.util.HexFormat;
import java.util.Locale;

/**
 * Hex encoding helpers used across PKCS#11 attribute and key material paths.
 */
public final class Hex {

    private static final HexFormat FORMAT = HexFormat.of();

    private Hex() {
    }

    public static byte[] decode(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string must not be null");
        }
        String cleaned = hex.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            return new byte[0];
        }
        if ((cleaned.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must have even length");
        }
        try {
            return FORMAT.parseHex(cleaned);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("invalid hex string", ex);
        }
    }

    public static String encode(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes must not be null");
        }
        return FORMAT.formatHex(bytes);
    }

    public static String encodeUpper(byte[] bytes) {
        return encode(bytes).toUpperCase(Locale.ROOT);
    }
}
