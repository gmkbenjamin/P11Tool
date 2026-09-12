package p11tool.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * Minimal PEM encode/decode helpers.
 */
public final class Pem {

    private Pem() {
    }

    public static byte[] decodePublicKey(String pemOrBase64) {
        if (pemOrBase64 == null) {
            throw new IllegalArgumentException("PEM input must not be null");
        }
        String normalized = pemOrBase64
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(normalized);
    }

    public static String encodePublicKey(byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
    }

    public static String encodeBlock(String label, byte[] data) {
        String upper = label.toUpperCase(Locale.ROOT);
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(data);
        return "-----BEGIN " + upper + "-----\n" + body + "\n-----END " + upper + "-----\n";
    }
}
