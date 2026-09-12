package p11tool.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Locale;

/**
 * Key Check Value helpers (encrypt a block of zeros; take first 3 bytes).
 */
public final class Kcv {

    private Kcv() {
    }

    public static String compute(byte[] keyBytes, String keyType) {
        if (keyBytes == null) {
            throw new IllegalArgumentException("keyBytes must not be null");
        }
        if (keyType == null) {
            throw new IllegalArgumentException("keyType must not be null");
        }
        String type = keyType.toUpperCase(Locale.ROOT);
        try {
            byte[] data;
            String algorithm;
            String transformation;
            switch (type) {
                case "AES" -> {
                    data = new byte[16];
                    algorithm = "AES";
                    transformation = "AES/ECB/NoPadding";
                }
                case "DES" -> {
                    data = new byte[8];
                    algorithm = "DES";
                    transformation = "DES/ECB/NoPadding";
                }
                case "DES3", "3DES" -> {
                    data = new byte[8];
                    algorithm = "DESede";
                    transformation = "DESede/ECB/NoPadding";
                }
                default -> throw new IllegalArgumentException("unsupported key type for KCV: " + keyType);
            }
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(data);
            return Hex.encodeUpper(encrypted).substring(0, 6);
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("failed to compute KCV", ex);
        }
    }

    /**
     * Software XOR of three equal-length key components, returning the combined key.
     */
    public static byte[] xorCombine(byte[] key1, byte[] key2, byte[] key3) {
        if (key1 == null || key2 == null || key3 == null) {
            throw new IllegalArgumentException("key components must not be null");
        }
        if (key1.length != key2.length || key1.length != key3.length) {
            throw new IllegalArgumentException("key components must have equal length");
        }
        byte[] combined = new byte[key1.length];
        for (int i = 0; i < key1.length; i++) {
            combined[i] = (byte) (key1[i] ^ key2[i] ^ key3[i]);
        }
        return combined;
    }
}
