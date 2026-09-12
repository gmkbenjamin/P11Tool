package p11tool.crypto;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Encrypt / decrypt / sign / verify using token keys.
 */
public final class CryptoOperations {

    private CryptoOperations() {
    }

    public static byte[] encrypt(PKCS11 p11, long session, String keyLabel, byte[] plaintext, String keyTypeHint,
                                 String mechanismOverride) throws PKCS11Exception {
        long key = Pkcs11Support.requireOneByLabel(p11, session, keyLabel);
        long mechanism = resolveEncryptMechanism(p11, session, key, keyTypeHint, mechanismOverride);
        byte[] iv = ivFor(mechanism);
        CK_MECHANISM mech = iv == null ? new CK_MECHANISM(mechanism) : new CK_MECHANISM(mechanism, iv);
        p11.C_EncryptInit(session, mech, key);
        byte[] out = new byte[plaintext.length + 64];
        int written = p11.C_Encrypt(session, 0L, plaintext, 0, plaintext.length, 0L, out, 0, out.length);
        return trim(out, written);
    }

    public static byte[] decrypt(PKCS11 p11, long session, String keyLabel, byte[] ciphertext, String keyTypeHint,
                                 String mechanismOverride) throws PKCS11Exception {
        long key = Pkcs11Support.requireOneByLabel(p11, session, keyLabel);
        long mechanism = resolveEncryptMechanism(p11, session, key, keyTypeHint, mechanismOverride);
        byte[] iv = ivFor(mechanism);
        CK_MECHANISM mech = iv == null ? new CK_MECHANISM(mechanism) : new CK_MECHANISM(mechanism, iv);
        p11.C_DecryptInit(session, mech, key);
        byte[] out = new byte[ciphertext.length + 64];
        int written = p11.C_Decrypt(session, 0L, ciphertext, 0, ciphertext.length, 0L, out, 0, out.length);
        return trim(out, written);
    }

    public static byte[] sign(PKCS11 p11, long session, String keyLabel, byte[] data, String keyTypeHint,
                              String mechanismOverride) throws PKCS11Exception {
        long key = Pkcs11Support.requireOneByLabel(p11, session, keyLabel);
        SignPlan plan = resolveSignPlan(p11, session, key, keyTypeHint, mechanismOverride);
        byte[] toSign = plan.hashInSoftware ? sha256(data) : data;
        p11.C_SignInit(session, new CK_MECHANISM(plan.mechanism), key);
        return p11.C_Sign(session, toSign);
    }

    public static boolean verify(PKCS11 p11, long session, String keyLabel, byte[] data, byte[] signature,
                                 String keyTypeHint, String mechanismOverride) throws PKCS11Exception {
        long key = Pkcs11Support.requireOneByLabel(p11, session, keyLabel);
        SignPlan plan = resolveSignPlan(p11, session, key, keyTypeHint, mechanismOverride);
        byte[] toVerify = plan.hashInSoftware ? sha256(data) : data;
        p11.C_VerifyInit(session, new CK_MECHANISM(plan.mechanism), key);
        try {
            p11.C_Verify(session, toVerify, signature);
            return true;
        } catch (PKCS11Exception ex) {
            // CKR_SIGNATURE_INVALID (0xC0) / CKR_SIGNATURE_LEN_RANGE (0xC1)
            long code = ex.getErrorCode();
            if (code == 0x000000C0L || code == 0x000000C1L) {
                return false;
            }
            throw ex;
        }
    }

    public static void wrapKey(PKCS11 p11, long session, String wrappingKeyLabel, String keyToWrapLabel, Path out)
            throws PKCS11Exception, IOException {
        long wrappingKey = Pkcs11Support.requireOneByLabel(p11, session, wrappingKeyLabel);
        long key = Pkcs11Support.requireOneByLabel(p11, session, keyToWrapLabel);
        byte[] wrapped = p11.C_WrapKey(session, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS), wrappingKey, key);
        Files.write(out, wrapped);
        System.out.println("Wrote wrapped key to " + out.toAbsolutePath());
    }

    public static void unwrapKey(PKCS11 p11, long session, String unwrappingKeyLabel, String newLabel,
                                 Path wrappedKeyFile, String keyType) throws PKCS11Exception, IOException {
        Pkcs11Support.requireAbsentLabel(p11, session, newLabel);
        long unwrappingKey = Pkcs11Support.requireOneByLabel(p11, session, unwrappingKeyLabel);
        byte[] wrapped = Files.readAllBytes(wrappedKeyFile);
        if (wrapped.length == 0) {
            throw new IllegalArgumentException("wrapped key file is empty: " + wrappedKeyFile);
        }

        String type = keyType.toUpperCase(Locale.ROOT);
        List<CK_ATTRIBUTE> attrs = new ArrayList<>();
        attrs.add(Pkcs11Support.labelAttr(newLabel));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));
        attrs.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_ID, Pkcs11Support.labelBytes(newLabel)));

        switch (type) {
            case "AES", "DES", "DES3", "3DES" -> {
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, Pkcs11Support.secretKeyType(type)));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_ENCRYPT, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_DECRYPT, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_WRAP, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_UNWRAP, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, false));
            }
            case "RSA" -> {
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_DECRYPT, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SIGN, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_UNWRAP, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
            }
            case "ECC", "EC", "ECDSA" -> {
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
                attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_EC));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SIGN, true));
                attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
            }
            default -> throw new IllegalArgumentException("unsupported unwrap -keyType: " + keyType);
        }

        long handle = p11.C_UnwrapKey(session, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS),
                unwrappingKey, wrapped, attrs.toArray(CK_ATTRIBUTE[]::new));
        System.out.println("Unwrapped object handle=" + handle + " label='" + newLabel + "'");
    }

    private static SignPlan resolveSignPlan(PKCS11 p11, long session, long key, String keyTypeHint,
                                            String mechanismOverride) throws PKCS11Exception {
        if (mechanismOverride != null) {
            long mech = MechanismNames.resolve(mechanismOverride);
            boolean hashInSoftware = mech == PKCS11Constants.CKM_ECDSA;
            return new SignPlan(mech, hashInSoftware);
        }
        String type = keyTypeHint != null ? keyTypeHint.toUpperCase(Locale.ROOT) : inferKeyType(p11, session, key);
        return switch (type) {
            case "RSA" -> new SignPlan(PKCS11Constants.CKM_SHA256_RSA_PKCS, false);
            // SoftHSM and many tokens lack CKM_ECDSA_SHA256; hash in software then use CKM_ECDSA.
            case "ECC", "EC", "ECDSA" -> new SignPlan(PKCS11Constants.CKM_ECDSA, true);
            case "AES", "DES", "DES3", "3DES" -> new SignPlan(PKCS11Constants.CKM_SHA256_HMAC, false);
            default -> throw new IllegalArgumentException("cannot choose sign mechanism for key type: " + type);
        };
    }

    private static byte[] sha256(byte[] data) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private record SignPlan(long mechanism, boolean hashInSoftware) {
    }

    private static long resolveEncryptMechanism(PKCS11 p11, long session, long key, String keyTypeHint,
                                                String mechanismOverride) throws PKCS11Exception {
        if (mechanismOverride != null) {
            return MechanismNames.resolve(mechanismOverride);
        }
        String type = keyTypeHint != null ? keyTypeHint.toUpperCase(Locale.ROOT) : inferKeyType(p11, session, key);
        return switch (type) {
            case "AES" -> PKCS11Constants.CKM_AES_CBC_PAD;
            case "DES" -> PKCS11Constants.CKM_DES_CBC_PAD;
            case "DES3", "3DES" -> PKCS11Constants.CKM_DES3_CBC_PAD;
            case "RSA" -> PKCS11Constants.CKM_RSA_PKCS;
            default -> throw new IllegalArgumentException("cannot choose encrypt mechanism for key type: " + type);
        };
    }

    private static String inferKeyType(PKCS11 p11, long session, long key) throws PKCS11Exception {
        long objectClass = Pkcs11Support.objectClass(p11, session, key);
        CK_ATTRIBUTE[] attrs = {new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE)};
        p11.C_GetAttributeValue(session, key, attrs);
        long keyType = ((Number) attrs[0].pValue).longValue();
        if (objectClass == PKCS11Constants.CKO_SECRET_KEY) {
            if (keyType == PKCS11Constants.CKK_AES) {
                return "AES";
            }
            if (keyType == PKCS11Constants.CKK_DES) {
                return "DES";
            }
            if (keyType == PKCS11Constants.CKK_DES3) {
                return "DES3";
            }
        }
        if (keyType == PKCS11Constants.CKK_RSA) {
            return "RSA";
        }
        if (keyType == PKCS11Constants.CKK_EC) {
            return "ECC";
        }
        throw new IllegalStateException("unsupported key type code: " + keyType);
    }

    private static byte[] ivFor(long mechanism) {
        if (mechanism == PKCS11Constants.CKM_AES_CBC || mechanism == PKCS11Constants.CKM_AES_CBC_PAD) {
            return new byte[16];
        }
        if (mechanism == PKCS11Constants.CKM_DES_CBC || mechanism == PKCS11Constants.CKM_DES_CBC_PAD
                || mechanism == PKCS11Constants.CKM_DES3_CBC || mechanism == PKCS11Constants.CKM_DES3_CBC_PAD) {
            return new byte[8];
        }
        return null;
    }

    private static byte[] trim(byte[] buffer, int length) {
        if (length == buffer.length) {
            return buffer;
        }
        byte[] out = new byte[length];
        System.arraycopy(buffer, 0, out, 0, length);
        return out;
    }
}
