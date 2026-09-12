package p11tool.crypto;

import p11tool.util.Hex;
import p11tool.util.Kcv;
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
 * Import hex data objects / secret keys, and XOR-combine extractable components.
 */
public final class ObjectImporter {

    private ObjectImporter() {
    }

    public static void importHex(PKCS11 p11, long session, String label, String in, String keyType)
            throws IOException, PKCS11Exception {
        Pkcs11Support.requireAbsentLabel(p11, session, label);
        byte[] value = readHexInput(in);

        List<CK_ATTRIBUTE> attrs = new ArrayList<>();
        attrs.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_VALUE, value));
        attrs.add(Pkcs11Support.labelAttr(label));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));

        if (keyType == null || keyType.isBlank()) {
            attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_DATA));
            System.out.println("Creating data object '" + label + "'");
            p11.C_CreateObject(session, attrs.toArray(CK_ATTRIBUTE[]::new));
            return;
        }

        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, false));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
        attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_DERIVE, true));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_ENCRYPT, true));
        attrs.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_DECRYPT, true));
        attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, Pkcs11Support.secretKeyType(keyType)));

        System.out.println("Creating " + keyType.toUpperCase(Locale.ROOT) + " secret key '" + label + "'");
        long handle = p11.C_CreateObject(session, attrs.toArray(CK_ATTRIBUTE[]::new));
        System.out.println("KCV: " + Kcv.compute(value, keyType));
        try {
            System.out.println("KCV (token): " + tokenKcv(p11, session, handle, keyType));
        } catch (PKCS11Exception ex) {
            System.out.println("KCV (token): unavailable (" + ex.getMessage() + ")");
        }
    }

    public static void xorCombine(PKCS11 p11, long session, String key1, String key2, String key3,
                                  String keyType, String label) throws PKCS11Exception, IOException {
        byte[] v1 = extractSecretValue(p11, session, key1);
        byte[] v2 = extractSecretValue(p11, session, key2);
        byte[] v3 = extractSecretValue(p11, session, key3);
        byte[] combined = Kcv.xorCombine(v1, v2, v3);
        System.out.println("Warning: XOR combine exports component key values from the token.");
        importHex(p11, session, label, Hex.encode(combined), keyType);
    }

    private static byte[] extractSecretValue(PKCS11 p11, long session, String label) throws PKCS11Exception {
        long handle = Pkcs11Support.requireOneByLabel(p11, session, label);
        return Pkcs11Support.getBytesAttr(p11, session, handle, PKCS11Constants.CKA_VALUE);
    }

    private static String tokenKcv(PKCS11 p11, long session, long key, String keyType) throws PKCS11Exception {
        String type = keyType.toUpperCase(Locale.ROOT);
        byte[] data;
        long mechanism;
        switch (type) {
            case "AES" -> {
                data = new byte[16];
                mechanism = PKCS11Constants.CKM_AES_ECB;
            }
            case "DES" -> {
                data = new byte[8];
                mechanism = PKCS11Constants.CKM_DES_ECB;
            }
            case "DES3", "3DES" -> {
                data = new byte[8];
                mechanism = PKCS11Constants.CKM_DES3_ECB;
            }
            default -> throw new IllegalArgumentException("unsupported key type for token KCV: " + keyType);
        }
        byte[] encrypted = new byte[data.length];
        p11.C_EncryptInit(session, new CK_MECHANISM(mechanism), key);
        int written = p11.C_Encrypt(session, 0L, data, 0, data.length, 0L, encrypted, 0, encrypted.length);
        byte[] out = written == encrypted.length ? encrypted : java.util.Arrays.copyOf(encrypted, written);
        return Hex.encodeUpper(out).substring(0, 6);
    }

    public static byte[] readHexInput(String in) throws IOException {
        Path path = Path.of(in);
        String text;
        if (Files.isRegularFile(path)) {
            text = Files.readString(path);
        } else {
            text = in;
        }
        return Hex.decode(text);
    }
}
