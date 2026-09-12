package p11tool.crypto;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Thin helpers around the JDK PKCS#11 JNI wrapper.
 */
public final class Pkcs11Support {

    public static final int MAX_OBJECTS = 10_000;

    private Pkcs11Support() {
    }

    public static PKCS11 loadModule(String libraryPath) throws IOException, PKCS11Exception {
        Objects.requireNonNull(libraryPath, "libraryPath");
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        return PKCS11.getInstance(libraryPath, "C_GetFunctionList", initArgs, false);
    }

    public static long openRwSession(PKCS11 p11, long slotId) throws PKCS11Exception {
        return p11.C_OpenSession(slotId,
                PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION,
                null, null);
    }

    public static void loginIfNeeded(PKCS11 p11, long session, String pin) throws PKCS11Exception {
        if (pin != null && !pin.isEmpty()) {
            p11.C_Login(session, PKCS11Constants.CKU_USER, pin.toCharArray());
        }
    }

    public static void closeQuietly(PKCS11 p11, long session) {
        if (p11 == null || session == 0L) {
            return;
        }
        try {
            p11.C_Logout(session);
        } catch (PKCS11Exception ignored) {
            // already logged out or login was not required
        }
        try {
            p11.C_CloseSession(session);
        } catch (PKCS11Exception ignored) {
            // best-effort cleanup
        }
    }

    public static long[] findByLabel(PKCS11 p11, long session, String label) throws PKCS11Exception {
        CK_ATTRIBUTE[] template = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, labelBytes(label))};
        p11.C_FindObjectsInit(session, template);
        try {
            return p11.C_FindObjects(session, MAX_OBJECTS);
        } finally {
            p11.C_FindObjectsFinal(session);
        }
    }

    public static long requireOneByLabel(PKCS11 p11, long session, String label) throws PKCS11Exception {
        long[] handles = findByLabel(p11, session, label);
        if (handles.length < 1) {
            throw new IllegalStateException("object with label '" + label + "' not found");
        }
        return handles[0];
    }

    public static void requireAbsentLabel(PKCS11 p11, long session, String label) throws PKCS11Exception {
        if (label == null) {
            return;
        }
        long[] handles = findByLabel(p11, session, label);
        if (handles.length > 0) {
            throw new IllegalStateException("object with label '" + label + "' already exists");
        }
    }

    public static byte[] labelBytes(String label) {
        return Objects.requireNonNull(label, "label").getBytes(StandardCharsets.UTF_8);
    }

    public static CK_ATTRIBUTE labelAttr(String label) {
        return new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, labelBytes(label));
    }

    public static CK_ATTRIBUTE boolAttr(long type, boolean value) {
        return new CK_ATTRIBUTE(type, value);
    }

    public static CK_ATTRIBUTE longAttr(long type, long value) {
        return new CK_ATTRIBUTE(type, value);
    }

    public static CK_ATTRIBUTE bytesAttr(long type, byte[] value) {
        return new CK_ATTRIBUTE(type, value);
    }

    public static long objectClass(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        CK_ATTRIBUTE[] attrs = {new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS)};
        p11.C_GetAttributeValue(session, handle, attrs);
        Object value = attrs[0].pValue;
        if (value instanceof Long l) {
            return l;
        }
        if (value instanceof Number n) {
            return n.longValue();
        }
        throw new IllegalStateException("unexpected CKA_CLASS value: " + value);
    }

    public static byte[] getBytesAttr(PKCS11 p11, long session, long handle, long type) throws PKCS11Exception {
        CK_ATTRIBUTE[] attrs = {new CK_ATTRIBUTE(type)};
        p11.C_GetAttributeValue(session, handle, attrs);
        Object value = attrs[0].pValue;
        if (value == null) {
            return new byte[0];
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        throw new IllegalStateException("attribute " + type + " is not a byte array");
    }

    public static long secretKeyType(String keyType) {
        return switch (normalizeKeyType(keyType)) {
            case "AES" -> PKCS11Constants.CKK_AES;
            case "DES" -> PKCS11Constants.CKK_DES;
            case "DES3", "3DES" -> PKCS11Constants.CKK_DES3;
            default -> throw new IllegalArgumentException("unsupported secret key type: " + keyType);
        };
    }

    public static String normalizeKeyType(String keyType) {
        if (keyType == null) {
            throw new IllegalArgumentException("keyType is required");
        }
        return keyType.toUpperCase(Locale.ROOT);
    }

    public static List<CK_ATTRIBUTE> secretKeyTemplate(String label, String keyType, boolean extractable) {
        List<CK_ATTRIBUTE> attrs = new ArrayList<>();
        attrs.add(boolAttr(PKCS11Constants.CKA_TOKEN, true));
        attrs.add(labelAttr(label));
        attrs.add(bytesAttr(PKCS11Constants.CKA_ID, labelBytes(label)));
        attrs.add(longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
        attrs.add(longAttr(PKCS11Constants.CKA_KEY_TYPE, secretKeyType(keyType)));
        attrs.add(boolAttr(PKCS11Constants.CKA_PRIVATE, false));
        attrs.add(boolAttr(PKCS11Constants.CKA_EXTRACTABLE, extractable));
        attrs.add(boolAttr(PKCS11Constants.CKA_SENSITIVE, !extractable));
        attrs.add(boolAttr(PKCS11Constants.CKA_ENCRYPT, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_DECRYPT, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_WRAP, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_UNWRAP, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_SIGN, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_VERIFY, true));
        attrs.add(boolAttr(PKCS11Constants.CKA_DERIVE, true));
        return attrs;
    }
}
