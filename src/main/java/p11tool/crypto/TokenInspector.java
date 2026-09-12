package p11tool.crypto;

import p11tool.util.Hex;
import p11tool.util.Pem;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Inspect and export token objects.
 */
public final class TokenInspector {

    private TokenInspector() {
    }

    public static void printModuleInfo(PKCS11 p11, long[] slots) throws PKCS11Exception {
        CK_INFO info = p11.C_GetInfo();
        System.out.println(info);
        System.out.println();
        System.out.println("Number of slots with tokens: " + slots.length);
        for (int i = 0; i < slots.length; i++) {
            System.out.println();
            System.out.println("Slot list index " + i + " -> slot ID " + slots[i]);
            System.out.println(p11.C_GetSlotInfo(slots[i]));
            System.out.println(p11.C_GetTokenInfo(slots[i]));
        }
    }

    public static void listObjects(PKCS11 p11, long session, long slotId) throws PKCS11Exception {
        System.out.println("Session info:");
        CK_SESSION_INFO sessionInfo = p11.C_GetSessionInfo(session);
        System.out.println(sessionInfo);
        System.out.println();
        System.out.println("Token info:");
        CK_TOKEN_INFO tokenInfo = p11.C_GetTokenInfo(slotId);
        System.out.println(tokenInfo);
        System.out.println();

        p11.C_FindObjectsInit(session, new CK_ATTRIBUTE[0]);
        long[] handles;
        try {
            handles = p11.C_FindObjects(session, Pkcs11Support.MAX_OBJECTS);
        } finally {
            p11.C_FindObjectsFinal(session);
        }
        System.out.println(handles.length + " object(s) found.");
        System.out.println();

        for (int i = 0; i < handles.length; i++) {
            CK_ATTRIBUTE[] common = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE)
            };
            p11.C_GetAttributeValue(session, handles[i], common);
            System.out.println("Object " + i + " (handle=" + handles[i] + "):");
            for (CK_ATTRIBUTE attr : common) {
                System.out.println("  " + attr);
            }
            long objectClass = ((Number) common[1].pValue).longValue();
            if (objectClass == PKCS11Constants.CKO_SECRET_KEY) {
                printSecret(p11, session, handles[i]);
            } else if (objectClass == PKCS11Constants.CKO_PUBLIC_KEY) {
                printPublic(p11, session, handles[i]);
            } else if (objectClass == PKCS11Constants.CKO_PRIVATE_KEY) {
                printPrivate(p11, session, handles[i]);
            } else if (objectClass == PKCS11Constants.CKO_DATA) {
                printData(p11, session, handles[i]);
            } else if (objectClass == PKCS11Constants.CKO_CERTIFICATE) {
                printCertificate(p11, session, handles[i]);
            }
            System.out.println();
        }
    }

    public static void destroyByLabel(PKCS11 p11, long session, String label) throws PKCS11Exception {
        long[] handles = Pkcs11Support.findByLabel(p11, session, label);
        if (handles.length == 0) {
            System.out.println("Nothing to delete for label '" + label + "'");
            return;
        }
        for (long handle : handles) {
            System.out.println("Deleting handle " + handle + " with label '" + label + "'");
            p11.C_DestroyObject(session, handle);
        }
    }

    public static void exportByLabel(PKCS11 p11, long session, String label) throws Exception {
        long handle = Pkcs11Support.requireOneByLabel(p11, session, label);
        long objectClass = Pkcs11Support.objectClass(p11, session, handle);
        if (objectClass == PKCS11Constants.CKO_SECRET_KEY || objectClass == PKCS11Constants.CKO_DATA) {
            byte[] value = Pkcs11Support.getBytesAttr(p11, session, handle, PKCS11Constants.CKA_VALUE);
            System.out.println("hex: " + Hex.encode(value));
            System.out.println("base64: " + Base64.getEncoder().encodeToString(value));
            return;
        }
        if (objectClass == PKCS11Constants.CKO_PUBLIC_KEY) {
            CK_ATTRIBUTE[] keyTypeAttr = {new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE)};
            p11.C_GetAttributeValue(session, handle, keyTypeAttr);
            long keyType = ((Number) keyTypeAttr[0].pValue).longValue();
            if (keyType == PKCS11Constants.CKK_RSA) {
                CK_ATTRIBUTE[] attrs = {
                        new CK_ATTRIBUTE(PKCS11Constants.CKA_PUBLIC_EXPONENT),
                        new CK_ATTRIBUTE(PKCS11Constants.CKA_MODULUS)
                };
                p11.C_GetAttributeValue(session, handle, attrs);
                byte[] exponent = (byte[]) attrs[0].pValue;
                byte[] modulus = (byte[]) attrs[1].pValue;
                RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent));
                PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(spec);
                System.out.print(Pem.encodePublicKey(pub.getEncoded()));
                return;
            }
            if (keyType == PKCS11Constants.CKK_EC) {
                byte[] point = Pkcs11Support.getBytesAttr(p11, session, handle, PKCS11Constants.CKA_EC_POINT);
                System.out.println("CKA_EC_POINT (hex): " + Hex.encode(point));
                return;
            }
            throw new IllegalStateException("unsupported public key type for export");
        }
        if (objectClass == PKCS11Constants.CKO_PRIVATE_KEY) {
            byte[] value = Pkcs11Support.getBytesAttr(p11, session, handle, PKCS11Constants.CKA_VALUE);
            System.out.println("base64: " + Base64.getEncoder().encodeToString(value));
            return;
        }
        throw new IllegalStateException("unsupported object class for export: " + objectClass);
    }

    public static void importRsaPublicKey(PKCS11 p11, long session, String label, PathLike pemSource)
            throws Exception {
        Pkcs11Support.requireAbsentLabel(p11, session, label);
        String pem = pemSource.read();
        byte[] keyBytes = Pem.decodePublicKey(pem);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        java.security.interfaces.RSAPublicKey pubKey =
                (java.security.interfaces.RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);

        CK_ATTRIBUTE[] attrs = {
                Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY),
                Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA),
                Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true),
                Pkcs11Support.labelAttr(label),
                Pkcs11Support.bytesAttr(PKCS11Constants.CKA_ID, Pkcs11Support.labelBytes(label)),
                Pkcs11Support.boolAttr(PKCS11Constants.CKA_ENCRYPT, true),
                Pkcs11Support.boolAttr(PKCS11Constants.CKA_WRAP, true),
                Pkcs11Support.boolAttr(PKCS11Constants.CKA_VERIFY, true),
                Pkcs11Support.bytesAttr(PKCS11Constants.CKA_MODULUS, toUnsigned(pubKey.getModulus())),
                Pkcs11Support.bytesAttr(PKCS11Constants.CKA_PUBLIC_EXPONENT, toUnsigned(pubKey.getPublicExponent()))
        };
        System.out.println("Importing RSA public wrapping key '" + label + "'");
        p11.C_CreateObject(session, attrs);
    }

    private static byte[] toUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }

    private static void printSecret(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        printAttrs(p11, session, handle,
                PKCS11Constants.CKA_KEY_TYPE,
                PKCS11Constants.CKA_ID,
                PKCS11Constants.CKA_SENSITIVE,
                PKCS11Constants.CKA_ENCRYPT,
                PKCS11Constants.CKA_DECRYPT,
                PKCS11Constants.CKA_WRAP,
                PKCS11Constants.CKA_UNWRAP,
                PKCS11Constants.CKA_EXTRACTABLE,
                PKCS11Constants.CKA_NEVER_EXTRACTABLE);
    }

    private static void printPublic(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        printAttrs(p11, session, handle,
                PKCS11Constants.CKA_KEY_TYPE,
                PKCS11Constants.CKA_ID,
                PKCS11Constants.CKA_ENCRYPT,
                PKCS11Constants.CKA_VERIFY,
                PKCS11Constants.CKA_WRAP);
    }

    private static void printPrivate(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        printAttrs(p11, session, handle,
                PKCS11Constants.CKA_KEY_TYPE,
                PKCS11Constants.CKA_ID,
                PKCS11Constants.CKA_SENSITIVE,
                PKCS11Constants.CKA_DECRYPT,
                PKCS11Constants.CKA_SIGN,
                PKCS11Constants.CKA_UNWRAP,
                PKCS11Constants.CKA_EXTRACTABLE,
                PKCS11Constants.CKA_NEVER_EXTRACTABLE);
    }

    private static void printData(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        printAttrs(p11, session, handle, PKCS11Constants.CKA_APPLICATION, PKCS11Constants.CKA_VALUE);
    }

    private static void printCertificate(PKCS11 p11, long session, long handle) throws PKCS11Exception {
        printAttrs(p11, session, handle,
                PKCS11Constants.CKA_CERTIFICATE_TYPE,
                PKCS11Constants.CKA_SUBJECT,
                PKCS11Constants.CKA_ID,
                PKCS11Constants.CKA_ISSUER,
                PKCS11Constants.CKA_SERIAL_NUMBER);
    }

    private static void printAttrs(PKCS11 p11, long session, long handle, long... types) throws PKCS11Exception {
        CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[types.length];
        for (int i = 0; i < types.length; i++) {
            attrs[i] = new CK_ATTRIBUTE(types[i]);
        }
        try {
            p11.C_GetAttributeValue(session, handle, attrs);
            for (CK_ATTRIBUTE attr : attrs) {
                System.out.println("  " + attr);
            }
        } catch (PKCS11Exception ex) {
            System.out.println("  (attributes unavailable: " + ex.getMessage() + ")");
        }
    }

    /**
     * Tiny abstraction so callers can pass a path string or inline PEM.
     */
    public interface PathLike {
        String read() throws Exception;

        static PathLike of(String pathOrInline) {
            return () -> {
                java.nio.file.Path path = java.nio.file.Path.of(pathOrInline);
                if (java.nio.file.Files.isRegularFile(path)) {
                    return java.nio.file.Files.readString(path, StandardCharsets.US_ASCII);
                }
                return pathOrInline;
            };
        }
    }
}
