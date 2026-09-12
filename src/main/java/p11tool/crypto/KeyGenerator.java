package p11tool.crypto;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Key generation for AES/DES/3DES/RSA/ECC.
 */
public final class KeyGenerator {

    private KeyGenerator() {
    }

    public static void generate(PKCS11 p11, long session, String keyType, String label, String pubLabel,
                                String priLabel, Integer keySize, BigInteger publicExponent, String curve)
            throws PKCS11Exception, Exception {
        String type = keyType.toUpperCase(Locale.ROOT);
        switch (type) {
            case "AES" -> generateAes(p11, session, label, keySize);
            case "DES" -> generateDes(p11, session, label, PKCS11Constants.CKK_DES, PKCS11Constants.CKM_DES_KEY_GEN);
            case "DES3", "3DES" ->
                    generateDes(p11, session, label, PKCS11Constants.CKK_DES3, PKCS11Constants.CKM_DES3_KEY_GEN);
            case "RSA" -> generateRsa(p11, session, pubLabel, priLabel, keySize, publicExponent);
            case "ECC", "EC", "ECDSA" -> generateEcc(p11, session, pubLabel, priLabel, curve);
            default -> throw new IllegalArgumentException("unsupported -keyType: " + keyType);
        }
    }

    private static void generateAes(PKCS11 p11, long session, String label, Integer keySizeBits)
            throws PKCS11Exception {
        if (label == null) {
            throw new IllegalArgumentException("label is required for AES keygen");
        }
        Pkcs11Support.requireAbsentLabel(p11, session, label);
        int bits = keySizeBits != null ? keySizeBits : 256;
        int valueLen = switch (bits) {
            case 128 -> 16;
            case 192 -> 24;
            case 256 -> 32;
            default -> throw new IllegalArgumentException("AES -keySize must be 128, 192, or 256");
        };
        List<CK_ATTRIBUTE> attrs = Pkcs11Support.secretKeyTemplate(label, "AES", true);
        attrs.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_VALUE_LEN, valueLen));
        System.out.println("Generating AES-" + bits + " key '" + label + "'");
        p11.C_GenerateKey(session, new CK_MECHANISM(PKCS11Constants.CKM_AES_KEY_GEN),
                attrs.toArray(CK_ATTRIBUTE[]::new));
    }

    private static void generateDes(PKCS11 p11, long session, String label, long keyType, long mechanism)
            throws PKCS11Exception {
        if (label == null) {
            throw new IllegalArgumentException("label is required for DES/3DES keygen");
        }
        Pkcs11Support.requireAbsentLabel(p11, session, label);
        String typeName = keyType == PKCS11Constants.CKK_DES ? "DES" : "DES3";
        List<CK_ATTRIBUTE> attrs = Pkcs11Support.secretKeyTemplate(label, typeName, true);
        System.out.println("Generating " + typeName + " key '" + label + "'");
        p11.C_GenerateKey(session, new CK_MECHANISM(mechanism), attrs.toArray(CK_ATTRIBUTE[]::new));
    }

    private static void generateRsa(PKCS11 p11, long session, String pubLabel, String priLabel,
                                    Integer keySize, BigInteger publicExponent) throws PKCS11Exception {
        if (pubLabel == null || priLabel == null) {
            throw new IllegalArgumentException("-pubLabel and -priLabel are required for RSA");
        }
        Pkcs11Support.requireAbsentLabel(p11, session, pubLabel);
        Pkcs11Support.requireAbsentLabel(p11, session, priLabel);
        int bits = keySize != null ? keySize : 2048;
        BigInteger exp = publicExponent != null ? publicExponent : BigInteger.valueOf(65537);

        List<CK_ATTRIBUTE> publicKey = new ArrayList<>();
        publicKey.add(Pkcs11Support.labelAttr(pubLabel));
        publicKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY));
        publicKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));
        publicKey.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_ID, Pkcs11Support.labelBytes(pubLabel)));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_ENCRYPT, true));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_WRAP, true));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_VERIFY, true));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, false));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_MODIFIABLE, true));
        publicKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_MODULUS_BITS, bits));
        publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PUBLIC_EXPONENT, exp));

        List<CK_ATTRIBUTE> privateKey = new ArrayList<>();
        privateKey.add(Pkcs11Support.labelAttr(priLabel));
        privateKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
        privateKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_DECRYPT, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SIGN, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_UNWRAP, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_MODIFIABLE, true));

        System.out.println("Generating RSA-" + bits + " key pair '" + pubLabel + "' / '" + priLabel + "'");
        p11.C_GenerateKeyPair(session, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
                publicKey.toArray(CK_ATTRIBUTE[]::new),
                privateKey.toArray(CK_ATTRIBUTE[]::new));
    }

    private static void generateEcc(PKCS11 p11, long session, String pubLabel, String priLabel, String curve)
            throws Exception {
        if (pubLabel == null || priLabel == null) {
            throw new IllegalArgumentException("-pubLabel and -priLabel are required for ECC");
        }
        Pkcs11Support.requireAbsentLabel(p11, session, pubLabel);
        Pkcs11Support.requireAbsentLabel(p11, session, priLabel);

        String curveName = curve != null ? curve : "secp256r1";
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curveName));
        byte[] encodedParams = parameters.getEncoded();

        List<CK_ATTRIBUTE> publicKey = new ArrayList<>();
        publicKey.add(Pkcs11Support.labelAttr(pubLabel));
        publicKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY));
        publicKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_EC));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));
        publicKey.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_ID, Pkcs11Support.labelBytes(pubLabel)));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_VERIFY, true));
        publicKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, false));
        publicKey.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_EC_PARAMS, encodedParams));

        List<CK_ATTRIBUTE> privateKey = new ArrayList<>();
        privateKey.add(Pkcs11Support.labelAttr(priLabel));
        privateKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
        privateKey.add(Pkcs11Support.longAttr(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_EC));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_TOKEN, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_PRIVATE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SENSITIVE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_EXTRACTABLE, true));
        privateKey.add(Pkcs11Support.boolAttr(PKCS11Constants.CKA_SIGN, true));
        privateKey.add(Pkcs11Support.bytesAttr(PKCS11Constants.CKA_ID, Pkcs11Support.labelBytes(priLabel)));

        System.out.println("Generating ECC (" + curveName + ") key pair '" + pubLabel + "' / '" + priLabel + "'");
        p11.C_GenerateKeyPair(session, new CK_MECHANISM(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                publicKey.toArray(CK_ATTRIBUTE[]::new),
                privateKey.toArray(CK_ATTRIBUTE[]::new));
    }
}
