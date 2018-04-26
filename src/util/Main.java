package util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;

import iaik.pkcs.pkcs11.wrapper.CK_KEY_DERIVATION_STRING_DATA;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;


import sun.security.util.ECUtil;

//TODO: ecc keygen. Unwrap keys
//To generate exportable keys on Thales HSM set system variable CKNFAST_OVERRIDE_SECURITY_ASSURANCES=tokenkeys
//For AWS KMS BOYK select RSAES_PKCS1_V1_5 as wrapping algorithm
//reload a different copy of cryptoki.dll solves token has been removed issue. 
//For Thales OCS protected keys, use ~nfast/bin/ckinfo and below instructions to preload OCS
/*When using k/n OCS where k>1 you got to load all OCSs to be used with preload and then start the application server also with preload. Example:
$ ~nfast/bin/preload -c 2of3_0 pause
-- follow instruction to insert cards and enter pins. --
-- then press ctr-z --
$ bg 
$ ~nfast/bin/preload -c 2of3_1 exit
-- follow instruction to insert cards and enter pins. --
*/


public class Main {

    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, PKCS11Exception, InterruptedException, InvalidKeySpecException,
            Base64DecodingException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, TokenException {
        String passwd = null;
        String lib = null;
        String in = null;
        int keySize = -1;
        String keyLabel = null;
        String label = null;
        String keyType = null;
        String pubLabel = null;
        String priLabel = null;
        String key1 = null;
        String key2 = null;
        String key3 = null;
        BigInteger publicExponent = null;
        int slotNum = -1;
        boolean export = false;
        boolean wrap = false;
        boolean getinfo = false;
        boolean destroy = false;
        boolean unwrap = false;
        boolean keygen = false;
        boolean generate = false;
        boolean encrypt = false;
        boolean decrypt = false;
        boolean sign = false;
        boolean verify = false;
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].toLowerCase().equals("generate"))
                generate = true;
            if (args[i].toLowerCase().equals("encrypt"))
                encrypt = true;
            if (args[i].toLowerCase().equals("decrypt"))
                decrypt = true;
            if (args[i].toLowerCase().equals("sign"))
                sign = true;
            if (args[i].toLowerCase().equals("verify"))
                verify = true;
            if (args[i].toLowerCase().equals("keygen"))
                keygen = true;
            if (args[i].toLowerCase().equals("export"))
                export = true;
            if (args[i].toLowerCase().equals("destroy"))
                destroy = true;
            if (args[i].toLowerCase().equals("getinfo"))
                getinfo = true;
            if (args[i].toLowerCase().equals("wrap"))
                wrap = true;
            if (args[i].toLowerCase().equals("unwrap"))
                unwrap = true;
            if (args[i].toLowerCase().equals("-pin"))
                passwd = args[i + 1];
            if (args[i].toLowerCase().equals("-lib"))
                lib = args[i + 1];
            if (args[i].toLowerCase().equals("-slotnum"))
                slotNum = Integer.valueOf(args[i + 1]);
            if (args[i].toLowerCase().equals("-in"))
                in = args[i + 1];
            if (args[i].toLowerCase().equals("-keysize"))
                keySize = Integer.valueOf(args[i + 1]);
            if (args[i].toLowerCase().equals("-keylabel"))
                keyLabel = args[i + 1];
            if (args[i].toLowerCase().equals("-label"))
                label = args[i + 1];
            if (args[i].toLowerCase().equals("-keytype"))
                keyType = args[i + 1];
            if (args[i].toLowerCase().equals("-publicexponent"))
                publicExponent = new BigInteger(args[i + 1]);
            if (args[i].toLowerCase().equals("-publabel"))
                pubLabel = args[i + 1];
            if (args[i].toLowerCase().equals("-prilabel"))
                priLabel = args[i + 1];
            if (args[i].toLowerCase().equals("-key1"))
                key1 = args[i + 1];
            if (args[i].toLowerCase().equals("-key2"))
                key2 = args[i + 1];
            if (args[i].toLowerCase().equals("-key3"))
                key3 = args[i + 1];
        }

        if (lib == null || (keygen == false && wrap == false && getinfo == false && destroy == false && export == false
                && unwrap == false && generate == false && encrypt == false && decrypt == false && verify == false && sign == false)) {
            System.out.println(
                    "Usage: java -jar p11tool.jar <getinfo|wrap|unwrap|destroy|export|generate|encrypt|decrypt|verify|sign> -lib <PKCS11 library file path. Use quotation marks if there are spaces in the path.> -slotNum [Optional] <Slot number> -pin [Optional] <HSM slot password>");
            System.exit(1);
        }

        if (passwd == null) {
            char passwdArray[] = System.console().readPassword("Enter slot user password [Optional]: ");
            passwd = new String(passwdArray);
        }

        // String hsmPin = "Pa55w0rd";
        // SunPKCS11 p = new
        // sun.security.pkcs11.SunPKCS11("C:\\Users\\benjamin.bi\\OneDrive\\P11Tool\\pkcs11
        // - Thales.cfg");
        // Security.addProvider(p);
        // KeyStore ks = KeyStore.getInstance("PKCS11");

        // ks.load(null, hsmPin.toCharArray());
        // System.out.println(ks.getCertificate("ausidSubCAKey"));
        // System.out.println(ks.size());
        System.out.println();

        System.out.println("Initializing...");
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();

        System.out.println("Getting instance...");
        PKCS11 p11 = PKCS11.getInstance(lib, "C_GetFunctionList", initArgs, false);
        // PKCS11 p11 = PKCS11.getInstance("C:/Program
        // Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll",
        // "C_GetFunctionList", initArgs, false);
        // PKCS11 p11 =
        // PKCS11.getInstance("C:\\SoftHSM2\\lib\\softhsm2-x64.dll",
        // "C_GetFunctionList", initArgs, false);
        // PKCS11 p11 = PKCS11.getInstance("C:\\Program
        // Files\\SafeNet\\LunaClient\\cryptoki.dll", "C_GetFunctionList",
        // initArgs, false);
        System.out.println("Getting slot list...");
        long[] slots = p11.C_GetSlotList(true);
        long sessionhandle;


        if (destroy) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            System.out.println("Deleting " + label);
            destroyByLabel(p11, sessionhandle, label);
        }
        if (generate) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            if (key1 != null && key2 != null && key3 != null) {
                combineHard(lib, passwd, key1, key2, key3, keyType, label);
                combine(p11, sessionhandle, key1, key2, key3, keyType, label);

            } else {
                generate(p11, sessionhandle, label, in, keyType);
            }

        }
        if (encrypt) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
        }
        if (decrypt) {

        }
        if (sign) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
        }
        if (verify) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
        }
        if (keygen) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            //TODO ECC
            System.out.println("Generate key selected....");
            keyGen(p11, sessionhandle, keyLabel, keySize, keyType, publicExponent, pubLabel, priLabel);
        }
        if (export) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            System.out.println("Export selected....");
            export(p11, sessionhandle, label);

        }
        if (unwrap) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            //TODO unwrapped object template requirements
            System.out.println("Unwrap selected....");
            unwrapKey(p11, sessionhandle, label, keyLabel, in, keyType);
        }

        if (wrap) {
            sessionhandle = p11.C_OpenSession(slots[slotNum],
                    PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                System.out.println("Logging in...");
                p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
            }
            System.out.println("Wrap selected....");
            if (keySize != -1)
                keyGen(p11, sessionhandle, keyLabel, keySize, keyType, publicExponent, pubLabel, priLabel);
            importPubKey(p11, passwd, sessionhandle, label, in);
            wrapKey(p11, passwd, sessionhandle, label, keyLabel);
        }

        if (getinfo) {
            System.out.println("Getting info...");
            CK_INFO cki = p11.C_GetInfo();
            System.out.println();

            System.out.println(cki);
            System.out.println();

            System.out.println("Number of slots: " + slots.length);
            System.out.println();

            if (slotNum != -1) {
                sessionhandle = p11.C_OpenSession(slots[slotNum],
                        PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
                if (passwd != null && !passwd.isEmpty() && !passwd.equals("")) {
                    System.out.println("Logging in...");
                    p11.C_Login(sessionhandle, PKCS11Constants.CKU_USER, passwd.toCharArray());
                }
                getInfo(p11, passwd, sessionhandle, slots[slotNum]);
            } else {
                for (int i = 0; i < slots.length; i++) {
                    System.out.println("Slot index number: " + slots[i]);
                    System.out.println(p11.C_GetSlotInfo(slots[i]));
                    System.out.println(p11.C_GetTokenInfo(slots[i]));


                }

            }

        }

        System.out.println("Exit....");
    }


    private static void combineHard(String lib, String passwd, String key1, String key2, String key3, String keyType, String label) throws IOException, TokenException {
        BufferedReader input_ = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter output_ = new PrintWriter(System.out, true);
        Module pkcs11Module = Module.getInstance(lib);
        pkcs11Module.initialize(null);

        Token token = Util.selectToken(pkcs11Module, output_, input_);
        TokenInfo tokenInfo = token.getTokenInfo();
        byte[] key = {0x00};
        CK_KEY_DERIVATION_STRING_DATA params = new CK_KEY_DERIVATION_STRING_DATA();
        params.pData = key;
        iaik.pkcs.pkcs11.wrapper.CK_MECHANISM test = new iaik.pkcs.pkcs11.wrapper.CK_MECHANISM();
        test.mechanism = iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_XOR_BASE_AND_DATA;
        test.pParameter = params;


    }

    private static void combine(PKCS11 p11, long sessionhandle, String key1, String key2, String key3, String keyType, String label) throws PKCS11Exception, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		/*
		CK_ATTRIBUTE[] keytemplate1 = { new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key1.getBytes()), };
		p11.C_FindObjectsInit(sessionhandle, keytemplate1);
		long[] handles1 = p11.C_FindObjects(sessionhandle, 2147483647);
		p11.C_FindObjectsFinal(sessionhandle);
		
		CK_ATTRIBUTE[] keytemplate2 = { new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key2.getBytes()), };
		p11.C_FindObjectsInit(sessionhandle, keytemplate2);
		long[] handles2 = p11.C_FindObjects(sessionhandle, 2147483647);
		p11.C_FindObjectsFinal(sessionhandle);
		CK_ATTRIBUTE[] attributeTemplateList2 = new CK_ATTRIBUTE[1];
		attributeTemplateList2[0] = new CK_ATTRIBUTE();
		attributeTemplateList2[0].type = PKCS11Constants.CKA_VALUE;
		p11.C_GetAttributeValue(sessionhandle, handles2[0], attributeTemplateList2);
		byte[] keyValue2 = (byte[]) attributeTemplateList2[0].pValue;

		CK_ATTRIBUTE[] keytemplate3 = { new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key3.getBytes()), };
		p11.C_FindObjectsInit(sessionhandle, keytemplate3);
		long[] handles3 = p11.C_FindObjects(sessionhandle, 2147483647);
		p11.C_FindObjectsFinal(sessionhandle);
		CK_ATTRIBUTE[] attributeTemplateList3 = new CK_ATTRIBUTE[1];
		attributeTemplateList3[0] = new CK_ATTRIBUTE();
		attributeTemplateList3[0].type = PKCS11Constants.CKA_VALUE;
		p11.C_GetAttributeValue(sessionhandle, handles3[0], attributeTemplateList3);
		byte[] keyValue3 = (byte[]) attributeTemplateList3[0].pValue;
		
		ArrayList<CK_ATTRIBUTE> tempKey = new ArrayList<CK_ATTRIBUTE>();
		
		tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
		tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, "tempKey".getBytes()));
		tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
		tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, true));
		if (keyType.toUpperCase().equals("DES"))
			tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES));
		if (keyType.toUpperCase().equals("DES3")||keyType.toUpperCase().equals("3DES"))
			tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES3));
		if(keyType.toUpperCase().equals("AES"))
			tempKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES));
	CK_KEY_DERIVATION_STRING_DATA params = new CK_KEY_DERIVATION_STRING_DATA();
		params.pData = keyValue2;
		//CK_KEY_DERIVATION_STRING_DATA hasn't been implemented, so sad :(
		long tempKeyHandle = p11.C_DeriveKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_XOR_BASE_AND_DATA, 
				keyValue2), handles1[0], tempKey.toArray(new CK_ATTRIBUTE[tempKey.size()]));
		
		*/

        //Below code will export three keys, xor them and import back into the HSM. Which defeats the whole point of having the keys in the HSM in the first place.

        CK_ATTRIBUTE[] keytemplate1 = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key1.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, keytemplate1);
        long[] handles1 = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        CK_ATTRIBUTE[] attributeTemplateList1 = new CK_ATTRIBUTE[1];
        attributeTemplateList1[0] = new CK_ATTRIBUTE();
        attributeTemplateList1[0].type = PKCS11Constants.CKA_VALUE;
        p11.C_GetAttributeValue(sessionhandle, handles1[0], attributeTemplateList1);
        byte[] keyValue1 = (byte[]) attributeTemplateList1[0].pValue;

        CK_ATTRIBUTE[] keytemplate2 = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key2.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, keytemplate2);
        long[] handles2 = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        CK_ATTRIBUTE[] attributeTemplateList2 = new CK_ATTRIBUTE[1];
        attributeTemplateList2[0] = new CK_ATTRIBUTE();
        attributeTemplateList2[0].type = PKCS11Constants.CKA_VALUE;
        p11.C_GetAttributeValue(sessionhandle, handles2[0], attributeTemplateList2);
        byte[] keyValue2 = (byte[]) attributeTemplateList2[0].pValue;

        CK_ATTRIBUTE[] keytemplate3 = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, key3.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, keytemplate3);
        long[] handles3 = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        CK_ATTRIBUTE[] attributeTemplateList3 = new CK_ATTRIBUTE[1];
        attributeTemplateList3[0] = new CK_ATTRIBUTE();
        attributeTemplateList3[0].type = PKCS11Constants.CKA_VALUE;
        p11.C_GetAttributeValue(sessionhandle, handles3[0], attributeTemplateList3);
        byte[] keyValue3 = (byte[]) attributeTemplateList3[0].pValue;


        byte[] combinedKey = new byte[keyValue3.length];
        for (int i = 0; i < keyValue3.length; i++) {
            combinedKey[i] = (byte) (keyValue1[i] ^ keyValue2[i] ^ keyValue3[i]);
        }
        generate(p11, sessionhandle, label, byteArrayToHexString(combinedKey), keyType);


    }

    private static void generate(PKCS11 p11, long sessionhandle, String label, String in, String keyType) throws IOException, PKCS11Exception, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Generating object...");
        CK_ATTRIBUTE[] key = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, key);
        long[] handles = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        if (handles.length > 0) {
            System.out.println("Object with the same label already exists.");
            System.exit(1);
        }
        String lines = "";
        File inFile = new File(in);
        if (inFile.exists()) {
            BufferedReader br = new BufferedReader(
                    new FileReader(in));
            String line;
            while ((line = br.readLine()) != null) {
                lines += line + "\n";
            }
            br.close();
        } else {
            lines = in;
        }

        ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
        attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE, hexStringToByteArray(lines)));
        attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()));
        attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
        if (keyType == null) {
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_DATA));
        } else {
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, false));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, true));
            if (keyType.toUpperCase().equals("DES"))
                attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES));
            if (keyType.toUpperCase().equals("DES3") || keyType.toUpperCase().equals("3DES"))
                attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES3));
            if (keyType.toUpperCase().equals("AES"))
                attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES));
        }

        long object = p11.C_CreateObject(sessionhandle, attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));

        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_VALUE;
        p11.C_GetAttributeValue(sessionhandle, object, attributeTemplateList);
        //System.out.println(byteArrayToHexString((byte[])attributeTemplateList[0].pValue));

        //System.out.println("KCV: " + GetKcv(lines,keyType));
        System.out.println("KCV: " + GetKcv(byteArrayToHexString((byte[]) attributeTemplateList[0].pValue), keyType));
        System.out.println("KCV: " + GetKcvHard(sessionhandle, p11, object, keyType));

        //if(keyType != null){

        // get CKA_CHECK_VALUE somehow?

        //p11.C_GetAttributeValue(sessionhandle, object, attrList1);
        //}
    }

    private static String GetKcvHard(long sessionhandle, PKCS11 p11, long key, String keyType) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, PKCS11Exception {
        String kcv = "";
        byte[] ivbyte = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] data = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] ivbyteaes = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] dataaes = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (keyType.toUpperCase().equals("AES")) {
            byte[] encrypted = new byte[16];
            p11.C_EncryptInit(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_AES_ECB), key);
            p11.C_Encrypt(sessionhandle, dataaes, 0, 16, encrypted, 0, 16);
            kcv = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();
        }
        if (keyType.toUpperCase().equals("DES")) {
            byte[] encrypted = new byte[8];
            p11.C_EncryptInit(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_DES_ECB), key);
            p11.C_Encrypt(sessionhandle, data, 0, 8, encrypted, 0, 16);
            kcv = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();
        }
        if (keyType.toUpperCase().equals("DES3") || keyType.toUpperCase().equals("3DES")) {
            byte[] encrypted = new byte[8];
            p11.C_EncryptInit(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_DES3_ECB), key);
            p11.C_Encrypt(sessionhandle, data, 0, 8, encrypted, 0, 16);
            kcv = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();
        }


        return kcv;
    }


    private static String GetKcv(String key, String keyType) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String kcv = "";
        byte[] ivbyte = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] data = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        IvParameterSpec iv = new IvParameterSpec(ivbyte);
        SecretKeySpec skeySpec = null;
        Cipher cipher = null;
        if (keyType.toUpperCase().equals("AES")) {
            ivbyte = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            data = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            iv = new IvParameterSpec(ivbyte);
            skeySpec = new SecretKeySpec(hexStringToByteArray(key), "AES");
            cipher = Cipher.getInstance("AES/CBC/NOPADDING");
        }
        if (keyType.toUpperCase().equals("DES")) {
            skeySpec = new SecretKeySpec(hexStringToByteArray(key), "DES");
            cipher = Cipher.getInstance("DES/CBC/NOPADDING");
        }
        if (keyType.toUpperCase().equals("DES3") || keyType.toUpperCase().equals("3DES")) {
            skeySpec = new SecretKeySpec(hexStringToByteArray(key), "DESede");
            cipher = Cipher.getInstance("DESede/CBC/NOPADDING");
        }
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(data);
        kcv = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();
        return kcv;
    }


    private static void unwrapKey(PKCS11 p11, long sessionhandle, String label, String keyLabel, String in, String keyType) throws PKCS11Exception, IOException {
        CK_ATTRIBUTE[] key = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, keyLabel.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, key);
        long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        if (keyHandles.length < 1) {
            System.out.println("Unwrapping key " + keyLabel + " not found.");
            System.exit(1);
        }

        byte[] wrappedKey = null;
        FileInputStream fis = new FileInputStream(in);
        fis.read(wrappedKey);
        fis.close();
        ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
        attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label));
        if (keyType.toUpperCase().equals("RSA")) {

        }
        if (keyType.toUpperCase().equals("ECC")) {

        }
        if (keyType.toUpperCase().equals("AES")) {

        }
        if (keyType.toUpperCase().equals("DES")) {

        }
        if (keyType.toUpperCase().equals("DES3")) {

        }
        p11.C_UnwrapKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS), keyHandles[0], wrappedKey, attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));
    }

    public static void export(PKCS11 p11, long sessionhandle, String label)
            throws PKCS11Exception, NoSuchAlgorithmException, InvalidKeySpecException {

        CK_ATTRIBUTE[] key = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, key);
        long[] handles = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
        attributeTemplateList[0] = new CK_ATTRIBUTE();
        attributeTemplateList[0].type = PKCS11Constants.CKA_CLASS;
        p11.C_GetAttributeValue(sessionhandle, handles[0], attributeTemplateList);
        System.out.println(attributeTemplateList[0].toString());
        if (attributeTemplateList[0].toString().contains("CKO_SECRET_KEY")) {
            CK_ATTRIBUTE[] attributeTemplateList1 = new CK_ATTRIBUTE[1];
            attributeTemplateList1[0] = new CK_ATTRIBUTE();
            attributeTemplateList1[0].type = PKCS11Constants.CKA_VALUE;
            p11.C_GetAttributeValue(sessionhandle, handles[0], attributeTemplateList1);
            byte[] keyValue = (byte[]) attributeTemplateList1[0].pValue;
            System.out.println(new sun.misc.BASE64Encoder().encode(keyValue));
            System.out.println(new String(keyValue, StandardCharsets.UTF_8));
        }
        if (attributeTemplateList[0].toString().contains("CKO_PUBLIC_KEY")) {
            CK_ATTRIBUTE[] attributeTemplateList1 = new CK_ATTRIBUTE[2];
            attributeTemplateList1[0] = new CK_ATTRIBUTE();
            attributeTemplateList1[0].type = PKCS11Constants.CKA_PUBLIC_EXPONENT;
            attributeTemplateList1[1] = new CK_ATTRIBUTE();
            attributeTemplateList1[1].type = PKCS11Constants.CKA_MODULUS;
            p11.C_GetAttributeValue(sessionhandle, handles[0], attributeTemplateList1);
            byte[] exponent = (byte[]) attributeTemplateList1[0].pValue;
            byte[] modulus = (byte[]) attributeTemplateList1[1].pValue;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(byteArrayToHexString(modulus), 16),
                    new BigInteger(byteArrayToHexString(exponent), 16));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey pub = factory.generatePublic(spec);
            System.out.println(
                    "-----BEGIN PUBLIC KEY-----\n" + Base64.encode(pub.getEncoded()) + "\n-----END PUBLIC KEY-----\n");
        }
        if (attributeTemplateList[0].toString().contains("CKO_PRIVATE_KEY")) {
            CK_ATTRIBUTE[] attributeTemplateList1 = new CK_ATTRIBUTE[1];
            attributeTemplateList1[0] = new CK_ATTRIBUTE();
            attributeTemplateList1[0].type = PKCS11Constants.CKA_VALUE;
            p11.C_GetAttributeValue(sessionhandle, handles[0], attributeTemplateList1);
            byte[] keyValue = (byte[]) attributeTemplateList1[0].pValue;
            System.out.println(new sun.misc.BASE64Encoder().encode(keyValue));
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            if (((int) bytes[i] & 0xff) < 0x10)
                buffer.append("0");
            buffer.append(Long.toString((int) bytes[i] & 0xff, 16));
        }
        return buffer.toString();
    }

    public static void derToPem(String in) throws IOException, CertificateException {
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(
                new FileReader(in));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();

        byte[] base64 = org.bouncycastle.util.encoders.Base64.encode(strKeyPEM.getBytes());
        FileOutputStream fos = new FileOutputStream("pub.key");
        fos.write(base64);
        fos.close();

    }

    public static void wrapKey(PKCS11 p11, String passwd, long sessionhandle, String label, String keyLabel)
            throws PKCS11Exception, IOException {
        FileOutputStream fos;
        CK_ATTRIBUTE[] key = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, keyLabel.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, key);
        long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        /*
         * CK_ATTRIBUTE[] attributeTemplateList = new CK_ATTRIBUTE[1];
         * attributeTemplateList[0] = new CK_ATTRIBUTE();
         * attributeTemplateList[0].type = PKCS11Constants.CKA_VALUE;
         * p11.C_GetAttributeValue(sessionhandle, keyHandles[0],
         * attributeTemplateList); byte[] keyValue = (byte[])
         * attributeTemplateList[0].pValue; fos = new
         * FileOutputStream("unwrapped.key"); fos.write(keyValue); fos.close();
         */
        CK_ATTRIBUTE[] wrappingkey = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, wrappingkey);
        long[] wrappingKeyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
        p11.C_FindObjectsFinal(sessionhandle);
        byte[] wrappedKey = p11.C_WrapKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS),
                wrappingKeyHandles[0], keyHandles[0]);
        fos = new FileOutputStream("wrapped.key");
        fos.write(wrappedKey);
        fos.close();
    }

    public static void importPubKey(PKCS11 p11, String passwd, long sessionhandle, String label, String keyFilePath)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, Base64DecodingException {

        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(keyFilePath));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();

        strKeyPEM = strKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        strKeyPEM = strKeyPEM.replace("-----END PUBLIC KEY-----", "");
        System.out.println(strKeyPEM);
        byte[] keyBytes = Base64.decode(strKeyPEM.trim());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        try {

            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(spec);

            CK_ATTRIBUTE[] searchTemplate = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
            p11.C_FindObjectsInit(sessionhandle, searchTemplate);

            long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
            p11.C_FindObjectsFinal(sessionhandle);
            if (keyHandles.length > 0) {
                System.out.println("The object with the same label " + label + " already exists.");
                System.exit(0);
            }
            ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, new BigInteger("1234", 16).toByteArray()));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODULUS, pubKey.getModulus().toByteArray()));
            attrList.add(
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_PUBLIC_EXPONENT, pubKey.getPublicExponent().toByteArray()));
            System.out.println("Importing wrapping key");
            p11.C_CreateObject(sessionhandle, attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));

        } catch (Exception e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

    }

    public static void destroyByLabel(PKCS11 p11, long sessionhandle, String label) throws PKCS11Exception {
        CK_ATTRIBUTE[] searchTemplate = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
        p11.C_FindObjectsInit(sessionhandle, searchTemplate);

        long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647); // number
        // of
        // objects
        // to
        // return.

        try {
            System.out.println("Deleting object");
            p11.C_DestroyObject(sessionhandle, keyHandles[0]);
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("Nothing to delete");
        }
    }

    public static void keyGen(PKCS11 p11, long sessionhandle, String label, int size, String keyType,
                              BigInteger publicExponent, String pubLabel, String priLabel) throws PKCS11Exception {

        if (label != null) {
            CK_ATTRIBUTE[] searchTemplate = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes()),};
            p11.C_FindObjectsInit(sessionhandle, searchTemplate);
            long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
            p11.C_FindObjectsFinal(sessionhandle);
            if (keyHandles.length > 0) {
                System.out.println("The object with the same label" + label + " already exists.");
                System.exit(0);
            }
        }
        if (pubLabel != null) {
            CK_ATTRIBUTE[] searchTemplate = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, pubLabel.getBytes()),};
            p11.C_FindObjectsInit(sessionhandle, searchTemplate);
            long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
            p11.C_FindObjectsFinal(sessionhandle);
            if (keyHandles.length > 0) {
                System.out.println("The object with the same label" + pubLabel + " already exists.");
                System.exit(0);
            }

        }
        if (priLabel != null) {
            CK_ATTRIBUTE[] searchTemplate = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, priLabel.getBytes()),};
            p11.C_FindObjectsInit(sessionhandle, searchTemplate);
            long[] keyHandles = p11.C_FindObjects(sessionhandle, 2147483647);
            p11.C_FindObjectsFinal(sessionhandle);
            if (keyHandles.length > 0) {
                System.out.println("The object with the same label" + priLabel + " already exists.");
                System.exit(0);
            }

        }
        if (keyType.toUpperCase().equals("ECC")) {
            ECParameterSpec params = null;
            ECPoint point = null;
            byte[] encodedParams =
                    ECUtil.encodeECParameterSpec(Security.getProvider("SunEC"), params);
            byte[] encodedPoint =
                    ECUtil.encodePoint(point, params.getCurve());
            ArrayList<CK_ATTRIBUTE> publicKey = new ArrayList<CK_ATTRIBUTE>();
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, pubLabel));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_EC));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, new BigInteger("1234", 16).toByteArray()));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, false));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODIFIABLE, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EC_PARAMS, encodedParams));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EC_POINT, encodedPoint));


            ArrayList<CK_ATTRIBUTE> privateKey = new ArrayList<CK_ATTRIBUTE>();
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, priLabel));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_EC));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODIFIABLE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EC_PARAMS, encodedParams));
            p11.C_GenerateKeyPair(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
                    publicKey.toArray(new CK_ATTRIBUTE[publicKey.size()]),
                    privateKey.toArray(new CK_ATTRIBUTE[privateKey.size()]));

        }
        if (keyType.toUpperCase().equals("DES")) {
            ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, false));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true));
            System.out.println("Generating key");
            p11.C_GenerateKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_DES_KEY_GEN), attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));
        }
        if (keyType.toUpperCase().equals("DES3") || keyType.toUpperCase().equals("3DES")) {
            ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));

            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_DES3));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, false));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true));
            System.out.println("Generating key");
            p11.C_GenerateKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_DES3_KEY_GEN),
                    attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));
        }
        if (keyType.toUpperCase().equals("RSA")) {
            if (publicExponent == null)
                publicExponent = BigInteger.valueOf(65537);
            ArrayList<CK_ATTRIBUTE> publicKey = new ArrayList<CK_ATTRIBUTE>();
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, pubLabel));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PUBLIC_KEY));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, new BigInteger("1234", 16).toByteArray()));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, false));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODIFIABLE, true));
            publicKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODULUS_BITS, size));

            publicKey.add(
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_PUBLIC_EXPONENT, publicExponent));
            ArrayList<CK_ATTRIBUTE> privateKey = new ArrayList<CK_ATTRIBUTE>();
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, priLabel));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_PRIVATE_KEY));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_RSA));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true));
            privateKey.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_MODIFIABLE, true));
            p11.C_GenerateKeyPair(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
                    publicKey.toArray(new CK_ATTRIBUTE[publicKey.size()]),
                    privateKey.toArray(new CK_ATTRIBUTE[privateKey.size()]));

        }
        if (keyType.toUpperCase().equals("AES")) {
            int keySize = size;
            if (size == 256)
                keySize = 32;
            if (size == 192)
                keySize = 24;
            if (size == 128)
                keySize = 16;

            System.out.println("Construct object attributes");

            ArrayList<CK_ATTRIBUTE> attrList = new ArrayList<CK_ATTRIBUTE>();
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE_LEN, keySize));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ID, label));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE, false));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN, true));
            attrList.add(new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY, true));

            System.out.println("Generating key");
            p11.C_GenerateKey(sessionhandle, new CK_MECHANISM(PKCS11Constants.CKM_AES_KEY_GEN),
                    attrList.toArray(new CK_ATTRIBUTE[attrList.size()]));

        }
    }

    public static void getInfo(PKCS11 p11, String passwd, long sessionhandle, long slot)
            throws PKCS11Exception, UnsupportedEncodingException {
        System.out.println("Openning session...");

        System.out.println();

        System.out.println("Getting session info...");
        CK_SESSION_INFO sessionInfo = p11.C_GetSessionInfo(sessionhandle);
        System.out.println(sessionInfo);
        System.out.println();

        System.out.println("Getting token info...");
        CK_TOKEN_INFO tokenInfo = p11.C_GetTokenInfo(slot);
        System.out.println(tokenInfo);
        System.out.println();

        System.out.println("Start searching for objects...");
        CK_ATTRIBUTE[] searchTemplate = {
                // Fill in the template if you know what you are searching for.
                // Otherwise leave it blank and it will return everything.
                // new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL,
                // "le-LunaCSPEnrollmentAgent-283ae1a3-cebc-4785-9875-0179fdc006ec".getBytes()),
        };
        p11.C_FindObjectsInit(sessionhandle, searchTemplate);

        long[] keyHandles = p11.C_FindObjects(sessionhandle, 5000000); // number
        // of
        // objects
        // to
        // return.
        System.out.println(keyHandles.length + " objects found.");
        System.out.println();

        CK_ATTRIBUTE[] commonAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL), // can
                // be
                // changed
                // after
                // generation
                // true for token, false for session. If true user may not
                // access the object until the user has been authenticated to
                // the token.
                new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS), new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_PRIVATE),

        };
        for (int i = 0; i < keyHandles.length; i++) {
            p11.C_GetAttributeValue(sessionhandle, keyHandles[i], commonAttributes);

            System.out.println("Object " + i + ": ");
            System.out.println(commonAttributes[0]);
            System.out.println(commonAttributes[1]);
            System.out.println(commonAttributes[3]);
            if (commonAttributes[1].toString().contains("CKO_SECRET_KEY"))
                getSecret(p11, sessionhandle, keyHandles[i]);
            if (commonAttributes[1].toString().contains("CKO_PUBLIC_KEY"))
                getPublic(p11, sessionhandle, keyHandles[i]);
            if (commonAttributes[1].toString().contains("CKO_PRIVATE_KEY"))
                getPrivate(p11, sessionhandle, keyHandles[i]);
            if (commonAttributes[1].toString().contains("CKO_DATA"))
                getData(p11, sessionhandle, keyHandles[i]);
            if (commonAttributes[1].toString().contains("CKO_CERTIFICATE"))
                getCertificate(p11, sessionhandle, keyHandles[i]);
            System.out.println();
        }

        p11.C_FindObjectsFinal(sessionhandle);
        System.out.println();

    }

    public static void logout(PKCS11 p11, long sessionhandle, String passwd) throws PKCS11Exception {
        System.out.println("Logging out...");
        try {
            p11.C_Logout(sessionhandle);
            System.out.println();

            System.out.println("Closing session...");
            p11.C_CloseSession(sessionhandle);
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void getPublic(PKCS11 p11, long sessionhandle, long keyHandle)
            throws PKCS11Exception, UnsupportedEncodingException {
        CK_ATTRIBUTE[] publicAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_ID), new CK_ATTRIBUTE(PKCS11Constants.CKA_START_DATE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_END_DATE), new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT), new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY_RECOVER), new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP),

        };
        p11.C_GetAttributeValue(sessionhandle, keyHandle, publicAttributes);
        System.out.println(publicAttributes[0]);
        try {
            System.out.println("CKA_ID = " + new String(
                    DatatypeConverter.parseHexBinary(publicAttributes[1].toString().replaceAll("CKA_ID = ", "")),
                    "UTF-8"));
        } catch (IllegalArgumentException ex) {
            System.out.println(publicAttributes[1]);
        }
        System.out.println(publicAttributes[2]);
        System.out.println(publicAttributes[3]);
        System.out.println(publicAttributes[4]);
        System.out.println(publicAttributes[5]);
        System.out.println(publicAttributes[6]);
        System.out.println(publicAttributes[7]);
        System.out.println(publicAttributes[8]);
    }

    public static void getPrivate(PKCS11 p11, long sessionhandle, long keyHandle)
            throws PKCS11Exception, UnsupportedEncodingException {
        CK_ATTRIBUTE[] privateAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_ID), new CK_ATTRIBUTE(PKCS11Constants.CKA_START_DATE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_END_DATE), new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE), new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN), new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN_RECOVER),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP), new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_NEVER_EXTRACTABLE)

        };
        p11.C_GetAttributeValue(sessionhandle, keyHandle, privateAttributes);
        System.out.println(privateAttributes[0]);
        try {
            System.out.println("CKA_ID = " + new String(
                    DatatypeConverter.parseHexBinary(privateAttributes[1].toString().replaceAll("CKA_ID = ", "")),
                    "UTF-8"));
        } catch (IllegalArgumentException ex) {
            System.out.println(privateAttributes[1]);
        }
        System.out.println(privateAttributes[2]);
        System.out.println(privateAttributes[3]);
        System.out.println(privateAttributes[4]);
        System.out.println(privateAttributes[5]);
        System.out.println(privateAttributes[6]);
        System.out.println(privateAttributes[7]);
        System.out.println(privateAttributes[8]);
        System.out.println(privateAttributes[9]);
        System.out.println(privateAttributes[10]);
        System.out.println(privateAttributes[11]);

    }

    public static void getSecret(PKCS11 p11, long sessionhandle, long keyHandle) throws PKCS11Exception {
        CK_ATTRIBUTE[] secretAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_ID), new CK_ATTRIBUTE(PKCS11Constants.CKA_START_DATE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_END_DATE), new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE), new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT), new CK_ATTRIBUTE(PKCS11Constants.CKA_SIGN),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_VERIFY), new CK_ATTRIBUTE(PKCS11Constants.CKA_WRAP),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_UNWRAP), new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_NEVER_EXTRACTABLE),


        };
        p11.C_GetAttributeValue(sessionhandle, keyHandle, secretAttributes);
        System.out.println(secretAttributes[0]);
        System.out.println(secretAttributes[1]);
        System.out.println(secretAttributes[2]);
        System.out.println(secretAttributes[3]);
        System.out.println(secretAttributes[4]);
        System.out.println(secretAttributes[5]);
        System.out.println(secretAttributes[6]);
        System.out.println(secretAttributes[7]);
        System.out.println(secretAttributes[8]);
        System.out.println(secretAttributes[9]);
        System.out.println(secretAttributes[10]);
        System.out.println(secretAttributes[11]);
        System.out.println(secretAttributes[12]);
        System.out.println(secretAttributes[13]);
    }

    public static void getData(PKCS11 p11, long sessionhandle, long keyHandle) throws PKCS11Exception {
        CK_ATTRIBUTE[] dataAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_APPLICATION),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE),

        };
        p11.C_GetAttributeValue(sessionhandle, keyHandle, dataAttributes);
        System.out.println(dataAttributes[0]);
        System.out.println(dataAttributes[1]);
    }

    public static void getCertificate(PKCS11 p11, long sessionhandle, long keyHandle)
            throws PKCS11Exception, UnsupportedEncodingException {
        CK_ATTRIBUTE[] certificateAttributes = {new CK_ATTRIBUTE(PKCS11Constants.CKA_CERTIFICATE_TYPE),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_SUBJECT), new CK_ATTRIBUTE(PKCS11Constants.CKA_ID),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_ISSUER), new CK_ATTRIBUTE(PKCS11Constants.CKA_SERIAL_NUMBER),
                new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE),

        };
        p11.C_GetAttributeValue(sessionhandle, keyHandle, certificateAttributes);
        System.out.println(certificateAttributes[0]);
        try {
            System.out.println("CKA_SUBJECT = " + new String(DatatypeConverter
                    .parseHexBinary(certificateAttributes[1].toString().replaceAll("CKA_SUBJECT = ", "")), "UTF-8"));
        } catch (IllegalArgumentException ex) {
            System.out.println(certificateAttributes[1]);
        }
        try {
            System.out.println("CKA_ID = " + new String(
                    DatatypeConverter.parseHexBinary(certificateAttributes[2].toString().replaceAll("CKA_ID = ", "")),
                    "UTF-8"));
        } catch (IllegalArgumentException ex) {
            System.out.println(certificateAttributes[2]);
        }
        try {
            System.out.println("CKA_ISSUER = " + new String(DatatypeConverter
                    .parseHexBinary(certificateAttributes[3].toString().replaceAll("CKA_ISSUER = ", "")), "UTF-8"));
        } catch (IllegalArgumentException ex) {
            System.out.println(certificateAttributes[3]);
        }

        System.out.println(certificateAttributes[4]);
        try {
            System.out.println("CKA_VALUE = " + Base64
                    .encode(new BigInteger(certificateAttributes[5].toString().replaceAll("CKA_VALUE = ", ""), 16)
                            .toByteArray()));
        } catch (IllegalArgumentException ex) {
            System.out.println(certificateAttributes[5]);
        }

    }

}
