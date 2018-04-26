import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class xor {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        byte[] keybytes1 = hexStringToByteArray(args[1]);
        byte[] keybytes2 = hexStringToByteArray(args[2]);
        byte[] keybytes3 = hexStringToByteArray(args[3]);
        byte[] finalkeybytes = new byte[keybytes1.length];
        String kcvfinal = "";
        String kcv1 = "";
        String kcv2 = "";
        String kcv3 = "";

        for (int i = 0; i < keybytes1.length; i++) {
            finalkeybytes[i] = (byte) ((keybytes1[i] ^ keybytes2[i]) ^ keybytes3[i]);
        }

        byte[] data = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


        if (args[0].toUpperCase().contains("DECRYPT")) {
            SecretKeySpec skeySpec = new SecretKeySpec(keybytes1, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NOPADDING");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(skeySpec.getEncoded(), "AES"));
            byte[] original = cipher.doFinal(keybytes2);
            System.out.println(byteArrayToHexString(original).toUpperCase());
        }


        if (args[0].toUpperCase().contains("DES")) {
            data = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            IvParameterSpec iv = new IvParameterSpec(data);
            SecretKeySpec skeySpec = new SecretKeySpec(keybytes1, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/CBC/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(data);
            kcv1 = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(keybytes2, "DESede");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcv2 = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(keybytes3, "DESede");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcv3 = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(finalkeybytes, "DESede");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcvfinal = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();

        }


        if (args[0].toUpperCase().contains("AES")) {
            IvParameterSpec iv = new IvParameterSpec(data);
            SecretKeySpec skeySpec = new SecretKeySpec(keybytes1, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(data);
            kcv1 = byteArrayToHexString(encrypted).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(keybytes2, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcv2 = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(keybytes3, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcv3 = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();


            skeySpec = new SecretKeySpec(finalkeybytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            kcvfinal = byteArrayToHexString(cipher.doFinal(data)).substring(0, 6).toUpperCase();


        }
        System.out.println("Key 1: " + args[1]);
        System.out.println("KCV: " + kcv1);
        System.out.println("");
        System.out.println("Key 2: " + args[2]);
        System.out.println("KCV: " + kcv2);
        System.out.println("");
        System.out.println("Key 3: " + args[3]);
        System.out.println("KCV: " + kcv3);
        System.out.println("");
        System.out.println("Combined Key: " + byteArrayToHexString(finalkeybytes).toUpperCase());
        System.out.println("KCV: " + kcvfinal);

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

}
