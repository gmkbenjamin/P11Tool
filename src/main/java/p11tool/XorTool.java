package p11tool;

import p11tool.util.Hex;
import p11tool.util.Kcv;

/**
 * Standalone XOR / KCV helper previously provided by {@code xor.java}.
 *
 * <pre>
 *   java -cp p11tool.jar p11tool.XorTool AES &lt;key1hex&gt; &lt;key2hex&gt; &lt;key3hex&gt;
 *   java -cp p11tool.jar p11tool.XorTool DES &lt;key1hex&gt; &lt;key2hex&gt; &lt;key3hex&gt;
 * </pre>
 */
public final class XorTool {

    private XorTool() {
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: XorTool <AES|DES|DES3|DECRYPT> <key1hex> <key2hex> <key3hex>");
            System.exit(2);
        }
        String mode = args[0].toUpperCase();
        byte[] key1 = Hex.decode(args[1]);
        byte[] key2 = Hex.decode(args[2]);
        byte[] key3 = Hex.decode(args[3]);

        if (mode.contains("DECRYPT")) {
            try {
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key1, "AES"));
                System.out.println(Hex.encodeUpper(cipher.doFinal(key2)));
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
            return;
        }

        String kcvType = mode.contains("AES") ? "AES" : "DES3";
        byte[] combined = Kcv.xorCombine(key1, key2, key3);
        System.out.println("Key 1: " + args[1]);
        System.out.println("KCV: " + Kcv.compute(key1, kcvType));
        System.out.println();
        System.out.println("Key 2: " + args[2]);
        System.out.println("KCV: " + Kcv.compute(key2, kcvType));
        System.out.println();
        System.out.println("Key 3: " + args[3]);
        System.out.println("KCV: " + Kcv.compute(key3, kcvType));
        System.out.println();
        System.out.println("Combined Key: " + Hex.encodeUpper(combined));
        System.out.println("KCV: " + Kcv.compute(combined, kcvType));
    }
}
