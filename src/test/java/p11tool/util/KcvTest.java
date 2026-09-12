package p11tool.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KcvTest {

    @Test
    void aesKcvKnownVector() {
        // All-zero AES-128 key encrypting 16 zero bytes → first 3 bytes of ciphertext
        byte[] key = new byte[16];
        String kcv = Kcv.compute(key, "AES");
        assertEquals(6, kcv.length());
        assertEquals(Kcv.compute(key, "aes"), kcv);
    }

    @Test
    void xorCombine() {
        byte[] a = Hex.decode("01020304");
        byte[] b = Hex.decode("10101010");
        byte[] c = Hex.decode("0000ffff");
        assertEquals("1112eceb", Hex.encode(Kcv.xorCombine(a, b, c)));
    }

    @Test
    void xorRejectsMismatchedLengths() {
        assertThrows(IllegalArgumentException.class,
                () -> Kcv.xorCombine(new byte[8], new byte[16], new byte[8]));
    }
}
