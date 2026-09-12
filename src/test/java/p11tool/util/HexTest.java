package p11tool.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HexTest {

    @Test
    void roundTrip() {
        byte[] original = new byte[]{0x00, 0x0a, (byte) 0xff, 0x10};
        assertEquals("000aff10", Hex.encode(original));
        assertArrayEquals(original, Hex.decode("000AFF10"));
        assertArrayEquals(original, Hex.decode("00 0a ff 10"));
    }

    @Test
    void rejectsOddLength() {
        assertThrows(IllegalArgumentException.class, () -> Hex.decode("abc"));
    }
}
