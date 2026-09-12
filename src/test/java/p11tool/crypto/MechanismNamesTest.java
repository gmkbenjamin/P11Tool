package p11tool.crypto;

import org.junit.jupiter.api.Test;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MechanismNamesTest {

    @Test
    void resolvesSymbolicNames() {
        assertEquals(PKCS11Constants.CKM_AES_CBC_PAD, MechanismNames.resolve("CKM_AES_CBC_PAD"));
        assertEquals(PKCS11Constants.CKM_AES_CBC_PAD, MechanismNames.resolve("AES_CBC_PAD"));
        assertEquals(PKCS11Constants.CKM_RSA_PKCS, MechanismNames.resolve("0x1"));
    }

    @Test
    void rejectsUnknown() {
        assertThrows(IllegalArgumentException.class, () -> MechanismNames.resolve("CKM_NOT_A_REAL_MECH"));
    }
}
