package p11tool.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CliOptionsTest {

    @Test
    void parsesKeygen() {
        CliOptions opts = CliOptions.parse(new String[]{
                "keygen", "-lib", "/tmp/lib.so", "-keyType", "AES", "-keyLabel", "k1", "-keySize", "256", "-slotNum", "1"
        });
        opts.validate();
        assertEquals(CliOptions.Command.KEYGEN, opts.command());
        assertEquals("/tmp/lib.so", opts.lib());
        assertEquals("AES", opts.keyType().orElseThrow());
        assertEquals("k1", opts.effectiveKeyLabel());
        assertEquals(256, opts.keySize().orElseThrow());
        assertEquals(1, opts.slotIndexOrDefault());
    }

    @Test
    void helpWhenEmpty() {
        CliOptions opts = CliOptions.parse(new String[]{});
        assertTrue(opts.helpRequested());
        assertEquals(CliOptions.Command.HELP, opts.command());
    }

    @Test
    void rejectsMultipleCommands() {
        assertThrows(IllegalArgumentException.class,
                () -> CliOptions.parse(new String[]{"encrypt", "decrypt", "-lib", "x"}));
    }

    @Test
    void validateRequiresLib() {
        CliOptions opts = CliOptions.parse(new String[]{"getinfo"});
        assertThrows(IllegalArgumentException.class, opts::validate);
    }
}
