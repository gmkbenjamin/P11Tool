package p11tool;

import p11tool.cli.CliOptions;
import p11tool.crypto.CryptoOperations;
import p11tool.crypto.KeyGenerator;
import p11tool.crypto.ObjectImporter;
import p11tool.crypto.Pkcs11Support;
import p11tool.crypto.TokenInspector;
import p11tool.gui.TokenMaster;
import p11tool.util.Hex;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

import java.io.Console;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * P11Tool entry point: PKCS#11 CLI for HSM / smart-card operations.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        int code = run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    static int run(String[] args) {
        try {
            CliOptions options = CliOptions.parse(args);
            if (options.helpRequested() || options.command() == CliOptions.Command.HELP) {
                System.out.println(CliOptions.usage());
                return 0;
            }
            options.validate();

            if (options.command() == CliOptions.Command.GUI) {
                TokenMaster.launch();
                return 0;
            }

            String pin = options.pin().orElseGet(Main::promptPin);
            PKCS11 p11 = Pkcs11Support.loadModule(options.lib());
            long[] slots = p11.C_GetSlotList(true);
            if (slots.length == 0 && options.command() != CliOptions.Command.GETINFO) {
                throw new IllegalStateException("no slots with tokens present");
            }

            switch (options.command()) {
                case GETINFO -> runGetInfo(p11, slots, options, pin);
                case KEYGEN -> withSession(p11, slots, options, pin, session -> {
                    KeyGenerator.generate(p11, session,
                            options.keyType().orElseThrow(),
                            options.effectiveKeyLabel(),
                            options.pubLabel().orElse(null),
                            options.priLabel().orElse(null),
                            options.keySize().orElse(null),
                            options.publicExponent().map(BigInteger::new).orElse(null),
                            options.curveOrDefault());
                });
                case GENERATE -> withSession(p11, slots, options, pin, session -> {
                    if (options.key1().isPresent()) {
                        ObjectImporter.xorCombine(p11, session,
                                options.key1().orElseThrow(),
                                options.key2().orElseThrow(),
                                options.key3().orElseThrow(),
                                options.keyType().orElseThrow(),
                                options.label().orElseThrow());
                    } else {
                        ObjectImporter.importHex(p11, session,
                                options.label().orElseThrow(),
                                options.in().orElseThrow(),
                                options.keyType().orElse(null));
                    }
                });
                case DESTROY -> withSession(p11, slots, options, pin,
                        session -> TokenInspector.destroyByLabel(p11, session, options.label().orElseThrow()));
                case EXPORT -> withSession(p11, slots, options, pin,
                        session -> TokenInspector.exportByLabel(p11, session, options.label().orElseThrow()));
                case WRAP -> withSession(p11, slots, options, pin, session -> {
                    if (options.keySize().isPresent()) {
                        KeyGenerator.generate(p11, session,
                                options.keyType().orElse("AES"),
                                options.keyLabel().orElseThrow(),
                                options.pubLabel().orElse(null),
                                options.priLabel().orElse(null),
                                options.keySize().orElse(null),
                                options.publicExponent().map(BigInteger::new).orElse(null),
                                options.curveOrDefault());
                    }
                    if (options.in().isPresent()) {
                        TokenInspector.importRsaPublicKey(p11, session, options.label().orElseThrow(),
                                TokenInspector.PathLike.of(options.in().orElseThrow()));
                    }
                    Path out = Path.of(options.out().orElse("wrapped.key"));
                    CryptoOperations.wrapKey(p11, session, options.label().orElseThrow(),
                            options.keyLabel().orElseThrow(), out);
                });
                case UNWRAP -> withSession(p11, slots, options, pin, session ->
                        CryptoOperations.unwrapKey(p11, session,
                                options.keyLabel().orElseThrow(),
                                options.label().orElseThrow(),
                                Path.of(options.in().orElseThrow()),
                                options.keyType().orElseThrow()));
                case ENCRYPT -> withSession(p11, slots, options, pin, session -> {
                    byte[] plaintext = readInputBytes(options.in().orElseThrow());
                    byte[] ciphertext = CryptoOperations.encrypt(p11, session, options.keyLabel().orElseThrow(),
                            plaintext, options.keyType().orElse(null), options.mechanism().orElse(null));
                    writeOutput(options.out().orElse(null), ciphertext, true);
                });
                case DECRYPT -> withSession(p11, slots, options, pin, session -> {
                    byte[] ciphertext = readBinaryOrHex(options.in().orElseThrow());
                    byte[] plaintext = CryptoOperations.decrypt(p11, session, options.keyLabel().orElseThrow(),
                            ciphertext, options.keyType().orElse(null), options.mechanism().orElse(null));
                    writeOutput(options.out().orElse(null), plaintext, false);
                });
                case SIGN -> withSession(p11, slots, options, pin, session -> {
                    byte[] data = readInputBytes(options.in().orElseThrow());
                    byte[] signature = CryptoOperations.sign(p11, session, options.keyLabel().orElseThrow(),
                            data, options.keyType().orElse(null), options.mechanism().orElse(null));
                    writeOutput(options.out().orElse("signature.bin"), signature, true);
                });
                case VERIFY -> withSession(p11, slots, options, pin, session -> {
                    byte[] data = readInputBytes(options.in().orElseThrow());
                    byte[] signature = Files.readAllBytes(Path.of(options.out().orElseThrow()));
                    boolean ok = CryptoOperations.verify(p11, session, options.keyLabel().orElseThrow(),
                            data, signature, options.keyType().orElse(null), options.mechanism().orElse(null));
                    System.out.println(ok ? "Signature VALID" : "Signature INVALID");
                    if (!ok) {
                        throw new IllegalStateException("signature verification failed");
                    }
                });
                default -> throw new IllegalStateException("unhandled command: " + options.command());
            }
            System.out.println("Done.");
            return 0;
        } catch (IllegalArgumentException ex) {
            System.err.println("Error: " + ex.getMessage());
            System.err.println();
            System.err.println(CliOptions.usage());
            return 2;
        } catch (Exception ex) {
            System.err.println("Error: " + ex.getMessage());
            ex.printStackTrace(System.err);
            return 1;
        }
    }

    private static void runGetInfo(PKCS11 p11, long[] slots, CliOptions options, String pin) throws Exception {
        TokenInspector.printModuleInfo(p11, slots);
        if (options.slotNum().isEmpty()) {
            return;
        }
        if (slots.length == 0) {
            System.out.println("No token-present slots to open.");
            return;
        }
        withSession(p11, slots, options, pin, session ->
                TokenInspector.listObjects(p11, session, slots[options.slotIndexOrDefault()]));
    }

    @FunctionalInterface
    private interface SessionWork {
        void run(long session) throws Exception;
    }

    private static void withSession(PKCS11 p11, long[] slots, CliOptions options, String pin, SessionWork work)
            throws Exception {
        int index = options.slotIndexOrDefault();
        if (index < 0 || index >= slots.length) {
            throw new IllegalArgumentException("slot index " + index + " out of range (0.." + (slots.length - 1)
                    + "); slot list=" + Arrays.toString(slots));
        }
        long session = Pkcs11Support.openRwSession(p11, slots[index]);
        try {
            Pkcs11Support.loginIfNeeded(p11, session, pin);
            work.run(session);
        } finally {
            Pkcs11Support.closeQuietly(p11, session);
        }
    }

    private static String promptPin() {
        Console console = System.console();
        if (console == null) {
            return "";
        }
        char[] chars = console.readPassword("Enter slot user PIN [optional, empty to skip login]: ");
        if (chars == null) {
            return "";
        }
        return new String(chars);
    }

    private static byte[] readInputBytes(String in) throws Exception {
        Path path = Path.of(in);
        if (Files.isRegularFile(path)) {
            return Files.readAllBytes(path);
        }
        return in.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] readBinaryOrHex(String in) throws Exception {
        Path path = Path.of(in);
        if (Files.isRegularFile(path)) {
            byte[] raw = Files.readAllBytes(path);
            // Prefer raw binary; if file is clearly hex text, decode it.
            String asText = new String(raw, StandardCharsets.US_ASCII).trim();
            if (asText.matches("(?i)[0-9a-f\\s]+") && (asText.replaceAll("\\s+", "").length() & 1) == 0
                    && asText.replaceAll("\\s+", "").length() >= 2) {
                try {
                    return Hex.decode(asText);
                } catch (IllegalArgumentException ignored) {
                    return raw;
                }
            }
            return raw;
        }
        return Hex.decode(in);
    }

    private static void writeOutput(String outPath, byte[] data, boolean preferHexStdout) throws Exception {
        if (outPath != null) {
            Files.write(Path.of(outPath), data);
            System.out.println("Wrote " + data.length + " bytes to " + Path.of(outPath).toAbsolutePath());
        } else if (preferHexStdout) {
            System.out.println(Hex.encode(data));
        } else {
            System.out.write(data);
            System.out.println();
        }
    }
}
