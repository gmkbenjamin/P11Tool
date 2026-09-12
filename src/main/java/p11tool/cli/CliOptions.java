package p11tool.cli;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Parsed CLI arguments for P11Tool.
 */
public final class CliOptions {

    public enum Command {
        GETINFO,
        KEYGEN,
        GENERATE,
        DESTROY,
        EXPORT,
        WRAP,
        UNWRAP,
        ENCRYPT,
        DECRYPT,
        SIGN,
        VERIFY,
        GUI,
        HELP
    }

    private final Command command;
    private final String lib;
    private final String pin;
    private final Integer slotNum;
    private final String in;
    private final String out;
    private final Integer keySize;
    private final String keyLabel;
    private final String label;
    private final String keyType;
    private final String pubLabel;
    private final String priLabel;
    private final String key1;
    private final String key2;
    private final String key3;
    private final String publicExponent;
    private final String curve;
    private final String mechanism;
    private final boolean helpRequested;

    private CliOptions(Builder b) {
        this.command = b.command;
        this.lib = b.lib;
        this.pin = b.pin;
        this.slotNum = b.slotNum;
        this.in = b.in;
        this.out = b.out;
        this.keySize = b.keySize;
        this.keyLabel = b.keyLabel;
        this.label = b.label;
        this.keyType = b.keyType;
        this.pubLabel = b.pubLabel;
        this.priLabel = b.priLabel;
        this.key1 = b.key1;
        this.key2 = b.key2;
        this.key3 = b.key3;
        this.publicExponent = b.publicExponent;
        this.curve = b.curve;
        this.mechanism = b.mechanism;
        this.helpRequested = b.helpRequested;
    }

    public static CliOptions parse(String[] args) {
        if (args == null || args.length == 0) {
            return new Builder().helpRequested(true).command(Command.HELP).build();
        }

        Builder builder = new Builder();
        Set<Command> commands = new LinkedHashSet<>();

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            String lower = arg.toLowerCase(Locale.ROOT);
            switch (lower) {
                case "getinfo" -> commands.add(Command.GETINFO);
                case "keygen" -> commands.add(Command.KEYGEN);
                case "generate" -> commands.add(Command.GENERATE);
                case "destroy" -> commands.add(Command.DESTROY);
                case "export" -> commands.add(Command.EXPORT);
                case "wrap" -> commands.add(Command.WRAP);
                case "unwrap" -> commands.add(Command.UNWRAP);
                case "encrypt" -> commands.add(Command.ENCRYPT);
                case "decrypt" -> commands.add(Command.DECRYPT);
                case "sign" -> commands.add(Command.SIGN);
                case "verify" -> commands.add(Command.VERIFY);
                case "gui" -> commands.add(Command.GUI);
                case "-h", "--help", "help" -> builder.helpRequested(true);
                case "-lib" -> builder.lib(requireValue(args, ++i, "-lib"));
                case "-pin" -> builder.pin(requireValue(args, ++i, "-pin"));
                case "-slotnum" -> builder.slotNum(Integer.valueOf(requireValue(args, ++i, "-slotNum")));
                case "-in" -> builder.in(requireValue(args, ++i, "-in"));
                case "-out" -> builder.out(requireValue(args, ++i, "-out"));
                case "-keysize" -> builder.keySize(Integer.valueOf(requireValue(args, ++i, "-keySize")));
                case "-keylabel" -> builder.keyLabel(requireValue(args, ++i, "-keyLabel"));
                case "-label" -> builder.label(requireValue(args, ++i, "-label"));
                case "-keytype" -> builder.keyType(requireValue(args, ++i, "-keyType"));
                case "-publabel" -> builder.pubLabel(requireValue(args, ++i, "-pubLabel"));
                case "-prilabel" -> builder.priLabel(requireValue(args, ++i, "-priLabel"));
                case "-key1" -> builder.key1(requireValue(args, ++i, "-key1"));
                case "-key2" -> builder.key2(requireValue(args, ++i, "-key2"));
                case "-key3" -> builder.key3(requireValue(args, ++i, "-key3"));
                case "-publicexponent" -> builder.publicExponent(requireValue(args, ++i, "-publicExponent"));
                case "-curve" -> builder.curve(requireValue(args, ++i, "-curve"));
                case "-mechanism" -> builder.mechanism(requireValue(args, ++i, "-mechanism"));
                default -> throw new IllegalArgumentException("unknown argument: " + arg);
            }
        }

        if (builder.helpRequested || commands.contains(Command.HELP) || commands.isEmpty()) {
            if (commands.isEmpty() || builder.helpRequested) {
                builder.command(Command.HELP);
                builder.helpRequested(true);
                return builder.build();
            }
        }

        if (commands.size() != 1) {
            throw new IllegalArgumentException("exactly one command is required, got: " + commands);
        }
        builder.command(commands.iterator().next());
        return builder.build();
    }

    private static String requireValue(String[] args, int index, String flag) {
        if (index >= args.length) {
            throw new IllegalArgumentException("missing value for " + flag);
        }
        return args[index];
    }

    public static String usage() {
        return """
                P11Tool — PKCS#11 utility

                Usage:
                  java --add-modules jdk.crypto.cryptoki \\
                       --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \\
                       -jar p11tool.jar <command> -lib <pkcs11-library> [options]

                Commands:
                  getinfo   Show module / slot / token / object information
                  keygen    Generate AES, DES, 3DES, RSA, or ECC keys
                  generate  Import hex data or secret key material (or XOR-combine -key1/2/3)
                  destroy   Destroy object(s) by label
                  export    Export public key PEM or extractable secret/private key material
                  wrap      Import wrapping public key (optional) and wrap a key with RSA-PKCS
                  unwrap    Unwrap a wrapped key blob onto the token
                  encrypt   Encrypt with a token key
                  decrypt   Decrypt with a token key
                  sign      Sign data with a private/secret key
                  verify    Verify a signature with a public/secret key
                  gui       Launch the basic Token Master GUI

                Common options:
                  -lib <path>           PKCS#11 shared library (required except gui/help)
                  -slotNum <index>      Index into C_GetSlotList(true) (default 0 for ops)
                  -pin <pin>            User PIN (prompted if omitted and a console is available)
                  -label <name>         Object label
                  -keyLabel <name>      Key label (wrap/unwrap/encrypt/decrypt/sign/verify)
                  -keyType <type>       AES | DES | DES3 | RSA | ECC
                  -keySize <bits>       Key size (AES 128/192/256, RSA modulus bits)
                  -pubLabel / -priLabel Labels for key-pair generation
                  -in / -out            Input / output file paths
                  -curve <name>         EC curve for ECC keygen (default secp256r1)
                  -mechanism <name>     Optional mechanism override (e.g. CKM_AES_CBC_PAD)
                  -key1 -key2 -key3     Labels of three extractable components to XOR-combine
                """;
    }

    public void validate() {
        if (helpRequested || command == Command.HELP || command == Command.GUI) {
            return;
        }
        if (lib == null || lib.isBlank()) {
            throw new IllegalArgumentException("-lib is required");
        }
        switch (command) {
            case DESTROY, EXPORT -> require(label != null, "-label is required");
            case KEYGEN -> {
                require(keyType != null, "-keyType is required");
                String type = keyType.toUpperCase(Locale.ROOT);
                if (type.equals("RSA") || type.equals("ECC")) {
                    require(pubLabel != null && priLabel != null, "-pubLabel and -priLabel are required for " + type);
                } else {
                    require(keyLabel != null || label != null, "-keyLabel (or -label) is required");
                }
            }
            case GENERATE -> {
                require(label != null, "-label is required");
                boolean combine = key1 != null || key2 != null || key3 != null;
                if (combine) {
                    require(key1 != null && key2 != null && key3 != null, "-key1 -key2 -key3 are all required to combine");
                    require(keyType != null, "-keyType is required when combining keys");
                } else {
                    require(in != null, "-in (hex string or file) is required");
                }
            }
            case WRAP -> require(label != null && keyLabel != null, "-label (wrapping key) and -keyLabel (key to wrap) are required");
            case UNWRAP -> require(label != null && keyLabel != null && in != null && keyType != null,
                    "-label, -keyLabel, -in and -keyType are required");
            case ENCRYPT, DECRYPT, SIGN -> require(keyLabel != null && in != null, "-keyLabel and -in are required");
            case VERIFY -> require(keyLabel != null && in != null && out != null,
                    "-keyLabel, -in (data) and -out (signature file) are required");
            case GETINFO -> {
                // slot optional
            }
            default -> {
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    public Command command() {
        return command;
    }

    public String lib() {
        return lib;
    }

    public Optional<String> pin() {
        return Optional.ofNullable(pin);
    }

    public Optional<Integer> slotNum() {
        return Optional.ofNullable(slotNum);
    }

    public int slotIndexOrDefault() {
        return slotNum != null ? slotNum : 0;
    }

    public Optional<String> in() {
        return Optional.ofNullable(in);
    }

    public Optional<String> out() {
        return Optional.ofNullable(out);
    }

    public Optional<Integer> keySize() {
        return Optional.ofNullable(keySize);
    }

    public Optional<String> keyLabel() {
        return Optional.ofNullable(keyLabel);
    }

    public String effectiveKeyLabel() {
        return keyLabel != null ? keyLabel : label;
    }

    public Optional<String> label() {
        return Optional.ofNullable(label);
    }

    public Optional<String> keyType() {
        return Optional.ofNullable(keyType);
    }

    public Optional<String> pubLabel() {
        return Optional.ofNullable(pubLabel);
    }

    public Optional<String> priLabel() {
        return Optional.ofNullable(priLabel);
    }

    public Optional<String> key1() {
        return Optional.ofNullable(key1);
    }

    public Optional<String> key2() {
        return Optional.ofNullable(key2);
    }

    public Optional<String> key3() {
        return Optional.ofNullable(key3);
    }

    public Optional<String> publicExponent() {
        return Optional.ofNullable(publicExponent);
    }

    public String curveOrDefault() {
        return curve != null ? curve : "secp256r1";
    }

    public Optional<String> mechanism() {
        return Optional.ofNullable(mechanism);
    }

    public boolean helpRequested() {
        return helpRequested;
    }

    public static final class Builder {
        private Command command = Command.HELP;
        private String lib;
        private String pin;
        private Integer slotNum;
        private String in;
        private String out;
        private Integer keySize;
        private String keyLabel;
        private String label;
        private String keyType;
        private String pubLabel;
        private String priLabel;
        private String key1;
        private String key2;
        private String key3;
        private String publicExponent;
        private String curve;
        private String mechanism;
        private boolean helpRequested;

        public Builder command(Command command) {
            this.command = command;
            return this;
        }

        public Builder lib(String lib) {
            this.lib = lib;
            return this;
        }

        public Builder pin(String pin) {
            this.pin = pin;
            return this;
        }

        public Builder slotNum(Integer slotNum) {
            this.slotNum = slotNum;
            return this;
        }

        public Builder in(String in) {
            this.in = in;
            return this;
        }

        public Builder out(String out) {
            this.out = out;
            return this;
        }

        public Builder keySize(Integer keySize) {
            this.keySize = keySize;
            return this;
        }

        public Builder keyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
            return this;
        }

        public Builder label(String label) {
            this.label = label;
            return this;
        }

        public Builder keyType(String keyType) {
            this.keyType = keyType;
            return this;
        }

        public Builder pubLabel(String pubLabel) {
            this.pubLabel = pubLabel;
            return this;
        }

        public Builder priLabel(String priLabel) {
            this.priLabel = priLabel;
            return this;
        }

        public Builder key1(String key1) {
            this.key1 = key1;
            return this;
        }

        public Builder key2(String key2) {
            this.key2 = key2;
            return this;
        }

        public Builder key3(String key3) {
            this.key3 = key3;
            return this;
        }

        public Builder publicExponent(String publicExponent) {
            this.publicExponent = publicExponent;
            return this;
        }

        public Builder curve(String curve) {
            this.curve = curve;
            return this;
        }

        public Builder mechanism(String mechanism) {
            this.mechanism = mechanism;
            return this;
        }

        public Builder helpRequested(boolean helpRequested) {
            this.helpRequested = helpRequested;
            return this;
        }

        public CliOptions build() {
            return new CliOptions(this);
        }
    }

    @Override
    public String toString() {
        return "CliOptions{command=" + command + ", lib=" + lib + ", args=" + Arrays.toString(new Object[]{
                slotNum, label, keyLabel, keyType
        }) + "}";
    }
}
