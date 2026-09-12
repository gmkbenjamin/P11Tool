# P11Tool

Java command-line utility for common **PKCS#11** operations against HSMs and smart cards
(SoftHSM, Thales, Luna, Utimaco, and similar providers).

It talks to a vendor PKCS#11 shared library through the JDK’s
`sun.security.pkcs11.wrapper` JNI bindings (`jdk.crypto.cryptoki`).

## Requirements

- JDK **17+** (tested on 21)
- A PKCS#11 library (for example SoftHSM 2’s `libsofthsm2.so`)

Run with module exports so the JDK PKCS#11 wrapper is visible:

```bash
java --add-modules jdk.crypto.cryptoki \
     --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
     -jar target/p11tool-1.0.0.jar <command> -lib /path/to/pkcs11.so ...
```

## Build

```bash
mvn -q test package
```

Artifact: `target/p11tool-1.0.0.jar` (shaded, runnable).

## Commands

| Command | Purpose |
|---------|---------|
| `getinfo` | Module / slot / token info; with `-slotNum` also lists objects |
| `keygen` | Generate AES, DES, 3DES, RSA, or ECC keys |
| `generate` | Import hex data/secret key, or XOR-combine three extractable keys |
| `destroy` | Delete object(s) by label |
| `export` | Export public key PEM or extractable key material |
| `wrap` / `unwrap` | RSA-PKCS wrap / unwrap |
| `encrypt` / `decrypt` | Encrypt / decrypt with a token key |
| `sign` / `verify` | Sign / verify |
| `gui` | Minimal Token Master Swing UI (load library, login, list objects) |

```bash
# SoftHSM example
java --add-modules jdk.crypto.cryptoki \
     --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
     -jar target/p11tool-1.0.0.jar keygen \
     -lib /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
     -slotNum 0 -pin 1234 -keyType AES -keyLabel aes1 -keySize 256

java ... getinfo -lib /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -slotNum 0 -pin 1234
```

See `java -jar ... help` for the full option list.

## Sample PKCS#11 configs

`config/` contains sample SunPKCS11 provider config snippets for SoftHSM, Luna, Thales, and Utimaco.
They are optional; the CLI loads the shared library path via `-lib` directly.

## Offline XOR / KCV helper

```bash
java -cp target/p11tool-1.0.0.jar p11tool.XorTool AES <key1hex> <key2hex> <key3hex>
```

## Project layout

- `src/main/java/p11tool` — application code (CLI, crypto ops, GUI)
- `vendor/iaik` — vendored IAIK PKCS#11 high-level wrapper (not on the compile path; kept for reference / future native-free paths)
- `vendor/native` — historical JNI sources for the IAIK wrapper

## Notes / assumptions

- `-slotNum` is an **index** into `C_GetSlotList(true)`, not necessarily the raw slot ID.
- Default mechanisms: AES/DES CBC-PAD for encrypt; `CKM_SHA256_RSA_PKCS` for RSA sign; software SHA-256 + `CKM_ECDSA` for ECC (override with `-mechanism`).
- XOR `generate -key1/2/3` exports component key values from the token (same limitation as the original tool).
- Windows single-file packaging via launch4j is deferred; use the runnable JAR.
- Vendor-specific attributes (e.g. Thales `CKNFAST_OVERRIDE_SECURITY_ASSURANCES`) remain environment/config concerns outside this tool.

## License

Original project did not declare a license. The vendored IAIK sources retain their upstream notices.
