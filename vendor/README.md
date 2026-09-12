# Vendored upstream material (not compiled by the Maven build)

- `iaik/` — IAIK PKCS#11 wrapper Java sources historically bundled with this repo
- `native/` — JNI / platform build files for that wrapper

P11Tool’s runtime path uses the JDK `jdk.crypto.cryptoki` PKCS#11 bindings instead.
Keep these trees for reference or a future optional backend.
