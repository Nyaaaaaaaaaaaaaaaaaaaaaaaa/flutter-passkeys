# HarmonyOS passkeys example

This standalone app lets you paste WebAuthn `publicKey` option JSON from your
own relying party, query FIDO2 availability, register, authenticate, and cancel
a pending Flutter operation. It prints the response JSON for server
verification. It does not include a relying party server.

Build with an OHOS enabled Flutter SDK and HarmonyOS SDK 6.0.0(20)+:

```sh
flutter pub get
flutter build hap --debug --no-codesign --no-pub
```

For device testing, replace the example bundle name, sign the HAP, and complete
the relying party setup for that app. Use a HarmonyOS 6.0.0(20)+ device.
Registration and authentication cannot be proven by a compiler-only build.
