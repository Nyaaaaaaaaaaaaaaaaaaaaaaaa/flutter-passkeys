# passkeys_ohos

HarmonyOS NEXT implementation of the federated `passkeys` Flutter plugin. It
uses Huawei Online Authentication Kit's `fido2` API on HarmonyOS 6.0.0(20) or
newer. Android, iOS, and the other existing platform implementations remain in
the same fork.

## Install from Git

Use the main `passkeys` package. Flutter registers `passkeys_ohos` automatically
on OHOS; the sibling platform packages resolve from the same Git revision.

```yaml
dependencies:
  passkeys:
    git:
      url: https://github.com/Nyaaaaaaaaaaaaaaaaaaaaaaaa/flutter-passkeys.git
      ref: v2.23.1-ohos.1
      path: packages/passkeys/passkeys
```

Use an OHOS enabled Flutter toolchain and a HarmonyOS SDK containing
`@kit.OnlineAuthenticationKit`. The standalone example is under
`examples/passkeys_ohos_example`. This fork is distributed through Git tags and
GitHub Releases; no pub.dev or OHPM publication is needed.

## Operations

- `register`: WebAuthn creation options to `fido2.register` and a standard
  nested attestation response.
- `authenticate`: request options to `fido2.authenticate` and a standard
  nested assertion response.
- `getAvailability` / `canAuthenticate`: FIDO2 client capability query.
- `cancelCurrentAuthenticatorOperation`: completes the pending Flutter call as
  cancelled. Huawei's public FIDO2 API does not expose a call to dismiss an
  already shown system sheet; a new ceremony can start after that native call
  finishes.

Challenge, user ID, credential IDs, and response bytes cross the method channel
as Base64URL text; the native API receives and returns `Uint8Array`. The plugin
maps user abort/rejection, timeout, no credential, device unsupported, and
remaining native errors to the existing Dart exception contract. The PRF and
other WebAuthn extensions are rejected explicitly because the HarmonyOS 6 FIDO2
API does not expose equivalent extension outputs.

Use a relying party that issues and verifies WebAuthn challenges for your RP ID.
Configure the signed app and relying party according to Huawei's
[passkey integration guide](https://developer.huawei.com/consumer/cn/doc/doccenter-capabilities/onlineauthentication-passwordless-auth)
before device testing. The repository's example HAP is unsigned and contains no
production relying party or credentials.

## Build and validation

From `examples/passkeys_ohos_example`:

```sh
flutter pub get
flutter build hap --debug --no-codesign --no-pub
```

The GitHub PR workflow builds this HAP and checks that its ArkTS bytecode
contains `PasskeysOhosPlugin`. The tagged Release contains the unsigned HAP and
`SHA256SUMS`. Actual registration, authentication, system cancellation UI, and
server verification require a HarmonyOS 6 device and a configured relying
party.
