import 'package:flutter/material.dart';
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';

void main() => runApp(const PasskeysOhosExample());

class PasskeysOhosExample extends StatefulWidget {
  const PasskeysOhosExample({super.key});

  @override
  State<PasskeysOhosExample> createState() => _PasskeysOhosExampleState();
}

class _PasskeysOhosExampleState extends State<PasskeysOhosExample> {
  final authenticator = PasskeyAuthenticator();
  final request = TextEditingController();
  String result = 'Paste WebAuthn publicKey options from your relying party.';

  @override
  void dispose() {
    request.dispose();
    super.dispose();
  }

  Future<void> run(Future<String> Function() operation) async {
    try {
      final value = await operation();
      if (mounted) setState(() => result = value);
    } catch (error) {
      if (mounted) setState(() => result = error.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Passkeys on HarmonyOS')),
        body: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextField(
              controller: request,
              maxLines: 8,
              decoration: const InputDecoration(
                labelText: 'Registration or authentication options JSON',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: () => run(() async {
                final availability = await authenticator
                    .getAvailability()
                    .ohos();
                return 'Passkeys: ${availability.hasPasskeySupport}\n'
                    'User verification: '
                    '${availability.isUserVerifyingPlatformAuthenticatorAvailable}\n'
                    'Conditional mediation: '
                    '${availability.isConditionalMediationAvailable}';
              }),
              child: const Text('Check availability'),
            ),
            FilledButton(
              onPressed: () => run(
                () async => (await authenticator.register(
                  RegisterRequestType.fromJsonString(request.text),
                )).toJsonString(),
              ),
              child: const Text('Register'),
            ),
            FilledButton(
              onPressed: () => run(
                () async => (await authenticator.authenticate(
                  AuthenticateRequestType.fromJsonString(request.text),
                )).toJsonString(),
              ),
              child: const Text('Authenticate'),
            ),
            OutlinedButton(
              onPressed: () => run(() async {
                await authenticator.cancelCurrentAuthenticatorOperation();
                return 'Flutter request cancelled';
              }),
              child: const Text('Cancel pending request'),
            ),
            const SizedBox(height: 12),
            SelectableText(result),
          ],
        ),
      ),
    );
  }
}
