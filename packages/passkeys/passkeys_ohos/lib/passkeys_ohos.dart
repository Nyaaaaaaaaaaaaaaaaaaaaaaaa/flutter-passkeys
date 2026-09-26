import 'package:flutter/services.dart';
import 'package:passkeys_platform_interface/passkeys_platform_interface.dart';
import 'package:passkeys_platform_interface/types/types.dart';

/// HarmonyOS NEXT implementation of [PasskeysPlatform].
class PasskeysOhos extends PasskeysPlatform {
  /// Creates an instance; [channel] can be supplied by tests.
  PasskeysOhos({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel('passkeys_ohos');

  /// Registers the implementation with Flutter's federated plugin loader.
  static void registerWith() => PasskeysPlatform.instance = PasskeysOhos();

  final MethodChannel _channel;

  @override
  Future<bool> canAuthenticate() async =>
      await _channel.invokeMethod<bool>('canAuthenticate') ?? false;

  @override
  Future<AvailabilityTypeOHOS> getAvailability() async {
    final capabilities = await _channel.invokeMapMethod<String, bool>(
      'getAvailability',
    );
    return AvailabilityTypeOHOS(
      hasPasskeySupport: capabilities?['hasPasskeySupport'] ?? false,
      isUserVerifyingPlatformAuthenticatorAvailable:
          capabilities?['isUserVerifyingPlatformAuthenticatorAvailable'] ??
          false,
      isConditionalMediationAvailable:
          capabilities?['isConditionalMediationAvailable'] ?? false,
    );
  }

  @override
  Future<RegisterResponseType> register(RegisterRequestType request) async {
    final response = await _channel.invokeMethod<String>(
      'register',
      request.toJsonString(),
    );
    return RegisterResponseType.fromJsonString(response!);
  }

  @override
  Future<AuthenticateResponseType> authenticate(
    AuthenticateRequestType request,
  ) async {
    final response = await _channel.invokeMethod<String>('authenticate', {
      'options': request.toJsonString(),
      'mediation': request.mediation.name.toLowerCase(),
      'preferImmediatelyAvailableCredentials':
          request.preferImmediatelyAvailableCredentials,
      'canBeSecurityKey': request.canBeSecurityKey,
    });
    return AuthenticateResponseType.fromJsonString(response!);
  }

  @override
  Future<void> cancelCurrentAuthenticatorOperation() =>
      _channel.invokeMethod<void>('cancelCurrentAuthenticatorOperation');
}
