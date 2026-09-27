import {
  AbilityAware, AbilityPluginBinding, FlutterPlugin, FlutterPluginBinding,
  MethodCall, MethodCallHandler, MethodChannel, MethodResult,
} from '@ohos/flutter_ohos';
import { common } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { fido2 } from '@kit.OnlineAuthenticationKit';
import { util } from '@kit.ArkTS';

interface CredentialJson {
  type: string;
  id: string;
  transports?: string[];
}

interface RpJson {
  id?: string;
  name: string;
}

interface UserJson {
  id: string;
  name: string;
  displayName: string;
}

interface ParameterJson {
  type: string;
  alg: number;
}

interface SelectionJson {
  authenticatorAttachment?: string;
  residentKey?: string;
  requireResidentKey?: boolean;
  userVerification?: string;
}

interface AttestationResponseJson {
  clientDataJSON: string;
  attestationObject: string;
  transports?: string[];
}

interface AssertionResponseJson {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string;
}

interface ResultJson<T> {
  id: string;
  rawId: string;
  type: string;
  response: T;
  clientExtensionResults: Record<string, string>;
}

interface AvailabilityJson {
  hasPasskeySupport: boolean;
  isUserVerifyingPlatformAuthenticatorAvailable: boolean;
  isConditionalMediationAvailable: boolean;
}

interface RegisterJson {
  challenge: string;
  rp: RpJson;
  user: UserJson;
  pubKeyCredParams?: Array<ParameterJson>;
  excludeCredentials?: CredentialJson[];
  authenticatorSelection?: SelectionJson;
  timeout?: number;
  attestation?: string;
  extensions?: Record<string, Object>;
}

interface AuthenticateJson {
  challenge: string;
  rpId: string;
  allowCredentials?: CredentialJson[];
  timeout?: number;
  userVerification?: string;
  extensions?: Record<string, Object>;
}

const base64 = new util.Base64Helper();

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value) || value.length % 4 === 1) {
    throw new Error('Invalid base64url value');
  }
  const standard = value.replace(/-/g, '+').replace(/_/g, '/');
  return base64.decodeSync(standard.padEnd(Math.ceil(standard.length / 4) * 4, '='), util.Type.BASIC);
}

function encodeBase64Url(value: Uint8Array): string {
  return base64.encodeToStringSync(value, util.Type.BASIC_URL_SAFE).replace(/=+$/, '');
}

function credential(json: CredentialJson): fido2.PublicKeyCredentialDescriptor {
  return {
    type: json.type as fido2.PublicKeyCredentialType,
    id: decodeBase64Url(json.id),
    transports: json.transports?.map((transport) => transport as fido2.AuthenticatorTransport),
  };
}

function nativeError(error: BusinessError, operation: string): string {
  switch (error.code) {
    case 801:
    case 1021300001:
      return 'deviceNotSupported';
    case 1021300004:
    case 1021300010:
      return 'cancelled';
    case 1021300005:
      return 'ohos-timeout';
    case 1021310006:
      return 'no-credentials-available';
    case 1021300012:
      return 'ohos-unhandled-credential-limit';
    default:
      return `ohos-unhandled-${operation}-${error.code}`;
  }
}

/** HarmonyOS NEXT 6.0.0(20)+ FIDO2 bridge. */
export default class PasskeysOhosPlugin implements FlutterPlugin, MethodCallHandler, AbilityAware {
  private channel: MethodChannel | null = null;
  private context: common.UIAbilityContext | null = null;
  private pending: MethodResult | null = null;
  private nativeBusy: boolean = false;

  getUniqueClassName(): string { return 'PasskeysOhosPlugin'; }

  onAttachedToEngine(binding: FlutterPluginBinding): void {
    this.channel = new MethodChannel(binding.getBinaryMessenger(), 'passkeys_ohos');
    this.channel.setMethodCallHandler(this);
  }

  onDetachedFromEngine(_binding: FlutterPluginBinding): void {
    this.cancelPending();
    this.channel?.setMethodCallHandler(null);
    this.channel = null;
  }

  onAttachedToAbility(binding: AbilityPluginBinding): void {
    this.context = binding.getAbility().context;
  }

  onDetachedFromAbility(): void {
    this.cancelPending();
    this.context = null;
  }

  onMethodCall(call: MethodCall, result: MethodResult): void {
    switch (call.method) {
      case 'getAvailability':
        this.getAvailability().then((availability) => result.success(availability));
        return;
      case 'canAuthenticate':
        this.getAvailability().then((availability) => result.success(availability.hasPasskeySupport));
        return;
      case 'register':
        this.run(result, 'register', async (context) => {
          const json = JSON.parse(call.args as string) as RegisterJson;
          if (json.extensions && Object.keys(json.extensions).length > 0) {
            throw new Error('OHOS FIDO2 does not expose the requested WebAuthn extension');
          }
           const defaultParams: Array<ParameterJson> = [
             { type: 'public-key', alg: -7 },
             { type: 'public-key', alg: -257 },
           ];
           const options: fido2.PublicKeyCredentialCreationOptions = {
            rp: json.rp,
            user: {
              id: decodeBase64Url(json.user.id),
              name: json.user.name,
              displayName: json.user.displayName,
            },
            challenge: decodeBase64Url(json.challenge),
             pubKeyCredParams: (json.pubKeyCredParams ?? defaultParams).map((param): fido2.PublicKeyCredentialParameters => ({
              type: param.type as fido2.PublicKeyCredentialType,
              alg: param.alg as fido2.Algorithm,
            })),
            timeout: json.timeout,
            excludeCredentials: json.excludeCredentials?.map(credential),
            authenticatorSelection: json.authenticatorSelection ? {
              authenticatorAttachment: json.authenticatorSelection.authenticatorAttachment as fido2.AuthenticatorAttachment,
              residentKey: json.authenticatorSelection.residentKey,
              requireResidentKey: json.authenticatorSelection.requireResidentKey,
              userVerification: json.authenticatorSelection.userVerification as fido2.UserVerificationRequirement,
            } : undefined,
            attestation: json.attestation as fido2.AttestationConveyancePreference,
          };
          const response = await fido2.register(context, { publicKey: options });
          const id = encodeBase64Url(response.rawId);
           const output: ResultJson<AttestationResponseJson> = {
            id, rawId: id, type: response.type,
            response: {
              clientDataJSON: encodeBase64Url(response.response.clientDataJson),
              attestationObject: encodeBase64Url(response.response.attestationObject),
              transports: response.response.transports,
            },
            clientExtensionResults: {},
           };
           return JSON.stringify(output);
        });
        return;
      case 'authenticate':
        this.run(result, 'authenticate', async (context) => {
          const json = JSON.parse(call.argument('options') as string) as AuthenticateJson;
          if (json.extensions && Object.keys(json.extensions).length > 0) {
            throw new Error('OHOS FIDO2 does not expose the requested WebAuthn extension');
          }
          const options: fido2.PublicKeyCredentialRequestOptions = {
            challenge: decodeBase64Url(json.challenge),
            rpId: json.rpId,
            timeout: json.timeout,
            userVerification: json.userVerification as fido2.UserVerificationRequirement,
            allowCredentials: json.allowCredentials?.map(credential),
          };
          if (call.argument('preferImmediatelyAvailableCredentials') as boolean ||
              !(call.argument('canBeSecurityKey') as boolean)) {
            options.hints = [fido2.PublicKeyCredentialHint.CLIENT_DEVICE];
          }
          const mediation = call.argument('mediation') as fido2.CredentialMediationRequirement;
          const response = await fido2.authenticate(context, { publicKey: options, mediation });
          const id = encodeBase64Url(response.rawId);
           const output: ResultJson<AssertionResponseJson> = {
            id, rawId: id, type: response.type,
            response: {
              clientDataJSON: encodeBase64Url(response.response.clientDataJson),
              authenticatorData: encodeBase64Url(response.response.authenticatorData),
              signature: encodeBase64Url(response.response.signature),
              userHandle: response.response.userHandle ? encodeBase64Url(response.response.userHandle) : '',
            },
            clientExtensionResults: {},
           };
           return JSON.stringify(output);
        });
        return;
      case 'cancelCurrentAuthenticatorOperation':
        this.cancelPending();
        result.success(null);
        return;
      default:
        result.notImplemented();
    }
  }

  private async getAvailability(): Promise<AvailabilityJson> {
    const unavailable: AvailabilityJson = {
      hasPasskeySupport: false,
      isUserVerifyingPlatformAuthenticatorAvailable: false,
      isConditionalMediationAvailable: false,
    };
    if (!this.context) return unavailable;
    try {
      // HarmonyOS 6.1 returns a plain object even though the SDK declares Map.
      const capabilities = await fido2.getClientCapabilities(this.context) as
        Map<fido2.ClientCapability, boolean> | Record<string, boolean>;
      const hasCapability = (key: fido2.ClientCapability): boolean =>
        capabilities instanceof Map ? capabilities.get(key) === true : capabilities[key] === true;
      return {
        hasPasskeySupport: hasCapability(fido2.ClientCapability.PASSKEY_PLATFORM_AUTHENTICATOR),
        isUserVerifyingPlatformAuthenticatorAvailable:
          hasCapability(fido2.ClientCapability.USER_VERIFYING_PLATFORM_AUTHENTICATOR),
        isConditionalMediationAvailable: hasCapability(fido2.ClientCapability.CONDITIONAL_GET),
      };
    } catch (_) {
      return unavailable;
    }
  }

  private run(result: MethodResult, operation: string,
              task: (context: common.UIAbilityContext) => Promise<string>): void {
    if (!this.context) {
      result.error('deviceNotSupported', 'HarmonyOS FIDO2 requires an attached UIAbility.', null);
      return;
    }
    if (this.nativeBusy) {
      result.error('ohos-unhandled-busy', 'A native passkey operation is still active.', null);
      return;
    }
    this.nativeBusy = true;
    this.pending = result;
    task(this.context).then((response) => {
      if (this.pending === result) result.success(response);
    }).catch((error: BusinessError) => {
      if (this.pending === result) {
        const code = error.message?.includes('WebAuthn extension')
          ? 'ohos-unsupported-extension' : nativeError(error, operation);
        result.error(code, error.message ?? 'HarmonyOS FIDO2 failed.', error.code ?? null);
      }
    }).finally(() => {
      if (this.pending === result) this.pending = null;
      this.nativeBusy = false;
    });
  }

  private cancelPending(): void {
    const pending = this.pending;
    this.pending = null;
    pending?.error('cancelled', 'Passkey operation cancelled by Flutter.', null);
    // FIDO2 has no public API to dismiss an already displayed system sheet.
  }
}
