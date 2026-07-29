import { api, type PasskeyCeremony } from "./api";

function decodeBase64Url(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(padded), (character) =>
    character.charCodeAt(0),
  );
  return bytes.buffer;
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function creationOptions(
  ceremony: PasskeyCeremony,
): PublicKeyCredentialCreationOptions {
  const source = ceremony.public_key.publicKey as unknown as {
    challenge: string;
    user: { id: string };
    excludeCredentials?: Array<{ id: string }>;
  } & Record<string, unknown>;
  return {
    ...source,
    challenge: decodeBase64Url(source.challenge),
    user: { ...source.user, id: decodeBase64Url(source.user.id) },
    excludeCredentials: source.excludeCredentials?.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  } as PublicKeyCredentialCreationOptions;
}

function requestOptions(
  ceremony: PasskeyCeremony,
): PublicKeyCredentialRequestOptions {
  const source = ceremony.public_key.publicKey as unknown as {
    challenge: string;
    allowCredentials?: Array<{ id: string }>;
  } & Record<string, unknown>;
  return {
    ...source,
    challenge: decodeBase64Url(source.challenge),
    allowCredentials: source.allowCredentials?.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  } as PublicKeyCredentialRequestOptions;
}

function registrationCredential(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encodeBase64Url(response.attestationObject),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      transports: response.getTransports?.() ?? [],
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function authenticationCredential(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle
        ? encodeBase64Url(response.userHandle)
        : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

export async function registerPasskey(
  principalId: string,
  name: string,
): Promise<void> {
  if (!window.PublicKeyCredential)
    throw new Error("Passkeys are not available in this browser.");
  const ceremony = await api.beginPasskeyRegistration(principalId, name);
  const credential = await navigator.credentials.create({
    publicKey: creationOptions(ceremony),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("Passkey registration was cancelled.");
  }
  await api.finishPasskeyRegistration(
    ceremony.ceremony_id,
    registrationCredential(credential),
  );
}

export async function signInWithPasskey(
  principalName: string,
): Promise<string> {
  if (!window.PublicKeyCredential)
    throw new Error("Passkeys are not available in this browser.");
  const ceremony = await api.beginPasskeyLogin(principalName);
  const credential = await navigator.credentials.get({
    publicKey: requestOptions(ceremony),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("Passkey sign-in was cancelled.");
  }
  const session = await api.finishPasskeyLogin(
    ceremony.ceremony_id,
    authenticationCredential(credential),
  );
  sessionStorage.setItem("constellation_api_key", session.access_token);
  return session.principal.name;
}
