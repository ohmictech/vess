/// Biometric authentication gate for sensitive operations.
/// Unlocks for a short window (UNLOCK_WINDOW_MS) after successful biometric check.

const UNLOCK_WINDOW_MS = 60_000; // 60 seconds
let lastUnlock = 0;

export function isUnlocked(): boolean {
  return Date.now() - lastUnlock < UNLOCK_WINDOW_MS;
}

/** Trigger biometric (fingerprint/face) or fallback to confirm dialog.
 *  Returns true if authenticated, false if cancelled. */
export async function biometricGate(): Promise<boolean> {
  if (isUnlocked()) return true;

  try {
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.();
    if (available) {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: window.location.hostname || "localhost",
          userVerification: "required",
          timeout: 60000,
        },
      } as any);
    }
  } catch {
    // biometric failed or user cancelled — fall through to confirm
  }

  // Fallback: browser confirm dialog
  const ok = confirm("Authenticate to perform this sensitive operation?");
  if (!ok) return false;

  lastUnlock = Date.now();
  return true;
}

/** Force re-lock (e.g. after sensitive data is no longer needed). */
export function lock(): void {
  lastUnlock = 0;
}
