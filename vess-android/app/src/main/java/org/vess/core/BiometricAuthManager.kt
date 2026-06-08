package org.vess.core

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages biometric + device-credential authentication for wallet encryption.
 *
 * Flow:
 *   1. On first wallet creation, we generate a random 32-byte wallet password.
 *   2. We create an Android Keystore AES key protected by biometric + device credential.
 *   3. The wallet password is encrypted with the Keystore key and stored in preferences.
 *   4. On subsequent uses, biometric prompt decrypts the wallet password.
 *
 * The wallet password is NEVER stored in plaintext and NEVER persisted to disk
 * without being encrypted by the biometric-protected Keystore key.
 */
class BiometricAuthManager(private val activity: FragmentActivity) {

    companion object {
        private const val KEYSTORE_ALIAS = "vess_wallet_key"
        private const val PREFS_NAME = "vess_secure_prefs"
        private const val PREF_ENCRYPTED_PASSWORD = "encrypted_wallet_password"
        private const val PREF_IV = "encryption_iv"
        private const val PREF_BIOMETRIC_ENROLLED = "biometric_enrolled"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** Check if biometric auth (or device credential fallback) is available. */
        fun isAvailable(context: Context): Boolean {
            val bm = BiometricManager.from(context)
            return when (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
                BiometricManager.BIOMETRIC_SUCCESS -> true
                else -> false
            }
        }
    }

    private val prefs: SharedPreferences =
        activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Whether we've previously enrolled (stored an encrypted password). */
    val isEnrolled: Boolean
        get() = prefs.getBoolean(PREF_BIOMETRIC_ENROLLED, false) && getEncryptedPassword() != null

    /**
     * Generate a new random wallet password, encrypt it under the biometric-protected
     * Keystore key, and persist the ciphertext. Call this once after wallet creation.
     *
     * @param onSuccess Called with the plaintext wallet password (use it, then discard).
     */
    fun enroll(onSuccess: (String) -> Unit, onError: (String) -> Unit) {
        val cipher = getEnrollmentCipher() ?: run {
            onError("Could not initialize biometric keystore")
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Secure Your Wallet")
            .setDescription("Use your fingerprint or screen lock to encrypt your wallet key.")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val crypto = result.cryptoObject ?: run {
                        onError("Biometric crypto object missing")
                        return
                    }
                    // Generate a strong random wallet password
                    val walletPassword = generateRandomPassword()
                    // Encrypt it with the biometric-protected cipher
                    val encrypted = crypto.cipher!!.doFinal(walletPassword.toByteArray(Charsets.UTF_8))
                    val iv = crypto.cipher!!.iv
                    // Persist
                    prefs.edit()
                        .putString(PREF_ENCRYPTED_PASSWORD, android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
                        .putString(PREF_IV, android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
                        .putBoolean(PREF_BIOMETRIC_ENROLLED, true)
                        .apply()
                    onSuccess(walletPassword)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError("Authentication failed: $errString")
                }

                override fun onAuthenticationFailed() {
                    // Ignore — user can retry
                }
            })

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * Authenticate with biometric and decrypt the stored wallet password.
     *
     * @param onSuccess Called with the plaintext wallet password (use it, then discard).
     */
    fun authenticate(onSuccess: (String) -> Unit, onError: (String) -> Unit) {
        val encrypted = getEncryptedPassword() ?: run {
            onError("No encrypted password found — create a wallet first")
            return
        }

        val cipher = getDecryptionCipher(encrypted.iv) ?: run {
            onError("Could not initialize biometric keystore for decryption")
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock Your Wallet")
            .setDescription("Authenticate to access your Vess wallet.")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val crypto = result.cryptoObject ?: run {
                        onError("Biometric crypto object missing")
                        return
                    }
                    val decrypted = crypto.cipher!!.doFinal(encrypted.data)
                    val password = String(decrypted, Charsets.UTF_8)
                    onSuccess(password)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError("Authentication failed: $errString")
                }

                override fun onAuthenticationFailed() {
                    // Ignore — user can retry
                }
            })

        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    // ── Private helpers ──────────────────────────────────────────────

    private data class EncryptedBlob(val data: ByteArray, val iv: ByteArray)

    private fun getEncryptedPassword(): EncryptedBlob? {
        val dataB64 = prefs.getString(PREF_ENCRYPTED_PASSWORD, null) ?: return null
        val ivB64 = prefs.getString(PREF_IV, null) ?: return null
        return EncryptedBlob(
            android.util.Base64.decode(dataB64, android.util.Base64.NO_WRAP),
            android.util.Base64.decode(ivB64, android.util.Base64.NO_WRAP)
        )
    }

    private fun getEnrollmentCipher(): Cipher? {
        return try {
            // Generate a new AES-256 key in Android Keystore, protected by biometric
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
            )
            keyGenerator.init(
                KeyGenParameterSpec.Builder(KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    .build()
            )
            val secretKey = keyGenerator.generateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            cipher
        } catch (e: Exception) {
            android.util.Log.e("VessBio", "Enrollment cipher init failed", e)
            // If key already exists (re-enrollment), delete and retry
            try { deleteKeystoreEntry() } catch (_: Exception) {}
            null
        }
    }

    private fun getDecryptionCipher(iv: ByteArray): Cipher? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val secretKey = keyStore.getKey(KEYSTORE_ALIAS, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            cipher
        } catch (e: Exception) {
            android.util.Log.e("VessBio", "Decryption cipher init failed", e)
            null
        }
    }

    private fun deleteKeystoreEntry() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        keyStore.deleteEntry(KEYSTORE_ALIAS)
        prefs.edit().clear().apply()
    }

    private fun generateRandomPassword(): String {
        val bytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }
}
