package org.vess.core

import android.app.Application
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class VessUiState(
    val screen: Screen = Screen.Welcome,
    // Wallet creation
    val tag: String = "",
    val walletName: String = "default",
    val recoveryPhraseInput: String = "",
    // Biometric
    val biometricAvailable: Boolean = false,
    val biometricEnrolled: Boolean = false,
    // Internal wallet password (derived from biometric, never shown in UI)
    // walletPassword is set only transiently during auth flow
    // Wallet info (after creation/recovery)
    val walletInfo: WalletInfo? = null,
    // Node
    val nodeRunning: Boolean = false,
    val nodeStatus: NodeStatus? = null,
    val peerCount: Long = 0,
    // Balance
    val balance: Balance? = null,
    // Send
    val sendRecipient: String = "",
    val sendAmount: String = "",
    val sendMemo: String = "",
    val lastPaymentResult: PaymentResult? = null,
    // Notifications
    val notifications: List<Notification> = emptyList(),
    // Permissions
    val hasNotificationPermission: Boolean = false,
    // Error
    val error: String? = null,
    val loading: Boolean = false,
    val loadingMessage: String = ""
)

enum class Screen {
    Welcome, CreateWallet, RecoverWallet, WalletCreated, Dashboard
}

class VessViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow(VessUiState())
    val state: StateFlow<VessUiState> = _state.asStateFlow()

    private var pollJob: kotlinx.coroutines.Job? = null

    /** Holds the decrypted wallet password transiently — cleared after use. */
    private var walletPassword: String? = null

    /** Set after the Activity is available — lazy-init. */
    var biometricManager: BiometricAuthManager? = null

    init {
        _state.value = _state.value.copy(
            biometricAvailable = BiometricAuthManager.isAvailable(application)
        )
    }

    fun setScreen(screen: Screen) {
        _state.value = _state.value.copy(screen = screen, error = null)
    }

    fun updateTag(v: String) { _state.value = _state.value.copy(tag = v) }
    fun updateWalletName(v: String) { _state.value = _state.value.copy(walletName = v) }
    fun updateRecoveryPhrase(v: String) { _state.value = _state.value.copy(recoveryPhraseInput = v) }
    fun updateSendRecipient(v: String) { _state.value = _state.value.copy(sendRecipient = v) }
    fun updateSendAmount(v: String) { _state.value = _state.value.copy(sendAmount = v) }
    fun updateSendMemo(v: String) { _state.value = _state.value.copy(sendMemo = v) }
    fun setNotificationPermission(granted: Boolean) {
        _state.value = _state.value.copy(hasNotificationPermission = granted)
    }

    // ── Biometric-enrolled check ──────────────────────────────────────

    fun checkBiometricEnrolled() {
        val enrolled = biometricManager?.isEnrolled ?: false
        _state.value = _state.value.copy(biometricEnrolled = enrolled)
    }

    // ── Wallet creation (biometric-gated) ──────────────────────────────

    fun createWalletWithBiometric() {
        val s = _state.value
        if (s.tag.isBlank()) {
            _state.value = s.copy(error = "Enter a VessTag")
            return
        }
        val bm = biometricManager ?: run {
            _state.value = s.copy(error = "Biometric auth unavailable")
            return
        }

        _state.value = s.copy(loading = true, loadingMessage = "Authenticating…", error = null)
        bm.enroll(
            onSuccess = { password ->
                walletPassword = password
                doCreateWallet(s.tag, s.walletName, password)
            },
            onError = { err ->
                _state.value = _state.value.copy(loading = false, error = err)
            }
        )
    }

    private fun doCreateWallet(tag: String, walletName: String, password: String) {
        viewModelScope.launch {
            try {
                val info = VessCore.createWallet(tag, walletName, password)
                walletPassword = null // clear after use
                _state.value = _state.value.copy(
                    loading = false,
                    loadingMessage = "",
                    walletInfo = info,
                    recoveryPhraseInput = "", // don't persist recovery phrase in state
                    screen = Screen.WalletCreated
                )
            } catch (e: VessException) {
                walletPassword = null
                _state.value = _state.value.copy(
                    loading = false, loadingMessage = "",
                    error = e.message ?: "Wallet creation failed"
                )
            }
        }
    }

    // ── Wallet recovery (biometric-gated) ──────────────────────────────

    fun recoverWalletWithBiometric() {
        val s = _state.value
        if (s.recoveryPhraseInput.isBlank()) {
            _state.value = s.copy(error = "Enter your recovery phrase")
            return
        }
        val bm = biometricManager ?: run {
            _state.value = s.copy(error = "Biometric auth unavailable")
            return
        }

        _state.value = s.copy(loading = true, loadingMessage = "Authenticating…", error = null)
        bm.enroll(
            onSuccess = { password ->
                walletPassword = password
                doRecoverWallet(s.recoveryPhraseInput, s.walletName, password)
            },
            onError = { err ->
                _state.value = _state.value.copy(loading = false, error = err)
            }
        )
    }

    private fun doRecoverWallet(phrase: String, walletName: String, password: String) {
        viewModelScope.launch {
            try {
                val info = VessCore.recoverWallet(phrase, walletName, password)
                walletPassword = null
                _state.value = _state.value.copy(
                    loading = false,
                    loadingMessage = "",
                    walletInfo = info,
                    screen = Screen.WalletCreated
                )
            } catch (e: VessException) {
                walletPassword = null
                _state.value = _state.value.copy(
                    loading = false, loadingMessage = "",
                    error = e.message ?: "Recovery failed"
                )
            }
        }
    }

    // ── Node lifecycle ──────────────────────────────────────────────────

    fun startNodeWithBiometric() {
        val s = _state.value
        val info = s.walletInfo ?: run {
            _state.value = s.copy(error = "Create or recover a wallet first")
            return
        }
        if (VessCore.isNodeRunning()) {
            _state.value = s.copy(error = "Node is already running")
            return
        }

        // If we already have a password from enrollment, use it directly
        if (walletPassword != null) {
            doStartNode(info, walletPassword!!)
            return
        }

        // Otherwise, authenticate to get it
        val bm = biometricManager ?: run {
            _state.value = s.copy(error = "Biometric auth unavailable")
            return
        }

        _state.value = s.copy(loading = true, loadingMessage = "Unlocking wallet…", error = null)
        bm.authenticate(
            onSuccess = { password ->
                walletPassword = password
                doStartNode(info, password)
            },
            onError = { err ->
                _state.value = _state.value.copy(loading = false, error = err)
            }
        )
    }

    private fun doStartNode(info: WalletInfo, password: String) {
        viewModelScope.launch {
            try {
                // Use app's internal files directory — writable even in background
                val app = getApplication<Application>()
                val dataDir = app.filesDir.absolutePath

                val config = NodeConfig(
                    testnet = true,
                    kNeighbors = 4u,
                    maxHops = 3u,
                    stateDir = dataDir,
                    walletPath = info.walletPath,
                    walletPassword = password,
                    rpcPort = 9400u,
                    bindAddress = null,
                    bootstrapPeers = emptyList()
                )
                val status = VessCore.startNode(config)
                walletPassword = null // clear after passing to Rust

                // Start foreground service to keep node alive in background
                startNodeService()

                _state.value = _state.value.copy(
                    loading = false,
                    loadingMessage = "",
                    nodeRunning = true,
                    nodeStatus = status,
                    screen = Screen.Dashboard
                )
                startPolling()
            } catch (e: VessException) {
                walletPassword = null
                _state.value = _state.value.copy(
                    loading = false, loadingMessage = "",
                    error = e.message ?: "Failed to start node"
                )
            }
        }
    }

    fun stopNode() {
        viewModelScope.launch {
            try {
                VessCore.stopNode()
                stopNodeService()
                pollJob?.cancel()
                _state.value = _state.value.copy(nodeRunning = false, nodeStatus = null, peerCount = 0)
            } catch (_: VessException) { }
        }
    }

    fun sendPayment() {
        val s = _state.value
        val amount = s.sendAmount.toULongOrNull() ?: run {
            _state.value = s.copy(error = "Invalid amount")
            return
        }
        if (s.sendRecipient.isBlank()) {
            _state.value = s.copy(error = "Recipient is required")
            return
        }
        _state.value = s.copy(loading = true, error = null)
        viewModelScope.launch {
            try {
                val result = VessCore.sendPayment(amount, s.sendRecipient, s.sendMemo.ifBlank { null })
                _state.value = _state.value.copy(
                    loading = false,
                    lastPaymentResult = result,
                    sendAmount = "",
                    sendMemo = ""
                )
                refreshBalance()
            } catch (e: VessException) {
                _state.value = _state.value.copy(loading = false, error = e.message ?: "Payment failed")
            }
        }
    }

    fun refreshBalance() {
        if (!VessCore.isNodeRunning()) return
        viewModelScope.launch {
            try {
                val bal = VessCore.getBalance()
                _state.value = _state.value.copy(balance = bal)
            } catch (_: VessException) { }
            try {
                val status = VessCore.getStatus()
                _state.value = _state.value.copy(nodeStatus = status, peerCount = status.peerCount.toLong())
            } catch (_: VessException) { }
            try {
                val notes = VessCore.getNotifications()
                if (notes.isNotEmpty()) {
                    val current = _state.value.notifications
                    _state.value = _state.value.copy(notifications = (notes + current).take(50))
                }
            } catch (_: VessException) { }
        }
    }

    fun dismissError() { _state.value = _state.value.copy(error = null) }

    private fun startNodeService() {
        val app = getApplication<Application>()
        val intent = Intent(app, VessNodeService::class.java)
        ContextCompat.startForegroundService(app, intent)
    }

    private fun stopNodeService() {
        val app = getApplication<Application>()
        val intent = Intent(app, VessNodeService::class.java)
        app.stopService(intent)
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            delay(3000)
            while (isActive) {
                refreshBalance()
                delay(5000)
            }
        }
    }
}
