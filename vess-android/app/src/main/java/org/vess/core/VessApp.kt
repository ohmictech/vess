package org.vess.core

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ── Brand colors ──────────────────────────────────────────────────

private val VessDark = Color(0xFF1A1A2E)
private val VessAccent = Color(0xFF00D4AA)
private val VessCard = Color(0xFF16213E)
private val VessSurface = Color(0xFF0F3460)

// ── Root router ───────────────────────────────────────────────────

@Composable
fun VessApp(modifier: Modifier = Modifier, vm: VessViewModel) {
    val state by vm.state.collectAsState()

    when (state.screen) {
        Screen.Welcome -> WelcomeScreen(vm = vm)
        Screen.CreateWallet -> CreateWalletScreen(vm = vm, state = state)
        Screen.RecoverWallet -> RecoverWalletScreen(vm = vm, state = state)
        Screen.WalletCreated -> WalletCreatedScreen(vm = vm, state = state)
        Screen.Dashboard -> DashboardScreen(vm = vm, state = state)
    }
}

// ── Welcome ───────────────────────────────────────────────────────

@Composable
fun WelcomeScreen(vm: VessViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VessDark)
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Vess", fontSize = 48.sp, fontWeight = FontWeight.Bold, color = VessAccent)
        Text("Stateless Digital Cash", fontSize = 16.sp, color = Color.White.copy(alpha = 0.6f))
        Spacer(Modifier.height(64.dp))

        Button(
            onClick = { vm.setScreen(Screen.CreateWallet) },
            modifier = Modifier.fillMaxWidth().height(56.dp),
            colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
        ) {
            Text("Create Wallet", color = VessDark, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        }

        Spacer(Modifier.height(16.dp))

        OutlinedButton(
            onClick = { vm.setScreen(Screen.RecoverWallet) },
            modifier = Modifier.fillMaxWidth().height(56.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = VessAccent)
        ) {
            Text("Recover Wallet", fontSize = 18.sp)
        }
    }
}

// ── Create Wallet ─────────────────────────────────────────────────

@Composable
fun CreateWalletScreen(vm: VessViewModel, state: VessUiState) {
    FormScaffold(title = "Create Wallet", vm = vm, state = state, onBack = { vm.setScreen(Screen.Welcome) }) {
        if (!state.biometricAvailable) {
            BiometricUnavailableBanner()
        }

        OutlinedTextField(
            value = state.tag,
            onValueChange = vm::updateTag,
            label = { Text("VessTag (e.g. alice)") },
            prefix = { Text("+", color = VessAccent) },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            colors = fieldColors()
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = state.walletName,
            onValueChange = vm::updateWalletName,
            label = { Text("Wallet name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            colors = fieldColors()
        )

        Spacer(Modifier.height(12.dp))

        // Biometric info card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = VessCard)
        ) {
            Row(
                Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("🔐", fontSize = 24.sp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        "Secured by biometrics",
                        color = VessAccent,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        "Your wallet key will be encrypted with your fingerprint or screen lock.",
                        color = Color.White.copy(alpha = 0.6f),
                        fontSize = 12.sp
                    )
                }
            }
        }

        Spacer(Modifier.height(24.dp))

        if (state.error != null) {
            Text(state.error, color = Color(0xFFFF6B6B), fontSize = 14.sp)
            Spacer(Modifier.height(8.dp))
        }

        Button(
            onClick = vm::createWalletWithBiometric,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            enabled = !state.loading && state.biometricAvailable,
            colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
        ) {
            if (state.loading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp), color = VessDark)
            } else {
                Text("Authenticate \u0026 Create", color = VessDark, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
        }

        if (state.loadingMessage.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(state.loadingMessage, color = Color.White.copy(alpha = 0.5f), fontSize = 13.sp)
        }
    }
}

// ── Recover Wallet ────────────────────────────────────────────────

@Composable
fun RecoverWalletScreen(vm: VessViewModel, state: VessUiState) {
    FormScaffold(title = "Recover Wallet", vm = vm, state = state, onBack = { vm.setScreen(Screen.Welcome) }) {
        if (!state.biometricAvailable) {
            BiometricUnavailableBanner()
        }

        OutlinedTextField(
            value = state.recoveryPhraseInput,
            onValueChange = vm::updateRecoveryPhrase,
            label = { Text("12-word recovery phrase") },
            modifier = Modifier.fillMaxWidth().height(120.dp),
            colors = fieldColors()
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = state.walletName,
            onValueChange = vm::updateWalletName,
            label = { Text("Wallet name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            colors = fieldColors()
        )

        Spacer(Modifier.height(12.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = VessCard)
        ) {
            Row(
                Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("🔐", fontSize = 24.sp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        "Secured by biometrics",
                        color = VessAccent,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        "Your wallet key will be encrypted with your fingerprint or screen lock.",
                        color = Color.White.copy(alpha = 0.6f),
                        fontSize = 12.sp
                    )
                }
            }
        }

        Spacer(Modifier.height(24.dp))

        if (state.error != null) {
            Text(state.error, color = Color(0xFFFF6B6B), fontSize = 14.sp)
            Spacer(Modifier.height(8.dp))
        }

        Button(
            onClick = vm::recoverWalletWithBiometric,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            enabled = !state.loading && state.biometricAvailable,
            colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
        ) {
            if (state.loading) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp), color = VessDark)
            } else {
                Text("Authenticate \u0026 Recover", color = VessDark, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
        }

        if (state.loadingMessage.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(state.loadingMessage, color = Color.White.copy(alpha = 0.5f), fontSize = 13.sp)
        }
    }
}

// ── Wallet Created ────────────────────────────────────────────────

@Composable
fun WalletCreatedScreen(vm: VessViewModel, state: VessUiState) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VessDark)
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        Text("Wallet Created!", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = VessAccent)
        Spacer(Modifier.height(8.dp))
        Text("Tag: ${state.walletInfo?.tag ?: ""}", color = Color.White, fontSize = 16.sp)

        Spacer(Modifier.height(24.dp))

        // Recovery phrase — critical to back up
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFFF6B6B).copy(alpha = 0.15f))
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("RECOVERY PHRASE", color = Color(0xFFFF6B6B), fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                Text(
                    state.recoveryPhrase,
                    color = Color.White,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 16.sp,
                    lineHeight = 24.sp
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Write this down and store it safely. Anyone with these words can access your funds.",
                    color = Color.White.copy(alpha = 0.6f),
                    fontSize = 12.sp
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        // Stealth address
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = VessCard)
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("STEALTH ADDRESS", color = VessAccent, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                Text(
                    state.walletInfo?.stealthAddress ?: "",
                    color = Color.White.copy(alpha = 0.7f),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp
                )
            }
        }

        Spacer(Modifier.height(32.dp))

        Button(
            onClick = {
                vm.setScreen(Screen.Dashboard)
                vm.startNodeWithBiometric()
            },
            modifier = Modifier.fillMaxWidth().height(56.dp),
            colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
        ) {
            Text("Start Node & Open Wallet", color = VessDark, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        }
    }
}

// ── Biometric unavailable banner ──────────────────────────────────

@Composable
fun BiometricUnavailableBanner() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFA726).copy(alpha = 0.15f))
    ) {
        Text(
            "⚠️ Biometric authentication is not available on this device. " +
            "Please set up a screen lock (fingerprint, face, or PIN) in your device Settings.",
            modifier = Modifier.padding(12.dp),
            color = Color(0xFFFFA726),
            fontSize = 12.sp
        )
    }
    Spacer(Modifier.height(16.dp))
}

// ── Notification permission banner ────────────────────────────────

@Composable
fun NotificationPermissionBanner(onRequest: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFF6B6B).copy(alpha = 0.15f))
    ) {
        Row(
            Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "🔔 Background notifications are required for the Vess node to keep running.",
                modifier = Modifier.weight(1f),
                color = Color(0xFFFF6B6B),
                fontSize = 12.sp
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = onRequest,
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF6B6B))
            ) {
                Text("Enable", fontSize = 12.sp)
            }
        }
    }
}

// ── Dashboard ─────────────────────────────────────────────────────

@Composable
fun DashboardScreen(vm: VessViewModel, state: VessUiState) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VessDark)
    ) {
        // Top bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(VessSurface)
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("Vess", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = VessAccent)
                Text(
                    if (state.nodeRunning) "● Online (${state.peerCount} peers)" else "○ Offline",
                    fontSize = 12.sp,
                    color = if (state.nodeRunning) VessAccent else Color.White.copy(alpha = 0.4f)
                )
            }
            if (state.nodeRunning) {
                OutlinedButton(
                    onClick = vm::stopNode,
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF6B6B))
                ) {
                    Text("Stop")
                }
            } else {
                Button(
                    onClick = vm::startNodeWithBiometric,
                    colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
                ) {
                    Text("Start", color = VessDark)
                }
            }
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Notification permission banner
            if (!state.hasNotificationPermission && state.nodeRunning) {
                item {
                    NotificationPermissionBanner(onRequest = {
                        // The activity handles this — we just need to trigger it
                        // For now, show a message
                    })
                }
            }

            // Balance card
            item {
                BalanceCard(state = state)
            }

            // Quick send
            item {
                SendCard(vm = vm, state = state)
            }

            // Error
            if (state.error != null) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFFF6B6B).copy(alpha = 0.2f)),
                        onClick = vm::dismissError
                    ) {
                        Text(
                            state.error,
                            modifier = Modifier.padding(12.dp),
                            color = Color(0xFFFF6B6B),
                            fontSize = 14.sp
                        )
                    }
                }
            }

            // Last payment
            state.lastPaymentResult?.let { result ->
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = VessCard)) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Payment Sent", color = VessAccent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("${result.amount} Vess → ${result.recipient}", color = Color.White, fontSize = 14.sp)
                            Text("ID: ${result.paymentId.take(16)}…", color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                }
            }

            // Notifications
            if (state.notifications.isNotEmpty()) {
                item {
                    Text("Notifications", color = Color.White.copy(alpha = 0.6f), fontSize = 14.sp, fontWeight = FontWeight.Bold)
                }
                items(state.notifications) { note ->
                    Card(colors = CardDefaults.cardColors(containerColor = VessCard)) {
                        Column(Modifier.padding(12.dp)) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(note.kind.uppercase(), color = VessAccent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                Text("${note.createdAt}", color = Color.White.copy(alpha = 0.3f), fontSize = 10.sp)
                            }
                            Text(note.message, color = Color.White, fontSize = 13.sp)
                            note.amount?.let {
                                Text("$it Vess", color = Color.White.copy(alpha = 0.7f), fontSize = 14.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Bottom spacer
            item { Spacer(Modifier.height(32.dp)) }
        }
    }
}

// ── Balance Card ──────────────────────────────────────────────────

@Composable
fun BalanceCard(state: VessUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = VessCard)
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("BALANCE", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
            Spacer(Modifier.height(4.dp))
            Text(
                "${state.balance?.total ?: 0}",
                fontSize = 48.sp,
                fontWeight = FontWeight.Bold,
                color = VessAccent,
                fontFamily = FontFamily.Monospace
            )
            Text("Vess", color = Color.White.copy(alpha = 0.5f), fontSize = 14.sp)

            if (state.balance != null && state.balance!!.total > 0uL) {
                Spacer(Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("${state.balance!!.spendable}", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text("Spendable", color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("${state.balance!!.watchOnly}", color = Color.White.copy(alpha = 0.6f), fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text("Watch-only", color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("${state.balance!!.billCount}", color = Color.White.copy(alpha = 0.6f), fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text("Bills", color = Color.White.copy(alpha = 0.5f), fontSize = 11.sp)
                    }
                }
            }
        }
    }
}

// ── Send Card ─────────────────────────────────────────────────────

@Composable
fun SendCard(vm: VessViewModel, state: VessUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = VessCard)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text("SEND", color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = state.sendRecipient,
                onValueChange = vm::updateSendRecipient,
                label = { Text("Recipient (+tag or address)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                colors = fieldColors()
            )
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = state.sendAmount,
                    onValueChange = vm::updateSendAmount,
                    label = { Text("Amount") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    colors = fieldColors()
                )
                OutlinedTextField(
                    value = state.sendMemo,
                    onValueChange = vm::updateSendMemo,
                    label = { Text("Memo") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    colors = fieldColors()
                )
            }
            Spacer(Modifier.height(12.dp))

            Button(
                onClick = vm::sendPayment,
                modifier = Modifier.fillMaxWidth().height(48.dp),
                enabled = !state.loading && state.nodeRunning,
                colors = ButtonDefaults.buttonColors(containerColor = VessAccent)
            ) {
                if (state.loading) CircularProgressIndicator(modifier = Modifier.size(20.dp), color = VessDark)
                else Text("Send", color = VessDark, fontWeight = FontWeight.Bold)
            }
        }
    }
}

// ── Shared composables ────────────────────────────────────────────

@Composable
fun FormScaffold(
    title: String,
    vm: VessViewModel,
    state: VessUiState,
    onBack: () -> Unit,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VessDark)
    ) {
        // Top bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(VessSurface)
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onBack) {
                Text("← Back", color = VessAccent)
            }
            Spacer(Modifier.width(8.dp))
            Text(title, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp)
        ) {
            content()
        }
    }
}

@Composable
fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color.White,
    unfocusedTextColor = Color.White.copy(alpha = 0.8f),
    focusedBorderColor = VessAccent,
    unfocusedBorderColor = Color.White.copy(alpha = 0.2f),
    focusedLabelColor = VessAccent,
    unfocusedLabelColor = Color.White.copy(alpha = 0.4f),
    cursorColor = VessAccent
)
