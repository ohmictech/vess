package org.vess.core

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel

class MainActivity : ComponentActivity() {

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            val vm = _vm
            vm?.setNotificationPermission(granted)
        }

    private var _vm: VessViewModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val vm: VessViewModel = viewModel()
            _vm = vm

            // Initialize biometric manager once activity is available
            if (vm.biometricManager == null) {
                vm.biometricManager = BiometricAuthManager(this)
                vm.checkBiometricEnrolled()
            }

            Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                VessApp(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    vm = vm
                )
            }
        }

        // Request notification permission (Android 13+)
        requestNotificationPermission()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when {
                ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED -> {
                    _vm?.setNotificationPermission(true)
                }
                shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) -> {
                    // User previously denied — we'll show rationale in UI
                    _vm?.setNotificationPermission(false)
                }
                else -> {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
        } else {
            // Pre-Android 13: notifications implicitly granted
            _vm?.setNotificationPermission(true)
        }
    }
}
