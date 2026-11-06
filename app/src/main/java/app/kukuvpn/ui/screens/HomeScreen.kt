package app.kukuvpn.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.bg.TunnelStage
import app.kukuvpn.bg.TunnelState
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.core.warp.WarpSetup
import app.kukuvpn.data.AppSettings
import app.kukuvpn.ui.components.StatTile
import app.kukuvpn.ui.components.StageBar
import app.kukuvpn.ui.components.TrafficChart
import app.kukuvpn.ui.components.formatBytes
import app.kukuvpn.ui.components.formatUptime
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.compose.runtime.rememberCoroutineScope

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val app = context.applicationContext as KukuApp

    val state by ServiceBridge.state.collectAsState()
    val stages by ServiceBridge.stages.collectAsState()
    val stats by ServiceBridge.stats.collectAsState()
    val exitIp by ServiceBridge.exitIp.collectAsState()
    val activeProfile by ServiceBridge.activeProfile.collectAsState()
    val scope = rememberCoroutineScope()
    val lastError by ServiceBridge.lastError.collectAsState()

    val settings by app.settingsStore.settings.collectAsState(initial = AppSettings())
    val profiles by app.profileStore.profiles.collectAsState(initial = emptyList())
    val selectedId by app.profileStore.selectedId.collectAsState(initial = null)
    val warpStatus by WarpRegistrar.status.collectAsState()

    // 1 Hz samples for the sparkline, kept on their own stream so the chart
    // never rebuilds the whole screen (the v1.0.7 lesson, RIX-side).
    val downSamples = remember { mutableStateListOf<Long>() }
    val upSamples = remember { mutableStateListOf<Long>() }
    var lastIn by remember { mutableStateOf(0L) }
    var lastOut by remember { mutableStateOf(0L) }
    LaunchedEffect(state) {
        while (state == TunnelState.ACTIVE) {
            delay(1000)
            val din = (stats.bytesIn - lastIn).coerceAtLeast(0)
            val dout = (stats.bytesOut - lastOut).coerceAtLeast(0)
            lastIn = stats.bytesIn; lastOut = stats.bytesOut
            downSamples.add(din); upSamples.add(dout)
            if (downSamples.size > 60) downSamples.removeAt(0)
            if (upSamples.size > 60) upSamples.removeAt(0)
        }
    }

    // VPN permission flow: prepare() → launch system dialog → connect on OK
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) ServiceBridge.connect(context)
    }

    val selectedName = profiles.firstOrNull { it.id == selectedId || it.id == activeProfile?.id }?.name
        ?: activeProfile?.name

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            when (state) {
                TunnelState.OFF -> stringResource(R.string.state_off)
                TunnelState.PREPARING -> stringResource(R.string.state_preparing)
                TunnelState.CONNECTING -> stringResource(R.string.state_connecting)
                TunnelState.VERIFYING -> stringResource(R.string.state_verifying)
                TunnelState.ACTIVE -> stringResource(R.string.state_active)
                TunnelState.ERROR -> stringResource(R.string.state_error)
            },
            style = MaterialTheme.typography.headlineMedium,
            color = if (state == TunnelState.ACTIVE) MaterialTheme.colorScheme.primary
            else if (state == TunnelState.ERROR) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.onSurface,
        )

        StageBar(lit = stages)

        // ---- connect / cancel / disconnect ----
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(170.dp)) {
            val busy = state == TunnelState.CONNECTING || state == TunnelState.VERIFYING || state == TunnelState.PREPARING
            if (busy) {
                CircularProgressIndicator(Modifier.size(120.dp))
            }
            Button(
                onClick = {
                    when {
                        state == TunnelState.OFF || state == TunnelState.ERROR -> {
                            if (settings.vpnMode) {
                                val intent = ServiceBridge.prepare(context)
                                if (intent != null) vpnPermission.launch(intent) else ServiceBridge.connect(context)
                            } else ServiceBridge.connect(context)
                        }
                        busy -> ServiceBridge.disconnect(context) // second tap cancels the attempt
                        state == TunnelState.ACTIVE -> ServiceBridge.disconnect(context)
                    }
                },
                enabled = state != TunnelState.OFF || profiles.isNotEmpty(),
                modifier = Modifier.size(150.dp).height(150.dp),
                shape = MaterialTheme.shapes.extraLarge,
            ) {
                Text(
                    when {
                        state == TunnelState.OFF || state == TunnelState.ERROR -> stringResource(R.string.btn_connect)
                        busy -> stringResource(R.string.btn_cancel)
                        else -> stringResource(R.string.btn_disconnect)
                    },
                    textAlign = TextAlign.Center,
                )
            }
        }

        selectedName?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(stringResource(R.string.verify_note), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        lastError?.let {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.error.copy(alpha = 0.12f))) {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall)
            }
        }

        // ---- stats ----
        androidx.compose.foundation.layout.Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile(stringResource(R.string.stats_download), "▾ " + formatBytes(stats.bytesIn), Modifier.weight(1f))
            StatTile(stringResource(R.string.stats_upload), "▴ " + formatBytes(stats.bytesOut), Modifier.weight(1f))
        }
        androidx.compose.foundation.layout.Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatTile(stringResource(R.string.stats_uptime), formatUptime(stats.uptimeSec), Modifier.weight(1f))
            StatTile(stringResource(R.string.stats_exit), exitIp.ifBlank { "—" }, Modifier.weight(1f))
        }

        TrafficChart(downSamples.toList(), upSamples.toList(), Modifier.fillMaxWidth())

        // ---- mode switch ----
        androidx.compose.foundation.layout.Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { scope.launch { app.settingsStore.setVpnMode(true) } },
                enabled = !settings.vpnMode && state == TunnelState.OFF,
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.mode_vpn)) }
            OutlinedButton(
                onClick = { scope.launch { app.settingsStore.setVpnMode(false) } },
                enabled = settings.vpnMode && state == TunnelState.OFF,
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.mode_proxy)) }
        }

        if (profiles.isEmpty()) {
            Card {
                Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    if (warpStatus == WarpSetup.REGISTERING) {
                        Text(stringResource(R.string.warp_setting_up), style = MaterialTheme.typography.titleMedium)
                    } else {
                        Text(stringResource(R.string.no_profile_title), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.no_profile_body), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}
