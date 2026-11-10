package app.kukuvpn.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.data.AppSettings
import app.kukuvpn.core.fallback.FallbackEngine
import kotlinx.coroutines.launch

/**
 * v1.3.0 — the Connection page (modeled on the Aether screenshots the user
 * shared). The scan mode tunes how hard and how long the engine sweeps
 * before handing over.
 *
 * v1.6.7 — the Aether split the user drew: TWO independent selectors instead
 * of one mixed list, freely combinable like in Aether itself:
 *   پروتکل (Protocol): no protocol / Psiphon / Tor — WHAT carries the traffic;
 *   شبکه (Network):    Direct / Smart / WARP-MASQUE / WARP-WireGuard / Gool —
 *                      HOW it reaches the internet. Direct = the core connects
 *                      straight from the ISP = Aether's own architecture and
 *                      the user's proven fast path.
 * (v1.6.0 left the old per-protocol cards: Psiphon exit country + Tor bridges.)
 */
@Composable
fun ConnectionScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as KukuApp
    val scope = rememberCoroutineScope()
    val settings by app.settingsStore.settings.collectAsState(initial = AppSettings())

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack, contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp)) {
            Text("←")
        }
        Text(stringResource(R.string.conn_title), style = MaterialTheme.typography.headlineSmall)

        /* ------------------- protocol (پروتکل) ------------------------------- */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.conn_proto_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.conn_proto_desc),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val protos = listOf(
                    Triple(FallbackEngine.PROTO_NONE, R.string.proto_none, R.string.proto_none_desc),
                    Triple(FallbackEngine.PROTO_PSIPHON, R.string.proto_psiphon, R.string.proto_psiphon_desc),
                    Triple(FallbackEngine.PROTO_TOR, R.string.proto_tor, R.string.proto_tor_desc),
                )
                protos.forEach { (value, title, desc) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { scope.launch { app.settingsStore.setProtocol(value) } }
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(
                            selected = settings.protocol == value,
                            onClick = { scope.launch { app.settingsStore.setProtocol(value) } },
                        )
                        Column(Modifier.padding(start = 4.dp)) {
                            Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                            Text(
                                stringResource(desc),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        /* ---------------------- network (شبکه) ------------------------------- */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.conn_network_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.conn_network_desc),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Direct only makes sense with a protocol core; a plain VPN has
                // no protocol to "direct" — so the list adapts like Aether's.
                // A stored Direct pin (picked while a protocol was active) shows
                // as Smart until the user taps something; the engine coerces
                // direct→smart for protocol=none the same way.
                val netNow = if (settings.protocol == FallbackEngine.PROTO_NONE &&
                    settings.network == FallbackEngine.NET_DIRECT
                ) FallbackEngine.NET_SMART else settings.network
                val networks = if (settings.protocol == FallbackEngine.PROTO_NONE) {
                    listOf(
                        Triple(FallbackEngine.NET_SMART, R.string.net_smart, R.string.net_smart_desc),
                        Triple(FallbackEngine.NET_MASQUE, R.string.net_masque, R.string.net_masque_desc),
                        Triple(FallbackEngine.NET_WG, R.string.net_wg, R.string.net_wg_desc),
                        Triple(FallbackEngine.NET_GOOL, R.string.net_gool, R.string.net_gool_desc),
                    )
                } else {
                    listOf(
                        Triple(FallbackEngine.NET_DIRECT, R.string.net_direct, R.string.net_direct_desc),
                        Triple(FallbackEngine.NET_SMART, R.string.net_smart, R.string.net_smart_desc),
                        Triple(FallbackEngine.NET_MASQUE, R.string.net_masque, R.string.net_masque_desc),
                        Triple(FallbackEngine.NET_WG, R.string.net_wg, R.string.net_wg_desc),
                    )
                }
                networks.forEach { (value, title, desc) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { scope.launch { app.settingsStore.setNetwork(value) } }
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(
                            selected = netNow == value,
                            onClick = { scope.launch { app.settingsStore.setNetwork(value) } },
                        )
                        Column(Modifier.padding(start = 4.dp)) {
                            Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                            Text(
                                stringResource(desc),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        /* --------------------- psiphon exit country ------------------------- */
        val psiphonPinned = settings.protocol == FallbackEngine.PROTO_PSIPHON
        if (psiphonPinned) {
            Card {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.conn_psiphon_region), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(R.string.conn_psiphon_region_desc),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val regions = listOf(
                        "auto" to stringResource(R.string.region_auto),
                        "US" to stringResource(R.string.region_us),
                        "GB" to stringResource(R.string.region_gb),
                        "DE" to stringResource(R.string.region_de),
                        "NL" to stringResource(R.string.region_nl),
                        "CA" to stringResource(R.string.region_ca),
                        "SG" to stringResource(R.string.region_sg),
                        "JP" to stringResource(R.string.region_jp),
                    )
                    regions.forEach { (code, label) ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { scope.launch { app.settingsStore.setPsiphonRegion(code) } }
                                .padding(vertical = 2.dp),
                        ) {
                            RadioButton(
                                selected = settings.psiphonRegion == code,
                                onClick = { scope.launch { app.settingsStore.setPsiphonRegion(code) } },
                            )
                            Text(label, Modifier.padding(start = 4.dp), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        /* --------------------------- tor bridges ---------------------------- */
        val torPinned = settings.protocol == FallbackEngine.PROTO_TOR
        if (torPinned) {
            Card {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.conn_tor_bridges), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(R.string.conn_tor_bridges_desc),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    val modes = listOf(
                        Triple("auto", R.string.bridge_auto, R.string.bridge_auto_desc),
                        Triple("custom", R.string.bridge_custom, R.string.bridge_custom_desc),
                        Triple("none", R.string.bridge_none, R.string.bridge_none_desc),
                    )
                    modes.forEach { (value, title, desc) ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { scope.launch { app.settingsStore.setTorBridgeMode(value) } }
                                .padding(vertical = 2.dp),
                        ) {
                            RadioButton(
                                selected = settings.torBridgeMode == value,
                                onClick = { scope.launch { app.settingsStore.setTorBridgeMode(value) } },
                            )
                            Column(Modifier.padding(start = 4.dp)) {
                                Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                                Text(
                                    stringResource(desc),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                    if (settings.torBridgeMode == "custom") {
                        var draft by remember(settings.torCustomBridges) {
                            mutableStateOf(settings.torCustomBridges)
                        }
                        OutlinedTextField(
                            value = draft,
                            onValueChange = { draft = it },
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 3,
                            maxLines = 10,
                            placeholder = { Text(stringResource(R.string.tor_bridges_hint), style = MaterialTheme.typography.labelSmall) },
                        )
                        TextButton(onClick = { scope.launch { app.settingsStore.setTorCustomBridges(draft) } }) {
                            Text(stringResource(R.string.tor_bridges_save))
                        }
                    }
                }
            }
        }

        /* ----------------------------- scan mode ----------------------------- */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.conn_scan), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.conn_scan_desc),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val scans = listOf(
                    Triple("turbo", R.string.scan_turbo, R.string.scan_turbo_desc),
                    Triple("balanced", R.string.scan_balanced, R.string.scan_balanced_desc),
                    Triple("thorough", R.string.scan_thorough, R.string.scan_thorough_desc),
                    Triple("stealth", R.string.scan_stealth, R.string.scan_stealth_desc),
                    Triple("ironclad", R.string.scan_ironclad, R.string.scan_ironclad_desc),
                )
                scans.forEach { (value, title, desc) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { scope.launch { app.settingsStore.setScanMode(value) } }
                            .padding(vertical = 4.dp),
                    ) {
                        RadioButton(
                            selected = settings.scanMode == value,
                            onClick = { scope.launch { app.settingsStore.setScanMode(value) } },
                        )
                        Column(Modifier.padding(start = 4.dp)) {
                            Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                            Text(
                                stringResource(desc),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }

        Text(
            stringResource(R.string.conn_applies_next),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
