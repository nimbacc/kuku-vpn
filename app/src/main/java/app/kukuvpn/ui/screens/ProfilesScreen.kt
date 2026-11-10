package app.kukuvpn.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.core.links.SubscriptionFetcher
import app.kukuvpn.core.links.ShareLinkParser
import app.kukuvpn.ui.ImportIntents
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(snackbar: SnackbarHostState) {
    val context = LocalContext.current
    val app = context.applicationContext as KukuApp
    val scope = rememberCoroutineScope()

    val profiles by app.profileStore.profiles.collectAsState(initial = emptyList())
    val selectedId by app.profileStore.selectedId.collectAsState(initial = null)
    val lastGoodId by app.profileStore.lastGoodId.collectAsState(initial = null)
    val subscriptions by app.profileStore.subscriptions.collectAsState(initial = emptySet())

    var sheetOpen by remember { mutableStateOf(false) }
    var input by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState()

    // QR scanner (zxing embedded handles the camera activity)
    val qrPrompt = stringResource(R.string.profiles_scan_qr)
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        scope.launch {
            ImportIntents.import(context, text).fold(
                onSuccess = { snackbar.showSnackbar(context.getString(R.string.profiles_imported, it)) },
                onFailure = { snackbar.showSnackbar(context.getString(R.string.profiles_import_failed, it.message ?: "?")) },
            )
        }
    }

    fun doImport(raw: String) {
        if (raw.isBlank()) return
        busy = true
        scope.launch {
            ImportIntents.import(context, raw).fold(
                onSuccess = {
                    if (raw.trim().startsWith("http", true) && !ShareLinkParser.isSupported(raw)) {
                        app.profileStore.addSubscription(raw.trim())
                    }
                    snackbar.showSnackbar(context.getString(R.string.profiles_imported, it))
                    input = ""
                    sheetOpen = false
                },
                onFailure = { snackbar.showSnackbar(context.getString(R.string.profiles_import_failed, it.message ?: "?")) },
            )
            busy = false
        }
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(onClick = { sheetOpen = true }) {
                Icon(Icons.Filled.Add, stringResource(R.string.profiles_add))
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {

            if (subscriptions.isNotEmpty()) {
                Card {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.profiles_import_subscription), style = MaterialTheme.typography.titleSmall)
                        subscriptions.forEach { sub ->
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(sub, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f), maxLines = 1)
                                IconButton(onClick = {
                                    scope.launch {
                                        busy = true
                                        runCatching { SubscriptionFetcher.fetch(sub, sub) }
                                            .onSuccess { app.profileStore.addAll(it); snackbar.showSnackbar(context.getString(R.string.profiles_imported, it.size)) }
                                            .onFailure { snackbar.showSnackbar(context.getString(R.string.profiles_import_failed, it.message ?: "?")) }
                                        busy = false
                                    }
                                }) { Icon(Icons.Filled.Add, "refresh") }
                                IconButton(onClick = { scope.launch { app.profileStore.removeSubscription(sub) } }) {
                                    Icon(Icons.Filled.Delete, "remove")
                                }
                            }
                        }
                    }
                }
            }

            if (profiles.isEmpty()) {
                Text(stringResource(R.string.profiles_empty), style = MaterialTheme.typography.bodyLarge)
            }

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(profiles, key = { it.id }) { p ->
                    Card {
                        Row(
                            Modifier.fillMaxWidth().padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            RadioButton(
                                selected = p.id == selectedId,
                                onClick = {
                                    scope.launch {
                                        app.profileStore.select(p.id)
                                        // v1.6.7: tapping a bundled Psiphon/Tor
                                        // profile also pins the PROTOCOL — the
                                        // old "tapped Psiphon, connect rode WARP"
                                        // surprise is structurally impossible.
                                        // Network follows the Aether golden path:
                                        // DIRECT (the user's proven fast route).
                                        when (p.fromSubscription) {
                                            "psiphon" -> {
                                                app.settingsStore.setProtocol(app.kukuvpn.core.fallback.FallbackEngine.PROTO_PSIPHON)
                                                app.settingsStore.setNetwork(app.kukuvpn.core.fallback.FallbackEngine.NET_DIRECT)
                                            }
                                            "tor" -> {
                                                app.settingsStore.setProtocol(app.kukuvpn.core.fallback.FallbackEngine.PROTO_TOR)
                                                app.settingsStore.setNetwork(app.kukuvpn.core.fallback.FallbackEngine.NET_DIRECT)
                                            }
                                        }
                                    }
                                },
                            )
                            Column(Modifier.weight(1f)) {
                                Text(p.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                                Text(p.summary(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (p.id == lastGoodId) Icon(Icons.Filled.Verified, stringResource(R.string.profiles_last_good), tint = MaterialTheme.colorScheme.primary)
                            IconButton(onClick = { scope.launch { app.profileStore.delete(p.id) } }) {
                                Icon(Icons.Filled.Delete, stringResource(R.string.profiles_delete))
                            }
                        }
                    }
                }
            }
        }
    }

    if (sheetOpen) {
        ModalBottomSheet(onDismissRequest = { sheetOpen = false }, sheetState = sheetState) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.profiles_add), style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    label = { Text(stringResource(R.string.profiles_url_hint)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { doImport(input) }, enabled = !busy && input.isNotBlank()) {
                        Text(stringResource(R.string.profiles_import))
                    }
                    TextButton(onClick = {
                        val cm = context.getSystemService(android.content.ClipboardManager::class.java)
                        cm.primaryClip?.getItemAt(0)?.text?.let { input = it.toString() }
                    }) { Text(stringResource(R.string.profiles_paste)) }
                    TextButton(onClick = {
                        qrLauncher.launch(
                            ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt(qrPrompt)
                                .setBeepEnabled(false)
                        )
                    }) { Text(stringResource(R.string.profiles_scan_qr)) }
                }
                if (busy) Text("…", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
