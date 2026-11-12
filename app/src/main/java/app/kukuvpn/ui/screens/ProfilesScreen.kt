package app.kukuvpn.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Speed
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
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.bg.TunnelState
import app.kukuvpn.core.fallback.FallbackEngine
import app.kukuvpn.core.links.SubscriptionFetcher
import app.kukuvpn.core.links.ShareLinkParser
import app.kukuvpn.core.speed.SpeedTester
import app.kukuvpn.data.Profile
import app.kukuvpn.ui.ImportIntents
import app.kukuvpn.ui.components.qualityColor
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.delay
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
    // v1.7.4: the test-result sheet gets its OWN state — two sheets must not
    // share one ModalBottomSheetState (stale half-expanded flags on reopen)
    val resultSheetState = rememberModalBottomSheetState()
    // compose must SUBSCRIBE to the tunnel state (a plain .value read in a
    // composable never recomposes — the test buttons would go stale)
    val tunnelState by ServiceBridge.state.collectAsState()

    // v1.7.4 — per-profile speed testing (the Home button moved here: the user's
    // ask — "اسپید تست باید بره به قسمت پروفایل که بشه از پروفایل‌ها تست گرفت")
    var testTarget by remember { mutableStateOf<Profile?>(null) }
    var testRunning by remember { mutableStateOf(false) }
    var testNote by remember { mutableStateOf<String?>(null) }
    var testResult by remember { mutableStateOf<SpeedTester.Result?>(null) }
    // quality verdict per tested profile (this session) — a small chip on the row
    val qualityByProfile = remember { mutableStateMapOf<String, SpeedTester.Quality>() }
    var resultSheetOpen by remember { mutableStateOf(false) }

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

    /**
     * v1.7.4 — test ONE profile, Iter-style: select it, (re)connect if needed,
     * wait for ACTIVE, run the real measurement through the tunnel, collapse
     * the numbers into the weak/medium/good/excellent verdict. Honest about
     * every way this can go: no permission, connect failed, or a fallback
     * candidate winning instead of the picked profile.
     */
    fun startProfileTest(p: Profile) {
        if (testRunning) return
        scope.launch {
            testTarget = p
            testRunning = true
            testResult = null
            testNote = null
            resultSheetOpen = true
            testNote = context.getString(R.string.speedtest_connecting)

            val offStates = setOf(TunnelState.OFF, TunnelState.ERROR)
            // the tested profile must LEAD the chain — same pinning as the row select
            app.profileStore.select(p.id)
            when (p.fromSubscription) {
                "psiphon" -> {
                    app.settingsStore.setProtocol(FallbackEngine.PROTO_PSIPHON)
                    app.settingsStore.setNetwork(FallbackEngine.NET_DIRECT)
                }
                "tor" -> {
                    app.settingsStore.setProtocol(FallbackEngine.PROTO_TOR)
                    app.settingsStore.setNetwork(FallbackEngine.NET_DIRECT)
                }
            }
            // already riding THIS profile? test immediately — no bounce
            val alreadyActive = ServiceBridge.state.value == TunnelState.ACTIVE &&
                ServiceBridge.activeProfile.value?.id == p.id
            if (!alreadyActive) {
                // a live session on ANOTHER profile must bounce first
                if (!offStates.contains(ServiceBridge.state.value)) {
                    val activeId = ServiceBridge.activeProfile.value?.id
                    if (activeId != null && activeId != p.id) {
                        ServiceBridge.disconnect(context)
                    } else if (ServiceBridge.isBusy) {
                        ServiceBridge.disconnect(context) // cancel the in-flight attempt
                    }
                }
                var waited = 0
                while (!offStates.contains(ServiceBridge.state.value) && waited < 15_000) {
                    delay(300); waited += 300
                }
                if (!offStates.contains(ServiceBridge.state.value)) {
                    testNote = context.getString(R.string.speedtest_could_not_switch)
                    testRunning = false
                    return@launch
                }
                // connect — VPN permission cannot be requested from here; say so
                val prepareIntent = ServiceBridge.prepare(context)
                if (prepareIntent != null) {
                    testNote = context.getString(R.string.speedtest_need_vpn_perm)
                    testRunning = false
                    return@launch
                }
                ServiceBridge.connect(context)
                waited = 0
                while (ServiceBridge.state.value != TunnelState.ACTIVE && waited < 120_000) {
                    if (ServiceBridge.state.value == TunnelState.ERROR) break
                    delay(500); waited += 500
                }
            }
            val winner = ServiceBridge.activeProfile.value
            if (ServiceBridge.state.value != TunnelState.ACTIVE) {
                testNote = context.getString(R.string.speedtest_not_connected)
                testRunning = false
                return@launch
            }
            if (winner?.id != p.id) {
                // the chain fell back to a different candidate — testing THAT
                // and calling it this profile's speed would be a lie
                testNote = context.getString(R.string.speedtest_fallback, winner?.name ?: "?")
                testRunning = false
                return@launch
            }
            testNote = context.getString(R.string.speedtest_running)
            val r = SpeedTester.run()
            testResult = r
            testNote = null
            SpeedTester.verdict(r)?.let { qualityByProfile[p.id] = it }
            ServiceBridge.speedVerdict.value = SpeedTester.verdict(r)
            testRunning = false
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
                                                app.settingsStore.setProtocol(FallbackEngine.PROTO_PSIPHON)
                                                app.settingsStore.setNetwork(FallbackEngine.NET_DIRECT)
                                            }
                                            "tor" -> {
                                                app.settingsStore.setProtocol(FallbackEngine.PROTO_TOR)
                                                app.settingsStore.setNetwork(FallbackEngine.NET_DIRECT)
                                            }
                                        }
                                    }
                                },
                            )
                            Column(Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text(p.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                                    qualityByProfile[p.id]?.let { q ->
                                        // v1.7.4: this session's verdict chip
                                        Text(
                                            stringResource(SpeedTester.qualityLabel(q)),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = qualityColor(q),
                                        )
                                    }
                                }
                                Text(p.summary(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (p.id == lastGoodId) Icon(Icons.Filled.Verified, stringResource(R.string.profiles_last_good), tint = MaterialTheme.colorScheme.primary)
                            // v1.7.4: per-profile speed test
                            IconButton(
                                onClick = { startProfileTest(p) },
                                enabled = !testRunning && tunnelState in
                                    setOf(TunnelState.ACTIVE, TunnelState.OFF, TunnelState.ERROR),
                            ) { Icon(Icons.Filled.Speed, stringResource(R.string.speedtest_run)) }
                            IconButton(onClick = { scope.launch { app.profileStore.delete(p.id) } }) {
                                Icon(Icons.Filled.Delete, stringResource(R.string.profiles_delete))
                            }
                        }
                    }
                }
            }
        }
    }

    // v1.7.4 — the test result sheet: the verdict WORD first (the user reads
    // "عالی", not a chart), then the numbers it came from
    if (resultSheetOpen && testTarget != null) {
        val t = testTarget!!
        ModalBottomSheet(onDismissRequest = { resultSheetOpen = false }, sheetState = resultSheetState) {
            Column(
                Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    stringResource(R.string.speedtest_profile_title, t.name),
                    style = MaterialTheme.typography.titleLarge,
                )
                val res = testResult
                when {
                    testRunning && res == null -> {
                        Text(testNote ?: "", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("…", style = MaterialTheme.typography.headlineMedium)
                    }
                    res != null -> {
                        val q = SpeedTester.verdict(res)
                        if (q != null) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("●", color = qualityColor(q), style = MaterialTheme.typography.headlineMedium)
                                Text(
                                    stringResource(SpeedTester.qualityLabel(q)),
                                    style = MaterialTheme.typography.headlineMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = qualityColor(q),
                                )
                            }
                        }
                        Text(
                            SpeedTester.format(res),
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        )
                    }
                    else -> {
                        Text(testNote ?: "", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    }
                }
                Spacer(Modifier.padding(bottom = 12.dp))
            }
        }
    }

    if (sheetOpen) {
        ModalBottomSheet(onDismissRequest = { sheetOpen = false }, sheetState = sheetState) {
            // v1.7.4 — the user's bug report: paste several configs, the keyboard
            // eats the sheet height, the Import button ended up off-screen and the
            // column could not scroll — importing was impossible. The column now
            // scrolls (and pads for the IME); the field itself is height-capped so
            // even a 50-line paste never pushes the buttons out of reach.
            Column(
                Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
                    .imePadding(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(stringResource(R.string.profiles_add), style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    label = { Text(stringResource(R.string.profiles_url_hint)) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp, max = 220.dp),
                    minLines = 4,
                )
                // live feedback for the multi-import case: how many links
                // are actually visible in the paste right now
                val detected = remember(input) {
                    if (input.isBlank()) 0 else ShareLinkParser.parse(input).size
                }
                if (detected > 0) {
                    Text(
                        stringResource(R.string.profiles_detected, detected),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
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
                Spacer(Modifier.padding(bottom = 8.dp))
            }
        }
    }
}
