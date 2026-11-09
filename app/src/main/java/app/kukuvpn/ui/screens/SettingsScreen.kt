package app.kukuvpn.ui.screens

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.SplitMode
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(snackbar: SnackbarHostState, onOpenConnection: () -> Unit = {}, onOpenAbout: () -> Unit = {}) {
    val context = LocalContext.current
    val app = context.applicationContext as KukuApp
    val scope = rememberCoroutineScope()
    val settings by app.settingsStore.settings.collectAsState(initial = AppSettings())
    var appsDialog by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.headlineSmall)

        /* ----------------------------- connection ----------------------------- */
        SectionCard {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpenConnection() }
                    .padding(12.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.conn_title), style = MaterialTheme.typography.titleMedium)
                    Text(
                        protocolSummary(settings.protocol),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("›", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        /* ------------------------------ language ------------------------------ */
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                Text(stringResource(R.string.settings_language), Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                listOf("" to stringResource(R.string.theme_system), "fa" to "فارسی", "en" to "English").forEach { (code, label) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = settings.language == code,
                            onClick = {
                                scope.launch {
                                    app.settingsStore.setLanguage(code)
                                    AppCompatDelegate.setApplicationLocales(
                                        if (code.isBlank()) LocaleListCompat.getEmptyLocaleList()
                                        else LocaleListCompat.forLanguageTags(code)
                                    )
                                }
                            },
                        )
                        Text(label, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        /* -------------------------------- theme ------------------------------- */
        SectionCard {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                Text(stringResource(R.string.settings_theme), Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                listOf(0 to stringResource(R.string.theme_system), 1 to stringResource(R.string.theme_light), 2 to stringResource(R.string.theme_dark)).forEach { (v, label) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = settings.theme == v, onClick = { scope.launch { app.settingsStore.setTheme(v) } })
                        Text(label, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        /* --------------------------- split tunneling -------------------------- */
        SectionCard {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.settings_split), style = MaterialTheme.typography.titleMedium)
                listOf(
                    SplitMode.ALL to stringResource(R.string.split_all),
                    SplitMode.INCLUDE to stringResource(R.string.split_include),
                    SplitMode.EXCLUDE to stringResource(R.string.split_exclude),
                ).forEach { (mode, label) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = settings.splitMode == mode, onClick = { scope.launch { app.settingsStore.setSplitMode(mode) } })
                        Text(label, style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (settings.splitMode != SplitMode.ALL) {
                    TextButton(onClick = { appsDialog = true }) {
                        Text(stringResource(R.string.settings_split) + " (${settings.splitApps.size})")
                    }
                    Text(stringResource(R.string.split_apps_hint), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        /* ------------------------- security / behaviour ------------------------ */
        SectionCard {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                ToggleRow(stringResource(R.string.settings_kill_switch), settings.killSwitch) { v -> scope.launch { app.settingsStore.setKillSwitch(v) } }
                Text(stringResource(R.string.kill_switch_desc), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) {
                    Text(stringResource(R.string.kill_switch_system))
                }
                ToggleRow(stringResource(R.string.settings_auto_fallback), settings.autoFallback) { v -> scope.launch { app.settingsStore.setAutoFallback(v) } }
                Text(stringResource(R.string.fallback_desc), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        /* ------------------------------ misc ----------------------------------- */
        SectionCard {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                ToggleRow(stringResource(R.string.settings_sub_auto_update), settings.subAutoUpdate) { v -> scope.launch { app.settingsStore.setSubAutoUpdate(v) } }
                ToggleRow(stringResource(R.string.mode_vpn), settings.vpnMode) { v -> scope.launch { app.settingsStore.setVpnMode(v) } }
            }
        }

        /* ------------------------------- about --------------------------------- */
        SectionCard {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpenAbout() }
                    .padding(12.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.about_title), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(R.string.about_settings_hint),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("›", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    if (appsDialog) {
        val pm = context.packageManager
        val self = context.packageName
        val apps = pm.getInstalledPackages(0)
            .mapNotNull { info ->
                runCatching {
                    (info.applicationInfo?.let { pm.getApplicationLabel(it) }?.toString() ?: info.packageName) to info.packageName
                }.getOrNull()
            }
            .filter { it.second != self && it.second.isNotBlank() }
            .sortedBy { it.first }
        AlertDialog(
            onDismissRequest = { appsDialog = false },
            confirmButton = { TextButton(onClick = { appsDialog = false }) { Text(stringResource(R.string.ok)) } },
            title = { Text(stringResource(R.string.settings_split)) },
            text = {
                LazyColumn(modifier = Modifier.fillMaxWidth()) {
                    items(apps) { (label, pkg) ->
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                            Checkbox(
                                checked = pkg in settings.splitApps,
                                onCheckedChange = { checked ->
                                    scope.launch {
                                        val newSet = settings.splitApps.toMutableSet()
                                        if (checked) newSet += pkg else newSet -= pkg
                                        app.settingsStore.setSplitApps(newSet)
                                    }
                                },
                            )
                            Text(label, modifier = Modifier.padding(start = 8.dp), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            },
        )
    }
}

@Composable
private fun SectionCard(content: @Composable () -> Unit) {
    Card { content() }
}

/** One-line summary under the Connection entry — the current method. */
@Composable
private fun protocolSummary(protocol: String): String = when (protocol) {
    "masque" -> stringResource(R.string.conn_masque)
    "wg" -> stringResource(R.string.conn_wg)
    "gool" -> stringResource(R.string.conn_gool)
    else -> stringResource(R.string.conn_smart)
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
