package app.kukuvpn.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.core.content.pm.PackageInfoCompat
import app.kukuvpn.R
import app.kukuvpn.core.update.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * v1.4.1 — the About page the user asked for: app version, engine line and
 * the project's GitHub link, laid out after the About screen the user showed
 * in the numbered Aether screenshots.
 */
@Composable
fun AboutScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val pkgInfo = remember {
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0) }.getOrNull()
    }
    val versionLine = pkgInfo?.let {
        stringResource(R.string.about_version_value, it.versionName ?: "?", PackageInfoCompat.getLongVersionCode(it))
    } ?: stringResource(R.string.about_version_unknown)
    val localVersion = pkgInfo?.versionName ?: ""
    val scope = rememberCoroutineScope()
    var updateLine by remember { mutableStateOf("") }
    var updateUrl by remember { mutableStateOf("") }
    var checking by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        TextButton(onClick = onBack, contentPadding = PaddingValues(0.dp)) {
            Text("←")
        }
        Text(stringResource(R.string.about_title), style = MaterialTheme.typography.headlineSmall)

        /* ------------------------------ identity ------------------------------ */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Kuku VPN", style = MaterialTheme.typography.titleLarge)
                Text(versionLine, style = MaterialTheme.typography.bodyMedium)
                Text(
                    stringResource(R.string.about_engine_value),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        /* ------------------------------- github ------------------------------- */
        Card {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable {
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/nimbacc/kuku-vpn")))
                        }
                    }
                    .padding(12.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.about_github), style = MaterialTheme.typography.titleMedium)
                    Text(
                        "github.com/nimbacc/kuku-vpn",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text("↗", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        /* ---------------------------- update check ----------------------------- */
        // v1.7.0: one GET against the GitHub releases API when the user taps —
        // no background polling, no telemetry.
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                TextButton(
                    onClick = {
                        if (!checking) {
                            checking = true
                            updateLine = ""
                            scope.launch {
                                val result = withContext(Dispatchers.IO) { UpdateChecker.latest() }
                                checking = false
                                result.onSuccess { rel ->
                                    if (localVersion.isNotBlank() && UpdateChecker.isNewer(rel.tag, localVersion)) {
                                        updateLine = context.getString(R.string.about_update_available, rel.tag)
                                        updateUrl = rel.url
                                    } else {
                                        updateLine = context.getString(R.string.about_update_latest)
                                        updateUrl = ""
                                    }
                                }.onFailure {
                                    updateLine = context.getString(R.string.about_update_failed, it.message ?: "?")
                                    updateUrl = ""
                                }
                            }
                        }
                    }
                ) { Text(if (checking) "…" else stringResource(R.string.about_check_update)) }
                if (updateLine.isNotBlank()) {
                    Text(
                        updateLine,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (updateUrl.isNotBlank()) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.clickable(enabled = updateUrl.isNotBlank()) {
                            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(updateUrl))) }
                        },
                    )
                }
            }
        }

        /* --------------------------- recent changes ---------------------------- */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.about_changes), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.about_change_170), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_169), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_168), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_167), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_166), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_165), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_164), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_163), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_162), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_161), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_160), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_150), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_141), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_140), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_change_130), style = MaterialTheme.typography.bodySmall)
            }
        }

        Text(
            stringResource(R.string.about_licenses),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
