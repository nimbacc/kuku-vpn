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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.pm.PackageInfoCompat
import app.kukuvpn.R

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

        /* --------------------------- recent changes ---------------------------- */
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.about_changes), style = MaterialTheme.typography.titleMedium)
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
