package app.kukuvpn.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.kukuvpn.R
import app.kukuvpn.bg.TunnelStage
import java.util.Locale

/* --------------------------- formatting helpers ------------------------- */

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KB", "MB", "GB", "TB")
    var v = bytes / 1024.0
    var u = 0
    while (v >= 1024 && u < units.lastIndex) { v /= 1024; u++ }
    return String.format(Locale.US, "%.1f %s", v, units[u])
}

fun formatUptime(sec: Long): String {
    val h = sec / 3600
    val m = (sec % 3600) / 60
    val s = sec % 60
    return if (h > 0) String.format(Locale.US, "%d:%02d:%02d", h, m, s)
    else String.format(Locale.US, "%02d:%02d", m, s)
}

/* ------------------------------- stage bar ------------------------------- */

@Composable
fun StageBar(lit: Set<TunnelStage>, modifier: Modifier = Modifier) {
    val labels = listOf(
        stringResource(R.string.stage_core),
        stringResource(R.string.stage_listener),
        stringResource(R.string.stage_tunnel),
        stringResource(R.string.stage_exit),
    )
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        TunnelStage.entries.forEachIndexed { i, stage ->
            val isLit = stage in lit
            Card(
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(10.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isLit) MaterialTheme.colorScheme.primary.copy(alpha = 0.18f)
                    else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
                ),
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                    androidx.compose.material3.Surface(
                        shape = RoundedCornerShape(50),
                        color = if (isLit) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                        modifier = Modifier.size(10.dp),
                    ) {}
                    Text(
                        labels[i],
                        style = MaterialTheme.typography.labelSmall,
                        color = if (isLit) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
            }
        }
    }
}

/* ------------------------------- stat tile ------------------------------- */

@Composable
fun StatTile(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier, shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                value,
                style = MaterialTheme.typography.titleMedium,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
            )
        }
    }
}

/* ------------------------------ traffic chart ---------------------------- */

/**
 * Minimal dual-line sparkline (down = primary, up = secondary). Samples are
 * bytes/sec pushed from HomeScreen once per second while the tunnel is active.
 */
@Composable
fun TrafficChart(downSamples: List<Long>, upSamples: List<Long>, modifier: Modifier = Modifier) {
    // colors must be read OUTSIDE the draw scope (composable context rule)
    val primary = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.secondary
    Card(modifier, shape = RoundedCornerShape(12.dp)) {
        Box(Modifier.fillMaxWidth().height(96.dp).padding(8.dp)) {
            Canvas(Modifier.fillMaxSize()) {
                fun drawLine(samples: List<Long>, color: Color) {
                    if (samples.size < 2) return
                    val max = (samples.max().coerceAtLeast(1L)).toFloat()
                    val stepX = size.width / (samples.size - 1)
                    var prev = androidx.compose.ui.geometry.Offset(0f, size.height)
                    samples.forEachIndexed { i, v ->
                        val y = size.height - (v / max) * size.height * 0.92f
                        val p = androidx.compose.ui.geometry.Offset(i * stepX, y)
                        drawLine(color, prev, p, strokeWidth = 4f)
                        prev = p
                    }
                }
                drawLine(upSamples, secondary)
                drawLine(downSamples, primary)
            }
        }
    }
}
