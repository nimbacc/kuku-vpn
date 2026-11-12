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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.kukuvpn.R
import app.kukuvpn.bg.TunnelStage
import java.util.Locale

/* --------------------------- formatting helpers ------------------------- */

/**
 * v1.7.4 — the Iter-style verdict color: weak red, medium amber, good green,
 * excellent cyan. Fixed hexes on purpose (readable in both themes).
 */
fun qualityColor(q: app.kukuvpn.core.speed.SpeedTester.Quality): Color = when (q) {
    app.kukuvpn.core.speed.SpeedTester.Quality.WEAK -> Color(0xFFEF5350)
    app.kukuvpn.core.speed.SpeedTester.Quality.MEDIUM -> Color(0xFFFFB300)
    app.kukuvpn.core.speed.SpeedTester.Quality.GOOD -> Color(0xFF66BB6A)
    app.kukuvpn.core.speed.SpeedTester.Quality.EXCELLENT -> Color(0xFF26C6DA)
}


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

/** "1.2 MB/s" — per-second rate for the chart header and the notification. */
fun formatSpeed(bytesPerSec: Long): String = "${formatBytes(bytesPerSec)}/s"

/**
 * v1.7.0 — "DE" → 🇩🇪 via regional-indicator symbols. Empty/invalid input
 * returns "" so the UI just shows the bare IP.
 *
 * v1.7.1 FIX: Character.toChars() returns a char[] — the old code joined a
 * List<char[]> and joinToString() called toString() on the ARRAYS, so the
 * Exit-IP tile showed "[C@fbd365e[C@…" (the user's screenshot). append(char[])
 * appends the actual characters.
 */
fun flagOf(countryCode: String): String {
    val cc = countryCode.trim().uppercase(Locale.US)
    if (cc.length != 2 || cc.any { it !in 'A'..'Z' }) return ""
    return buildString {
        for (c in cc) append(Character.toChars(0x1F1E6 + (c.code - 'A'.code)))
    }
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
                // v1.7.2: “🇩🇪 104.28.x.x” was CLIPPED at one tile width — the
                // user saw the flag with no address. Ellipsis is the honest
                // fallback; the exit tile also got extra width on Home.
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/* ------------------------------ traffic chart ---------------------------- */

/**
 * v1.7.0 — REDESIGNED. The old anonymous dual sparkline read like a heart
 * monitor strip with no meaning (the user's words: "نمودار چی نشون می‌ده؟").
 * The new one is self-explanatory:
 *   • a titled card: what it is + the time window
 *   • a legend with LIVE numbers: current download and upload speed
 *   • one filled area per direction, scaled to the SESSION PEAK (fixed scale
 *     while connected, so the shape means something across seconds)
 *   • a peak marker so a quiet moment does not look like "nothing works"
 * Samples are bytes/sec pushed from HomeScreen once per second while active.
 */
@Composable
fun TrafficChart(
    downSamples: List<Long>,
    upSamples: List<Long>,
    active: Boolean,
    modifier: Modifier = Modifier,
    // v1.7.4: the Iter-style verdict — announced INSIDE the chart's legend row,
    // next to the live numbers ("کنار نمودار اعلام کنه")
    qualityLabel: String? = null,
    qualityColor: Color = Color(0xFF9E9E9E),
) {
    // colors must be read OUTSIDE the draw scope (composable context rule)
    val primary = MaterialTheme.colorScheme.primary
    val secondary = MaterialTheme.colorScheme.secondary
    val outline = MaterialTheme.colorScheme.outlineVariant
    val downNow = downSamples.lastOrNull() ?: 0L
    val upNow = upSamples.lastOrNull() ?: 0L
    val peak = maxOf(downSamples.maxOrNull() ?: 0L, upSamples.maxOrNull() ?: 0L)

    Card(modifier, shape = RoundedCornerShape(12.dp)) {
        // v1.7.1: tightened (canvas 84→62, paddings) so the Home screen fits
        // ONE phone page with no scrolling (the user's ask)
        Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
            Text(stringResource(R.string.chart_title), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(R.string.chart_caption, formatBytes(peak)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (!active && downSamples.isEmpty() && upSamples.isEmpty()) {
                Text(
                    stringResource(R.string.chart_idle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp),
                    textAlign = TextAlign.Center,
                )
            } else {
                // live legend — the numbers ARE the answer to "what am I looking at"
                Row(
                    Modifier.fillMaxWidth().padding(top = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    LegendChip("▾", primary, formatSpeed(downNow))
                    LegendChip("▴", secondary, formatSpeed(upNow))
                    if (qualityLabel != null) {
                        // right-aligned quality verdict (weak/medium/good/excellent)
                        Box(Modifier.weight(1f))
                        LegendChip("●", qualityColor, qualityLabel)
                    }
                }
                Canvas(
                    Modifier
                        .fillMaxWidth()
                        .height(62.dp)
                        .padding(top = 4.dp)
                ) {
                    // scale to the session peak (never zero) — a fixed scale
                    // during a session makes the shape comparable over time
                    val max = peak.coerceAtLeast(64L * 1024L).toFloat()
                    // baseline
                    drawLine(outline, Offset(0f, size.height - 1), Offset(size.width, size.height - 1), strokeWidth = 2f)
                    fun area(samples: List<Long>, color: Color) {
                        if (samples.isEmpty()) return
                        val stepX = size.width / 59f
                        fun x(i: Int) = if (samples.size == 1) 0f else i * (size.width / (samples.size - 1).coerceAtLeast(1))
                        val path = Path()
                        samples.forEachIndexed { i, v ->
                            val px = x(i)
                            val py = size.height - ((v / max) * (size.height - 4)).coerceAtLeast(0f)
                            if (i == 0) path.moveTo(px, py) else path.lineTo(px, py)
                        }
                        // fill down to the baseline
                        val fill = Path().apply {
                            addPath(path)
                            lineTo(x(samples.size - 1), size.height)
                            lineTo(0f, size.height)
                            close()
                        }
                        drawPath(fill, color.copy(alpha = 0.18f))
                        drawPath(path, color, style = Stroke(width = 3f, cap = StrokeCap.Round))
                    }
                    area(upSamples, secondary)
                    area(downSamples, primary)
                }
            }
        }
    }
}

@Composable
private fun LegendChip(arrow: String, color: Color, value: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        androidx.compose.material3.Surface(
            shape = RoundedCornerShape(50),
            color = color,
            modifier = Modifier.size(8.dp),
        ) {}
        Text(
            "$arrow $value",
            style = MaterialTheme.typography.titleSmall,
            fontFamily = FontFamily.Monospace,
            color = color,
        )
    }
}
