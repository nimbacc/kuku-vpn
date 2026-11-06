package app.kukuvpn.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import app.kukuvpn.R
import app.kukuvpn.bg.ServiceBridge
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun LogsScreen() {
    val context = LocalContext.current
    val logs by ServiceBridge.logs.collectAsState()
    val listState = rememberLazyListState()
    val fmt = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

    // live tail: follow only when already at the bottom (no annoying scroll-jump)
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }

    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                val cm = context.getSystemService(android.content.ClipboardManager::class.java)
                cm.setPrimaryClip(
                    android.content.ClipData.newPlainText(
                        "kuku-logs",
                        logs.joinToString("\n") { "${it.level}: ${it.message}" },
                    )
                )
            }) { Text(stringResource(R.string.logs_copy)) }
            TextButton(onClick = { ServiceBridge.clearLogs() }) { Text(stringResource(R.string.logs_clear)) }
        }

        if (logs.isEmpty()) Text(stringResource(R.string.logs_empty), style = MaterialTheme.typography.bodyLarge)

        LazyColumn(state = listState, verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxSize()) {
            items(logs) { line ->
                val color = when (line.level.uppercase()) {
                    "ERROR", "FATAL" -> MaterialTheme.colorScheme.error
                    "WARN", "WARNING" -> Color(0xFFE0A458)
                    "DEBUG" -> MaterialTheme.colorScheme.onSurfaceVariant
                    else -> MaterialTheme.colorScheme.onSurface
                }
                Text(
                    "[${fmt.format(Date(line.time))}] ${line.level} · ${line.message}",
                    color = color,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
