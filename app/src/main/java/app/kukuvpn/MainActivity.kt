package app.kukuvpn

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.os.LocaleListCompat
import app.kukuvpn.data.AppSettings
import app.kukuvpn.ui.KukuAppRoot
import app.kukuvpn.ui.theme.KukuTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(Dispatchers.Main)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as KukuApp
        // per-app language (fa / en / system) via AppCompat locales
        scope.launch {
            app.settingsStore.settings.map { it.language }.distinctUntilChanged().collect { lang ->
                AppCompatDelegate.setApplicationLocales(
                    if (lang.isBlank()) LocaleListCompat.getEmptyLocaleList()
                    else LocaleListCompat.forLanguageTags(lang)
                )
            }
        }

        handleShareIntent(intent)

        setContent {
            val settings by app.settingsStore.settings.collectAsState(initial = AppSettings())
            KukuTheme(themeSetting = settings.theme) {
                KukuAppRoot()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShareIntent(intent)
    }

    /** Incoming vless:// ss:// … links (browser tap or "share to Kuku"). */
    private fun handleShareIntent(intent: Intent?) {
        intent?.data?.toString()?.takeIf { it.contains("://") }?.let { app.kukuvpn.ui.ImportIntents.pending += it }
    }
}
