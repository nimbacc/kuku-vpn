package app.kukuvpn.ui

import android.content.Context
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.core.links.ShareLinkParser
import app.kukuvpn.core.links.SubscriptionFetcher
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.ui.screens.HomeScreen
import app.kukuvpn.ui.screens.LogsScreen
import app.kukuvpn.ui.screens.ProfilesScreen
import app.kukuvpn.ui.screens.SettingsScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Links that arrive via VIEW intents (browser / share) land here. */
object ImportIntents {
    val pending = mutableListOf<String>()

    suspend fun import(context: Context, raw: String): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            val app = context.applicationContext as KukuApp
            val text = raw.trim()
            val profiles = if (ShareLinkParser.isSupported(text)) {
                ShareLinkParser.parse(text)
            } else {
                SubscriptionFetcher.fetch(text, text) // throws with a useful message on failure
            }
            require(profiles.isNotEmpty()) { "no profile found" }
            app.profileStore.addAll(profiles)
            profiles.size
        }
    }
}

private data class Tab(val route: String, val labelRes: Int, val icon: @Composable () -> Unit)

@Composable
fun KukuAppRoot() {
    val nav = rememberNavController()
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current

    // drain share intents that arrived before/while composing
    LaunchedEffect(Unit) {
        kotlinx.coroutines.delay(400)
        val links = ImportIntents.pending.toList()
        ImportIntents.pending.clear()
        for (link in links) {
            ImportIntents.import(context, link).onSuccess {
                snackbar.showSnackbar(context.getString(R.string.profiles_imported, it))
            }.onFailure {
                snackbar.showSnackbar(context.getString(R.string.profiles_import_failed, it.message ?: "?"))
            }
        }
    }

    val tabs = listOf(
        Tab("home", R.string.tab_home) { Icon(Icons.Filled.Home, null) },
        Tab("profiles", R.string.tab_profiles) { Icon(Icons.Filled.Storage, null) },
        Tab("logs", R.string.tab_logs) { Icon(Icons.Filled.Terminal, null) },
        Tab("settings", R.string.tab_settings) { Icon(Icons.Filled.Settings, null) },
    )

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                val current by nav.currentBackStackEntryAsState()
                tabs.forEach { tab ->
                    NavigationBarItem(
                        selected = current?.destination?.route == tab.route,
                        onClick = { nav.navigate(tab.route) { launchSingleTop = true; popUpTo("home") { saveState = true } } },
                        icon = tab.icon,
                        label = { Text(stringResource(tab.labelRes)) },
                    )
                }
            }
        },
    ) { padding ->
        NavHost(nav, startDestination = "home", modifier = Modifier.padding(padding)) {
            composable("home") { HomeScreen() }
            composable("profiles") { ProfilesScreen(snackbar = snackbar) }
            composable("logs") { LogsScreen() }
            composable("settings") { SettingsScreen(snackbar = snackbar) }
        }
    }
}
