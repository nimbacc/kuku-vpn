package app.kukuvpn.core.backup

import android.content.Context
import android.net.Uri
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * v1.7.0 — whole-app backup: profiles + settings in one JSON file the user
 * can export to Downloads (SAF create-document) and restore on this or any
 * other device (SAF open-document). No cloud, no accounts — the file IS the
 * backup, and it lives only where the user puts it.
 */
object Backup {

    const val MIME = "application/json"
    const val SUGGESTED_NAME = "kuku-vpn-backup.json"

    @Serializable
    data class Payload(
        val format: Int = 1,
        val exportedAt: Long = System.currentTimeMillis(),
        val profiles: List<Profile> = emptyList(),
        val settings: AppSettings = AppSettings(),
    )

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true; prettyPrint = true }

    /** Serialise and write to the SAF uri the user picked. Throws with a useful message. */
    fun export(context: Context, uri: Uri, profiles: List<Profile>, settings: AppSettings) {
        val payload = Payload(profiles = profiles, settings = settings)
        val text = json.encodeToString(payload)
        context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
            out.write(text.toByteArray(Charsets.UTF_8))
            out.flush()
        } ?: error("cannot open the destination file")
    }

    /** Read + parse a backup file; returns what it contained for the caller to apply. */
    fun parse(context: Context, uri: Uri): Payload {
        val text = context.contentResolver.openInputStream(uri)?.use { inStream ->
            inStream.readBytes().toString(Charsets.UTF_8)
        } ?: error("cannot read the file")
        // tolerate an accidental BOM from other editors
        return json.decodeFromString<Payload>(text.replace("\uFEFF", "").trim())
    }
}
