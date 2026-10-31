package io.github.rldona.openpassword.locale

import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import java.util.Locale

/** Interface language. [SYSTEM] follows the device. */
enum class AppLanguage(val tag: String?) {
    SYSTEM(null),
    ENGLISH("en"),
    SPANISH("es"),
    ;

    companion object {
        /**
         * Accepts a full tag ("es-ES", the form the platform returns and a device may carry) and
         * falls back to the system for anything we do not ship.
         */
        fun fromTag(tag: String?): AppLanguage {
            val language = tag?.substringBefore('-')?.lowercase()?.ifBlank { null } ?: return SYSTEM
            return entries.firstOrNull { it.tag == language } ?: SYSTEM
        }
    }
}

/**
 * Per-app language without pulling in AppCompat.
 *
 * On Android 13+ the platform owns it ([LocaleManager]): it persists the choice, recreates the
 * activities and applies it to services too. On 28-32 the choice is stored in a preference and
 * applied by hand to every context that shows text; `Locale.setDefault` is deliberately left
 * alone, so formatters must use the configuration locale, never the default one.
 */
object AppLocales {
    private const val PREFS = "app_language"
    private const val KEY = "tag"

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun current(context: Context): AppLanguage {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val manager = context.getSystemService(LocaleManager::class.java) ?: return AppLanguage.SYSTEM
            manager.applicationLocales.toLanguageTags().substringBefore(',').ifBlank { null }
        } else {
            prefs(context).getString(KEY, null)
        }
        return AppLanguage.fromTag(tag)
    }

    fun set(activity: Activity, language: AppLanguage) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val manager = activity.getSystemService(LocaleManager::class.java) ?: return
            manager.applicationLocales =
                language.tag?.let { LocaleList.forLanguageTags(it) } ?: LocaleList.getEmptyLocaleList()
        } else {
            prefs(activity).edit().putString(KEY, language.tag).apply()
            activity.recreate()
        }
    }

    /**
     * Locale override for an activity, as a delta so `uiMode` and everything else still come
     * from the system. Null means "nothing to override".
     */
    fun overrideFor(base: Context): Configuration? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return null
        val tag = prefs(base).getString(KEY, null) ?: return null
        return Configuration().apply { setLocales(LocaleList(Locale.forLanguageTag(tag))) }
    }

    /**
     * Context with the chosen language, for anything that has no activity to override: the
     * autofill service, toasts from background code, and notifications.
     */
    fun wrap(base: Context): Context {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) return base
        val tag = prefs(base).getString(KEY, null) ?: return base
        val configuration = Configuration(base.resources.configuration).apply {
            setLocales(LocaleList(Locale.forLanguageTag(tag)))
        }
        return base.createConfigurationContext(configuration)
    }

    /** Moves a pre-13 preference into the platform once the device can hold it. */
    fun migrateLegacy(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val tag = prefs(context).getString(KEY, null) ?: return
        val manager = context.getSystemService(LocaleManager::class.java)
        if (manager != null && manager.applicationLocales.isEmpty) {
            manager.applicationLocales = LocaleList.forLanguageTags(tag)
        }
        prefs(context).edit().remove(KEY).apply()
    }
}
