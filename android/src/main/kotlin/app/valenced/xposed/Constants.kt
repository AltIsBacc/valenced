package app.valenced.xposed

import app.valenced.plugins.VersionRange

object ValencedConstants {
    const val TARGET_PACKAGE = "com.discord"

    /**
     * Discord versions this module's hooks are known to work on, checked by [app.valenced.xposed.tweaks.discordVersionRetriever].
     * Versions outside of it still load, but the user is warned.
     *
     * Keep it in sync with `DISCORD` in `android/patches`, which pins the version Valenced Manager patches.
     */
    val SUPPORTED_DISCORD_VERSIONS = VersionRange.parse(">=352.2 <353")

    const val FILES_DIR = "files/valenced"
    const val CACHE_DIR = "cache/valenced"
    const val MAIN_SCRIPT_FILE = "bundle.js"
    const val BUNDLE_MANIFEST_FILE = "manifest.json"
    const val PRELOADS_DIR = "preloads"

    const val LOADER_NAME = "ValencedAndroid"
    val LOADER_VERSION
        get() = BuildConfig.VERSION_NAME
    val USER_AGENT
        get() = "ValencedAndroid/$LOADER_VERSION"

    /**
     * Hermes bundle shipped inside this APK's `assets/` directory, built by the `:bundle` project.
     * Loaded by [app.valenced.xposed.tweaks.valencedScriptLoader].
     */
    const val BUNDLE_ASSET = "assets://valenced.bundle"
}

/**
 * Hermes bytecode assets shipped inside the Xposed module APK.
 */
val scriptAssets = emptyList<String>()
