package app.valenced.xposed.tweaks.plugins.external

import app.valenced.xposed.DexRemapper
import de.robv.android.xposed.XposedBridge
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

private const val RELOCATED_PREFIX = "relocated-"

private val dexEntry = Regex("classes\\d*\\.dex")

/**
 * Package the plugin API was compiled against. Assembled at runtime because the framework may rewrite
 * the module's own references to it, string constants included.
 */
private val compiledXposedPackage = listOf("de", "robv", "android", "xposed").joinToString("/")

/** Package the Xposed API is actually loaded under. Differs when the framework obfuscates it. */
private val loadedXposedPackage: String
    get() = XposedBridge::class.java.name.substringBeforeLast('.').replace('.', '/')

/**
 * Returns a plugin [jar] whose DEX files refer to the Xposed API under the name it is loaded as.
 *
 * Plugins are compiled against `de.robv.android.xposed`, but frameworks like LSPosed can obfuscate that package
 * in the target app. Only the module's own DEX is adjusted for it, so a plugin's references wouldn't resolve.
 * When the API isn't renamed, [jar] is returned as is.
 *
 * The relocated copy lives in [cacheDir], keyed by the plugin and the name the API has right now. The name
 * can change between framework sessions, which retires the older copies.
 */
internal fun relocateXposedApi(
    jar: File,
    cacheDir: File,
    loadedPackage: String = loadedXposedPackage,
): File {
    val from = "L$compiledXposedPackage/"
    val to = "L$loadedPackage/"
    if (from == to) return jar

    cacheDir.mkdirs()
    val relocated = File(cacheDir, "$RELOCATED_PREFIX${relocationKey(jar, from, to)}.jar")
    if (relocated.isFile && relocated.length() > 0) return relocated

    // Written aside and renamed, so that a process which dies half-way or another one racing us never leaves a broken jar.
    val partial = File.createTempFile(RELOCATED_PREFIX, ".tmp", cacheDir)
    try {
        writeRelocated(jar, partial, from, to)
        check(partial.renameTo(relocated)) { "Failed to move relocated plugin into place: ${relocated.name}" }
    } finally {
        partial.delete()
    }

    // Android 14+ refuses to load a writable DEX file.
    relocated.setReadOnly()

    cacheDir.listFiles { file -> file.name.endsWith(".jar") && file.name != relocated.name }
        ?.forEach { it.delete() }

    return relocated
}

private fun writeRelocated(jar: File, target: File, from: String, to: String) {
    ZipFile(jar).use { zip ->
        ZipOutputStream(target.outputStream().buffered()).use { out ->
            for (entry in zip.entries().asSequence()) {
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                val content = if (dexEntry.matches(entry.name)) {
                    try {
                        DexRemapper.remap(bytes, from, to)
                    } catch (e: IllegalArgumentException) {
                        throw IllegalArgumentException(
                            "Cannot relocate the Xposed API in ${jar.name}:${entry.name}: ${e.message}",
                            e,
                        )
                    }
                } else {
                    bytes
                }
                out.putNextEntry(ZipEntry(entry.name))
                out.write(content)
                out.closeEntry()
            }
        }
    }
}

private fun relocationKey(jar: File, from: String, to: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
    jar.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    digest.update("${DexRemapper.VERSION}|$from|$to".toByteArray())
    return digest.digest().joinToString("") { "%02x".format(it) }.take(24)
}
