package app.valenced.xposed.tweaks.plugins.external

import app.valenced.xposed.dexTypes
import app.valenced.xposed.syntheticDex
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.*

private const val COMPILED = "de/robv/android/xposed"

class XposedApiRelocationTest {
    private val dir: File = Files.createTempDirectory("valenced-relocation-test").toFile()
    private val cache = File(dir, "cache")

    @AfterTest
    fun cleanup() {
        dir.deleteRecursively()
    }

    private fun jarOf(dex: ByteArray): File = File(dir, "plugin.jar").also { jar ->
        ZipOutputStream(jar.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(dex)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("resource.txt"))
            zip.write("data".toByteArray())
            zip.closeEntry()
        }
    }

    private val xposedDex = syntheticDex(listOf("Lcom/a/A;", "L$COMPILED/Foo;"), listOf(0, 1))

    @Test
    fun `an API that isn't renamed leaves the jar alone`() {
        val jar = jarOf(xposedDex)

        assertEquals(jar, relocateXposedApi(jar, cache, COMPILED))
        assertFalse(cache.exists())
    }

    @Test
    fun `an obfuscated API gets a relocated copy with everything else intact`() {
        val jar = jarOf(xposedDex)

        val relocated = relocateXposedApi(jar, cache, "an")

        assertNotEquals(jar, relocated)
        ZipFile(relocated).use { zip ->
            val dex = zip.getInputStream(zip.getEntry("classes.dex")).use { it.readBytes() }
            assertEquals(listOf("Lan/Foo;", "Lcom/a/A;"), dex.dexTypes())
            assertEquals("data", zip.getInputStream(zip.getEntry("resource.txt")).use { String(it.readBytes()) })
        }
    }

    @Test
    fun `a relocated copy is reused`() {
        val jar = jarOf(xposedDex)

        val first = relocateXposedApi(jar, cache, "an")
        val modified = first.lastModified()
        val second = relocateXposedApi(jar, cache, "an")

        assertEquals(first, second)
        assertEquals(modified, second.lastModified())
    }

    @Test
    fun `a new name for the API retires older copies`() {
        val jar = jarOf(xposedDex)

        val first = relocateXposedApi(jar, cache, "an")
        val second = relocateXposedApi(jar, cache, "ao")

        assertNotEquals(first, second)
        assertFalse(first.exists())
        assertTrue(second.isFile)
    }

    @Test
    fun `a changed plugin gets a new copy`() {
        val first = relocateXposedApi(jarOf(xposedDex), cache, "an")
        val other = syntheticDex(listOf("Lcom/a/B;", "L$COMPILED/Bar;"), listOf(0, 1))
        val second = relocateXposedApi(jarOf(other), cache, "an")

        assertNotEquals(first, second)
        ZipFile(second).use { zip ->
            val dex = zip.getInputStream(zip.getEntry("classes.dex")).use { it.readBytes() }
            assertEquals(listOf("Lan/Bar;", "Lcom/a/B;"), dex.dexTypes())
        }
    }
}
