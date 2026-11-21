package app.valenced.xposed

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import kotlin.test.*

private const val FROM = "Lde/robv/android/xposed/"

/**
 * A DEX with the given sorted ASCII [strings] and a type for each of [typeStrings] (indices into [strings]),
 * and nothing else. Short enough that every string length fits one byte.
 */
internal fun syntheticDex(strings: List<String>, typeStrings: List<Int>): ByteArray {
    val stringIdsOff = 0x70
    val typeIdsOff = stringIdsOff + strings.size * 4
    val dataOff = typeIdsOff + typeStrings.size * 4

    val data = ByteArrayOutputStream()
    val stringOffsets = strings.map { string ->
        (dataOff + data.size()).also {
            data.write(string.length)
            data.write(string.toByteArray(Charsets.US_ASCII))
            data.write(0)
        }
    }

    val mapOff = (dataOff + data.size() + 3) and 3.inv()
    val map = listOf(
        Triple(0x0000, 1, 0),
        Triple(0x0001, strings.size, stringIdsOff),
        Triple(0x0002, typeStrings.size, typeIdsOff),
        Triple(0x2002, strings.size, dataOff),
        Triple(0x1000, 1, mapOff),
    )
    val size = mapOff + 4 + map.size * 12

    val buf = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
    buf.put("dex\n035\u0000".toByteArray(Charsets.US_ASCII))
    buf.putInt(0x20, size)
    buf.putInt(0x24, 0x70)
    buf.putInt(0x28, 0x12345678)
    buf.putInt(0x34, mapOff)
    buf.putInt(0x38, strings.size)
    buf.putInt(0x3C, stringIdsOff)
    buf.putInt(0x40, typeStrings.size)
    buf.putInt(0x44, typeIdsOff)
    buf.putInt(0x68, size - dataOff)
    buf.putInt(0x6C, dataOff)
    stringOffsets.forEachIndexed { n, offset -> buf.putInt(stringIdsOff + n * 4, offset) }
    typeStrings.forEachIndexed { n, string -> buf.putInt(typeIdsOff + n * 4, string) }
    buf.position(dataOff)
    buf.put(data.toByteArray())
    buf.position(mapOff)
    buf.putInt(map.size)
    for ((type, count, offset) in map) {
        buf.putShort(type.toShort())
        buf.putShort(0)
        buf.putInt(count)
        buf.putInt(offset)
    }
    return buf.array()
}

internal fun ByteArray.dexInt(at: Int): Int = ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).getInt(at)

internal fun ByteArray.dexString(index: Int): String {
    val at = dexInt(dexInt(0x3C) + index * 4)
    return String(this, at + 1, this[at].toInt(), Charsets.US_ASCII)
}

internal fun ByteArray.dexStrings(): List<String> = (0 until dexInt(0x38)).map { dexString(it) }

/** The descriptor of each type, in type index order. */
internal fun ByteArray.dexTypes(): List<String> =
    (0 until dexInt(0x40)).map { dexString(dexInt(dexInt(0x44) + it * 4)) }

class DexRemapperTest {
    @Test
    fun `moved types are renamed and the string table stays sorted`() {
        val dex = syntheticDex(listOf("Lcom/a/A;", "Lde/robv/android/xposed/Foo;"), listOf(0, 1))

        val result = DexRemapper.remap(dex, FROM, "Lan/")

        assertEquals(listOf("Lan/Foo;", "Lcom/a/A;"), result.dexStrings())
        assertEquals(listOf("Lan/Foo;", "Lcom/a/A;"), result.dexTypes())
    }

    @Test
    fun `array types move with their element type`() {
        val dex = syntheticDex(
            listOf("Lcom/a/A;", "Lde/robv/android/xposed/Foo;", "[Lde/robv/android/xposed/Foo;"),
            listOf(0, 1, 2),
        )

        val result = DexRemapper.remap(dex, FROM, "Lzz/")

        assertEquals(listOf("Lcom/a/A;", "Lzz/Foo;", "[Lzz/Foo;"), result.dexTypes())
    }

    @Test
    fun `the header and map describe the rewritten file`() {
        val dex = syntheticDex(listOf("Lcom/a/A;", "Lde/robv/android/xposed/Foo;"), listOf(0, 1))

        val result = DexRemapper.remap(dex, FROM, "Lan/")

        assertEquals(result.size, result.dexInt(0x20))
        assertEquals(result.size - result.dexInt(0x6C), result.dexInt(0x68))

        val adler = Adler32().apply { update(result, 12, result.size - 12) }
        assertEquals(adler.value.toInt(), result.dexInt(8))
        val sha1 = MessageDigest.getInstance("SHA-1").apply { update(result, 32, result.size - 32) }.digest()
        assertContentEquals(sha1, result.copyOfRange(12, 32))

        val mapOff = result.dexInt(0x34)
        assertEquals(5, result.dexInt(mapOff)) // header, string ids, type ids, string data, map
        assertEquals(result.size, mapOff + 4 + 5 * 12)
    }

    @Test
    fun `a DEX without types under the prefix is returned as is`() {
        val dex = syntheticDex(listOf("Lcom/a/A;"), listOf(0))

        assertSame(dex, DexRemapper.remap(dex, FROM, "Lan/"))
    }

    @Test
    fun `the same prefix is a no-op`() {
        val dex = syntheticDex(listOf("Lde/robv/android/xposed/Foo;"), listOf(0))

        assertSame(dex, DexRemapper.remap(dex, FROM, FROM))
    }

    @Test
    fun `a descriptor that already exists is rejected`() {
        val dex = syntheticDex(listOf("Lan/Foo;", "Lde/robv/android/xposed/Foo;"), listOf(0, 1))

        assertFailsWith<IllegalArgumentException> { DexRemapper.remap(dex, FROM, "Lan/") }
    }

    @Test
    fun `malformed input is rejected`() {
        assertFailsWith<IllegalArgumentException> { DexRemapper.remap(ByteArray(8), FROM, "Lan/") }
        assertFailsWith<IllegalArgumentException> { DexRemapper.remap(ByteArray(0x70), FROM, "Lan/") }
    }

    @Test
    fun `prefixes must be descriptor prefixes`() {
        val dex = syntheticDex(listOf("Lcom/a/A;"), listOf(0))

        assertFailsWith<IllegalArgumentException> { DexRemapper.remap(dex, "de/robv/", "Lan/") }
        assertFailsWith<IllegalArgumentException> { DexRemapper.remap(dex, FROM, "Lan") }
    }
}
