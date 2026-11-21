package app.valenced.xposed

import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * Moves every type under one package prefix of a DEX file to another prefix.
 *
 * Frameworks like LSPosed hide the Xposed API from the app by renaming its package at runtime. The module's own
 * DEX is renamed along with it, but a plugin loaded through a plain `DexClassLoader` still refers to
 * `de.robv.android.xposed.*`. Redirecting those names in a class loader doesn't work, because ART rejects a class
 * whose name differs from the one that was asked for. The references have to be rewritten in the DEX itself.
 *
 * Descriptors are sorted, and everything that points at them is sorted by them in turn. So moving a descriptor
 * renumbers strings, types, prototypes, fields and methods, and the data items that hold those indices
 * (code, debug info, annotations, class data, encoded values) are re-emitted against the new numbering.
 * The result is laid out from scratch and passes ART's DEX verifier.
 *
 * Only what plugin DEX files need is implemented: DEX 035-039, no call sites or method handles.
 */
internal object DexRemapper {
    /** Bump when the output for the same input changes, so cached results are not reused. */
    const val VERSION = 1

    /**
     * Returns [dex] with every type descriptor starting with [from] moved under [to].
     * Both are descriptor prefixes (`Lde/robv/android/xposed/`). Returns [dex] itself if it has no such type.
     *
     * @throws IllegalArgumentException if [dex] is malformed or uses features that aren't supported.
     */
    fun remap(dex: ByteArray, from: String, to: String): ByteArray {
        require(from.startsWith("L") && from.endsWith("/")) { "from must be a descriptor prefix: $from" }
        require(to.startsWith("L") && to.endsWith("/")) { "to must be a descriptor prefix: $to" }
        if (from == to) return dex

        return try {
            Relocation(dex, from, to).run()
        } catch (e: IndexOutOfBoundsException) {
            throw IllegalArgumentException("Malformed DEX file", e)
        }
    }
}

// Header layout.
private const val HEADER_SIZE = 0x70
private const val MAGIC = 0x0A786564 // "dex\n"
private const val ENDIAN_TAG = 0x12345678
private const val NO_INDEX = -1

// Map item types.
private const val MAP_HEADER = 0x0000
private const val MAP_STRING_ID = 0x0001
private const val MAP_TYPE_ID = 0x0002
private const val MAP_PROTO_ID = 0x0003
private const val MAP_FIELD_ID = 0x0004
private const val MAP_METHOD_ID = 0x0005
private const val MAP_CLASS_DEF = 0x0006
private const val MAP_CALL_SITE_ID = 0x0007
private const val MAP_METHOD_HANDLE = 0x0008
private const val MAP_MAP_LIST = 0x1000
private const val MAP_TYPE_LIST = 0x1001
private const val MAP_ANNOTATION_SET_REF_LIST = 0x1002
private const val MAP_ANNOTATION_SET = 0x1003
private const val MAP_CLASS_DATA = 0x2000
private const val MAP_CODE = 0x2001
private const val MAP_STRING_DATA = 0x2002
private const val MAP_DEBUG_INFO = 0x2003
private const val MAP_ANNOTATION = 0x2004
private const val MAP_ENCODED_ARRAY = 0x2005
private const val MAP_ANNOTATIONS_DIRECTORY = 0x2006

private fun ByteArray.u1(at: Int): Int = this[at].toInt() and 0xFF

private fun ByteArray.u2(at: Int): Int = u1(at) or (u1(at + 1) shl 8)

private fun ByteArray.u4(at: Int): Int = u1(at) or (u1(at + 1) shl 8) or (u1(at + 2) shl 16) or (u1(at + 3) shl 24)

private fun ByteArray.put2(at: Int, value: Int) {
    this[at] = value.toByte()
    this[at + 1] = (value ushr 8).toByte()
}

private fun ByteArray.put4(at: Int, value: Int) {
    put2(at, value)
    put2(at + 2, value ushr 16)
}

/** Sequential little-endian reader. */
private class Reader(val bytes: ByteArray, var pos: Int) {
    fun u1(): Int = bytes[pos++].toInt() and 0xFF

    fun u2(): Int = bytes.u2(pos).also { pos += 2 }

    fun u4(): Int = bytes.u4(pos).also { pos += 4 }

    fun uleb(): Int {
        var result = 0
        var shift = 0
        while (true) {
            val b = u1()
            result = result or ((b and 0x7F) shl shift)
            if ((b and 0x80) == 0) return result
            shift += 7
        }
    }

    fun sleb(): Int {
        var result = 0
        var shift = 0
        var b: Int
        do {
            b = u1()
            result = result or ((b and 0x7F) shl shift)
            shift += 7
        } while ((b and 0x80) != 0)
        if (shift < 32 && (b and 0x40) != 0) result = result or (-1 shl shift)
        return result
    }
}

/** Growable little-endian writer. Bytes past [size] are always zero. */
private class Out(capacity: Int) {
    var buf = ByteArray(capacity)
    var size = 0

    private fun ensure(extra: Int) {
        if (size + extra > buf.size) buf = buf.copyOf(maxOf(buf.size * 2, size + extra))
    }

    fun u1(value: Int) {
        ensure(1)
        buf[size++] = value.toByte()
    }

    fun u2(value: Int) {
        ensure(2)
        buf.put2(size, value)
        size += 2
    }

    fun u4(value: Int) {
        ensure(4)
        buf.put4(size, value)
        size += 4
    }

    fun uleb(value: Int) {
        var v = value
        while ((v ushr 7) != 0) {
            u1((v and 0x7F) or 0x80)
            v = v ushr 7
        }
        u1(v)
    }

    fun sleb(value: Int) {
        var v = value
        while (true) {
            val b = v and 0x7F
            v = v shr 7
            if ((v == 0 && (b and 0x40) == 0) || (v == -1 && (b and 0x40) != 0)) {
                u1(b)
                return
            }
            u1(b or 0x80)
        }
    }

    fun bytes(src: ByteArray, off: Int, len: Int) {
        ensure(len)
        System.arraycopy(src, off, buf, size, len)
        size += len
    }

    fun zeros(count: Int) {
        ensure(count)
        size += count
    }

    fun align(alignment: Int) {
        zeros((alignment - (size and (alignment - 1))) and (alignment - 1))
    }
}

private class Section(val type: Int, val count: Int, val offset: Int)

private class Relocation(private val d: ByteArray, private val from: String, private val to: String) {
    private val stringCount = d.u4(0x38)
    private val stringIdsOff = d.u4(0x3C)
    private val typeCount = d.u4(0x40)
    private val typeIdsOff = d.u4(0x44)
    private val protoCount = d.u4(0x48)
    private val protoIdsOff = d.u4(0x4C)
    private val fieldCount = d.u4(0x50)
    private val fieldIdsOff = d.u4(0x54)
    private val methodCount = d.u4(0x58)
    private val methodIdsOff = d.u4(0x5C)
    private val classCount = d.u4(0x60)
    private val classDefsOff = d.u4(0x64)

    private val strings = arrayOfNulls<String>(stringCount)
    private val rewritten = arrayOfNulls<String>(stringCount)

    // Old index -> new index.
    private val strMap = IntArray(stringCount)
    private val typeMap = IntArray(typeCount)
    private val protoMap = IntArray(protoCount)
    private val fieldMap = IntArray(fieldCount)
    private val methodMap = IntArray(methodCount)

    // Old data item offset -> new offset, and old annotation item offset -> new type index.
    private val newOff = HashMap<Int, Int>()
    private val annotationType = HashMap<Int, Int>()

    private val out = Out(d.size + (d.size shr 3) + 4096)
    private val sections = ArrayList<Section>()

    fun run(): ByteArray {
        require(d.size >= HEADER_SIZE && d.u4(0) == MAGIC) { "Not a DEX file" }
        require(d.u4(0x24) == HEADER_SIZE && d.u4(0x28) == ENDIAN_TAG) { "Unsupported DEX header" }
        require(d.u4(0x2C) == 0) { "DEX link data is not supported" }

        // Which strings are type descriptors that move?
        val movedStrings = ArrayList<Int>()
        val movedContents = ArrayList<String>()
        val typeStringIdx = IntArray(typeCount) { d.u4(typeIdsOff + it * 4) }
        for (t in 0 until typeCount) {
            val moved = move(string(typeStringIdx[t])) ?: continue
            movedStrings.add(typeStringIdx[t])
            movedContents.add(moved)
        }
        if (movedStrings.isEmpty()) return d

        rejectUnsupportedSections()

        remapStrings(movedStrings, movedContents)

        // Types are sorted by descriptor.
        val typeKeys = LongArray(typeCount) { (strMap[typeStringIdx[it]].toLong() shl 32) or it.toLong() }
        typeKeys.sort()
        val typeNewString = IntArray(typeCount)
        for (n in 0 until typeCount) {
            typeMap[(typeKeys[n] and 0xFFFFFFFFL).toInt()] = n
            typeNewString[n] = (typeKeys[n] ushr 32).toInt()
        }

        // Prototypes are sorted by return type, then parameter types.
        val protoReturn = IntArray(protoCount) { typeMap[d.u4(protoIdsOff + it * 12 + 4)] }
        val protoParams = Array(protoCount) { mappedTypeList(d.u4(protoIdsOff + it * 12 + 8)) }
        val protoOrder = Array(protoCount) { it }
        protoOrder.sortWith(
            Comparator { a, b ->
                val byReturn = Integer.compare(protoReturn[a], protoReturn[b])
                if (byReturn != 0) byReturn else compareLists(protoParams[a], protoParams[b])
            },
        )
        for (n in 0 until protoCount) protoMap[protoOrder[n]] = n

        // Fields are sorted by class, name, then type.
        val fieldClass = IntArray(fieldCount) { typeMap[d.u2(fieldIdsOff + it * 8)] }
        val fieldType = IntArray(fieldCount) { typeMap[d.u2(fieldIdsOff + it * 8 + 2)] }
        val fieldName = IntArray(fieldCount) { strMap[d.u4(fieldIdsOff + it * 8 + 4)] }
        val fieldOrder = Array(fieldCount) { it }
        fieldOrder.sortWith(
            Comparator { a, b ->
                var c = Integer.compare(fieldClass[a], fieldClass[b])
                if (c == 0) c = Integer.compare(fieldName[a], fieldName[b])
                if (c == 0) c = Integer.compare(fieldType[a], fieldType[b])
                c
            },
        )
        for (n in 0 until fieldCount) fieldMap[fieldOrder[n]] = n

        // Methods are sorted by class, name, then prototype.
        val methodClass = IntArray(methodCount) { typeMap[d.u2(methodIdsOff + it * 8)] }
        val methodProto = IntArray(methodCount) { protoMap[d.u2(methodIdsOff + it * 8 + 2)] }
        val methodName = IntArray(methodCount) { strMap[d.u4(methodIdsOff + it * 8 + 4)] }
        val methodOrder = Array(methodCount) { it }
        methodOrder.sortWith(
            Comparator { a, b ->
                var c = Integer.compare(methodClass[a], methodClass[b])
                if (c == 0) c = Integer.compare(methodName[a], methodName[b])
                if (c == 0) c = Integer.compare(methodProto[a], methodProto[b])
                c
            },
        )
        for (n in 0 until methodCount) methodMap[methodOrder[n]] = n

        // Fixed-size tables go first; they are filled in once the data items they point at have a new offset.
        val newStringIdsOff = HEADER_SIZE
        val newTypeIdsOff = newStringIdsOff + stringCount * 4
        val newProtoIdsOff = newTypeIdsOff + typeCount * 4
        val newFieldIdsOff = newProtoIdsOff + protoCount * 12
        val newMethodIdsOff = newFieldIdsOff + fieldCount * 8
        val newClassDefsOff = newMethodIdsOff + methodCount * 8
        val dataStart = newClassDefsOff + classCount * 32
        out.zeros(dataStart)

        val typeLists = LinkedHashSet<Int>()
        val encodedArrays = LinkedHashSet<Int>()
        val annotations = LinkedHashSet<Int>()
        val annotationSets = LinkedHashSet<Int>()
        val annotationRefLists = LinkedHashSet<Int>()
        val annotationDirectories = LinkedHashSet<Int>()
        val debugInfos = LinkedHashSet<Int>()
        val codeItems = LinkedHashSet<Int>()
        val classDatas = LinkedHashSet<Int>()
        discover(
            typeLists, encodedArrays, annotations, annotationSets, annotationRefLists,
            annotationDirectories, debugInfos, codeItems, classDatas,
        )

        // Items are emitted before the items that point at them, so every offset is known when it is needed.
        val stringOffsets = IntArray(stringCount)
        val newToOldString = IntArray(stringCount)
        for (old in 0 until stringCount) newToOldString[strMap[old]] = old
        phase(MAP_STRING_DATA, stringCount, 1) {
            for (n in 0 until stringCount) {
                stringOffsets[n] = out.size
                emitString(newToOldString[n])
            }
        }
        phase(MAP_TYPE_LIST, typeLists.size, 4) { typeLists.forEach { emitTypeList(it) } }
        phase(MAP_ENCODED_ARRAY, encodedArrays.size, 1) { encodedArrays.forEach { emitEncodedArray(it) } }
        phase(MAP_ANNOTATION, annotations.size, 1) { annotations.forEach { emitAnnotationItem(it) } }
        phase(MAP_ANNOTATION_SET, annotationSets.size, 4) { annotationSets.forEach { emitAnnotationSet(it) } }
        phase(MAP_ANNOTATION_SET_REF_LIST, annotationRefLists.size, 4) {
            annotationRefLists.forEach { emitAnnotationRefList(it) }
        }
        phase(MAP_ANNOTATIONS_DIRECTORY, annotationDirectories.size, 4) {
            annotationDirectories.forEach { emitAnnotationsDirectory(it) }
        }
        phase(MAP_DEBUG_INFO, debugInfos.size, 1) { debugInfos.forEach { emitDebugInfo(it) } }
        phase(MAP_CODE, codeItems.size, 4) { codeItems.forEach { emitCode(it) } }
        phase(MAP_CLASS_DATA, classDatas.size, 1) { classDatas.forEach { emitClassData(it) } }

        out.align(4)
        val mapOff = out.size
        sections.add(Section(MAP_MAP_LIST, 1, mapOff))

        val tables = ArrayList<Section>()
        tables.add(Section(MAP_HEADER, 1, 0))
        if (stringCount > 0) tables.add(Section(MAP_STRING_ID, stringCount, newStringIdsOff))
        if (typeCount > 0) tables.add(Section(MAP_TYPE_ID, typeCount, newTypeIdsOff))
        if (protoCount > 0) tables.add(Section(MAP_PROTO_ID, protoCount, newProtoIdsOff))
        if (fieldCount > 0) tables.add(Section(MAP_FIELD_ID, fieldCount, newFieldIdsOff))
        if (methodCount > 0) tables.add(Section(MAP_METHOD_ID, methodCount, newMethodIdsOff))
        if (classCount > 0) tables.add(Section(MAP_CLASS_DEF, classCount, newClassDefsOff))
        val map = tables + sections
        out.u4(map.size)
        for (section in map) {
            out.u2(section.type)
            out.u2(0)
            out.u4(section.count)
            out.u4(section.offset)
        }

        val b = out.buf

        for (n in 0 until stringCount) b.put4(newStringIdsOff + n * 4, stringOffsets[n])
        for (n in 0 until typeCount) b.put4(newTypeIdsOff + n * 4, typeNewString[n])

        for (n in 0 until protoCount) {
            val old = protoOrder[n]
            val at = newProtoIdsOff + n * 12
            b.put4(at, strMap[d.u4(protoIdsOff + old * 12)])
            b.put4(at + 4, protoReturn[old])
            b.put4(at + 8, offsetOf(d.u4(protoIdsOff + old * 12 + 8)))
        }

        for (n in 0 until fieldCount) {
            val old = fieldOrder[n]
            val at = newFieldIdsOff + n * 8
            b.put2(at, fieldClass[old])
            b.put2(at + 2, fieldType[old])
            b.put4(at + 4, fieldName[old])
        }

        for (n in 0 until methodCount) {
            val old = methodOrder[n]
            val at = newMethodIdsOff + n * 8
            b.put2(at, methodClass[old])
            b.put2(at + 2, methodProto[old])
            b.put4(at + 4, methodName[old])
        }

        // Class definitions keep their order, which has to list superclasses and interfaces first.
        for (c in 0 until classCount) {
            val old = classDefsOff + c * 32
            val at = newClassDefsOff + c * 32
            b.put4(at, typeMap[d.u4(old)])
            b.put4(at + 4, d.u4(old + 4))
            b.put4(at + 8, d.u4(old + 8).let { if (it == NO_INDEX) it else typeMap[it] })
            b.put4(at + 12, offsetOf(d.u4(old + 12)))
            b.put4(at + 16, d.u4(old + 16).let { if (it == NO_INDEX) it else strMap[it] })
            b.put4(at + 20, offsetOf(d.u4(old + 20)))
            b.put4(at + 24, offsetOf(d.u4(old + 24)))
            b.put4(at + 28, offsetOf(d.u4(old + 28)))
        }

        val result = b.copyOf(out.size)
        System.arraycopy(d, 0, result, 0, 8) // magic and version
        result.put4(0x20, result.size)
        result.put4(0x24, HEADER_SIZE)
        result.put4(0x28, ENDIAN_TAG)
        result.put4(0x2C, 0)
        result.put4(0x30, 0)
        result.put4(0x34, mapOff)
        result.put4(0x38, stringCount)
        result.put4(0x3C, if (stringCount > 0) newStringIdsOff else 0)
        result.put4(0x40, typeCount)
        result.put4(0x44, if (typeCount > 0) newTypeIdsOff else 0)
        result.put4(0x48, protoCount)
        result.put4(0x4C, if (protoCount > 0) newProtoIdsOff else 0)
        result.put4(0x50, fieldCount)
        result.put4(0x54, if (fieldCount > 0) newFieldIdsOff else 0)
        result.put4(0x58, methodCount)
        result.put4(0x5C, if (methodCount > 0) newMethodIdsOff else 0)
        result.put4(0x60, classCount)
        result.put4(0x64, if (classCount > 0) newClassDefsOff else 0)
        result.put4(0x68, result.size - dataStart)
        result.put4(0x6C, dataStart)

        val sha1 = MessageDigest.getInstance("SHA-1")
        sha1.update(result, 32, result.size - 32)
        System.arraycopy(sha1.digest(), 0, result, 12, 20)
        val adler = Adler32()
        adler.update(result, 12, result.size - 12)
        result.put4(8, adler.value.toInt())
        return result
    }

    // Strings

    private fun string(index: Int): String = strings[index] ?: readString(index).also { strings[index] = it }

    private fun readString(index: Int): String {
        val r = Reader(d, d.u4(stringIdsOff + index * 4))
        val length = r.uleb()
        val chars = CharArray(length)
        for (n in 0 until length) {
            val a = r.u1()
            chars[n] = when {
                a < 0x80 -> a.toChar()
                (a and 0xE0) == 0xC0 -> (((a and 0x1F) shl 6) or (r.u1() and 0x3F)).toChar()
                else -> (((a and 0x0F) shl 12) or ((r.u1() and 0x3F) shl 6) or (r.u1() and 0x3F)).toChar()
            }
        }
        return String(chars)
    }

    /** [descriptor] with its package prefix moved, or null if it isn't under [from]. Array types are included. */
    private fun move(descriptor: String): String? {
        var dims = 0
        while (dims < descriptor.length && descriptor[dims] == '[') dims++
        if (!descriptor.startsWith(from, dims)) return null
        return descriptor.substring(0, dims) + to + descriptor.substring(dims + from.length)
    }

    /**
     * Strings are sorted. Only the moved descriptors change, so every other string keeps its relative order.
     * Each moved string is placed by binary search among those, and the rest shift by how many moved in front.
     */
    private fun remapStrings(movedStrings: List<Int>, movedContents: List<String>) {
        val moved = movedStrings.size
        val isMoved = BooleanArray(stringCount)
        for (index in movedStrings) isMoved[index] = true
        val kept = IntArray(stringCount - moved)
        var k = 0
        for (index in 0 until stringCount) if (!isMoved[index]) kept[k++] = index

        val byContent = (0 until moved).sortedBy { movedContents[it] }
        val insertAt = IntArray(moved)
        for (m in 0 until moved) {
            val content = movedContents[byContent[m]]
            var lo = 0
            var hi = kept.size
            while (lo < hi) {
                val mid = (lo + hi) ushr 1
                val c = string(kept[mid]).compareTo(content)
                when {
                    c < 0 -> lo = mid + 1
                    c > 0 -> hi = mid
                    else -> throw IllegalArgumentException("DEX already contains $content")
                }
            }
            insertAt[m] = lo
        }

        var before = 0
        for (j in kept.indices) {
            while (before < moved && insertAt[before] <= j) before++
            strMap[kept[j]] = j + before
        }
        for (m in 0 until moved) {
            val index = movedStrings[byContent[m]]
            strMap[index] = insertAt[m] + m
            rewritten[index] = movedContents[byContent[m]]
        }
    }

    private fun emitString(old: Int) {
        val content = rewritten[old]
        if (content != null) {
            out.uleb(content.length)
            for (ch in content) {
                val c = ch.code
                when {
                    c in 1..0x7F -> out.u1(c)
                    c <= 0x7FF -> {
                        out.u1(0xC0 or (c shr 6))
                        out.u1(0x80 or (c and 0x3F))
                    }
                    else -> {
                        out.u1(0xE0 or (c shr 12))
                        out.u1(0x80 or ((c shr 6) and 0x3F))
                        out.u1(0x80 or (c and 0x3F))
                    }
                }
            }
            out.u1(0)
            return
        }

        val start = d.u4(stringIdsOff + old * 4)
        val r = Reader(d, start)
        r.uleb()
        var end = r.pos
        while (d[end] != 0.toByte()) end++
        out.bytes(d, start, end + 1 - start)
    }

    // Layout

    private fun rejectUnsupportedSections() {
        val mapOff = d.u4(0x34)
        val count = d.u4(mapOff)
        for (n in 0 until count) {
            val at = mapOff + 4 + n * 12
            val type = d.u2(at)
            require((type != MAP_CALL_SITE_ID && type != MAP_METHOD_HANDLE) || d.u4(at + 4) == 0) {
                "DEX files with call sites or method handles are not supported"
            }
        }
    }

    private fun phase(type: Int, count: Int, alignment: Int, body: () -> Unit) {
        if (count == 0) return
        out.align(alignment)
        sections.add(Section(type, count, out.size))
        body()
    }

    private fun offsetOf(old: Int): Int = if (old == 0) 0 else newOff.getValue(old)

    private fun nonZero(offset: Int, into: MutableSet<Int>) {
        if (offset != 0) into.add(offset)
    }

    /** Collects every data item reachable from the prototypes and class definitions. */
    private fun discover(
        typeLists: MutableSet<Int>,
        encodedArrays: MutableSet<Int>,
        annotations: MutableSet<Int>,
        annotationSets: MutableSet<Int>,
        annotationRefLists: MutableSet<Int>,
        annotationDirectories: MutableSet<Int>,
        debugInfos: MutableSet<Int>,
        codeItems: MutableSet<Int>,
        classDatas: MutableSet<Int>,
    ) {
        for (p in 0 until protoCount) nonZero(d.u4(protoIdsOff + p * 12 + 8), typeLists)
        for (c in 0 until classCount) {
            val at = classDefsOff + c * 32
            nonZero(d.u4(at + 12), typeLists)
            nonZero(d.u4(at + 20), annotationDirectories)
            nonZero(d.u4(at + 24), classDatas)
            nonZero(d.u4(at + 28), encodedArrays)
        }

        for (directory in annotationDirectories) {
            nonZero(d.u4(directory), annotationSets)
            val fields = d.u4(directory + 4)
            val methods = d.u4(directory + 8)
            val parameters = d.u4(directory + 12)
            var at = directory + 16
            repeat(fields + methods) {
                nonZero(d.u4(at + 4), annotationSets)
                at += 8
            }
            repeat(parameters) {
                nonZero(d.u4(at + 4), annotationRefLists)
                at += 8
            }
        }
        for (list in annotationRefLists) {
            for (n in 0 until d.u4(list)) nonZero(d.u4(list + 4 + n * 4), annotationSets)
        }
        for (set in annotationSets) {
            for (n in 0 until d.u4(set)) nonZero(d.u4(set + 4 + n * 4), annotations)
        }

        for (classData in classDatas) {
            val r = Reader(d, classData)
            val staticFields = r.uleb()
            val instanceFields = r.uleb()
            val directMethods = r.uleb()
            val virtualMethods = r.uleb()
            repeat(staticFields + instanceFields) {
                r.uleb()
                r.uleb()
            }
            repeat(directMethods + virtualMethods) {
                r.uleb()
                r.uleb()
                nonZero(r.uleb(), codeItems)
            }
        }
        for (code in codeItems) nonZero(d.u4(code + 8), debugInfos)
    }

    private fun mappedTypeList(offset: Int): IntArray {
        if (offset == 0) return IntArray(0)
        return IntArray(d.u4(offset)) { typeMap[d.u2(offset + 4 + it * 2)] }
    }

    private fun compareLists(a: IntArray, b: IntArray): Int {
        for (n in 0 until minOf(a.size, b.size)) {
            if (a[n] != b[n]) return Integer.compare(a[n], b[n])
        }
        return Integer.compare(a.size, b.size)
    }

    // Data items

    private fun emitTypeList(old: Int) {
        out.align(4)
        newOff[old] = out.size
        val r = Reader(d, old)
        val size = r.u4()
        out.u4(size)
        repeat(size) { out.u2(typeMap[r.u2()]) }
    }

    private fun emitEncodedArray(old: Int) {
        newOff[old] = out.size
        val r = Reader(d, old)
        val size = r.uleb()
        out.uleb(size)
        repeat(size) { copyValue(r) }
    }

    private fun emitAnnotationItem(old: Int) {
        newOff[old] = out.size
        val r = Reader(d, old)
        out.u1(r.u1()) // visibility
        annotationType[old] = copyAnnotation(r)
    }

    /** Annotation sets are sorted by the type of their annotations. */
    private fun emitAnnotationSet(old: Int) {
        out.align(4)
        newOff[old] = out.size
        val r = Reader(d, old)
        val size = r.u4()
        val keys = LongArray(size)
        for (n in 0 until size) {
            val item = r.u4()
            keys[n] = (annotationType.getValue(item).toLong() shl 32) or newOff.getValue(item).toLong()
        }
        keys.sort()
        out.u4(size)
        for (key in keys) out.u4(key.toInt())
    }

    private fun emitAnnotationRefList(old: Int) {
        out.align(4)
        newOff[old] = out.size
        val r = Reader(d, old)
        val size = r.u4()
        out.u4(size)
        repeat(size) { out.u4(offsetOf(r.u4())) }
    }

    private fun emitAnnotationsDirectory(old: Int) {
        out.align(4)
        newOff[old] = out.size
        val r = Reader(d, old)
        out.u4(offsetOf(r.u4()))
        val fields = r.u4()
        val methods = r.u4()
        val parameters = r.u4()
        out.u4(fields)
        out.u4(methods)
        out.u4(parameters)
        copyIndexed(r, fields, fieldMap)
        copyIndexed(r, methods, methodMap)
        copyIndexed(r, parameters, methodMap)
    }

    /** Copies `(index, offset)` pairs, which are sorted by index. */
    private fun copyIndexed(r: Reader, count: Int, indexMap: IntArray) {
        val keys = LongArray(count)
        val offsets = IntArray(count)
        for (n in 0 until count) {
            keys[n] = (indexMap[r.u4()].toLong() shl 32) or n.toLong()
            offsets[n] = offsetOf(r.u4())
        }
        keys.sort()
        for (key in keys) {
            out.u4((key ushr 32).toInt())
            out.u4(offsets[(key and 0xFFFFFFFFL).toInt()])
        }
    }

    private fun emitDebugInfo(old: Int) {
        newOff[old] = out.size
        val r = Reader(d, old)
        out.uleb(r.uleb()) // line_start
        val parameters = r.uleb()
        out.uleb(parameters)
        repeat(parameters) { out.uleb(mapPlusOne(r.uleb(), strMap)) }
        while (true) {
            val op = r.u1()
            out.u1(op)
            when (op) {
                0x00 -> return
                0x01 -> out.uleb(r.uleb()) // advance pc
                0x02 -> out.sleb(r.sleb()) // advance line
                0x03, 0x04 -> { // start local, with a signature if extended
                    out.uleb(r.uleb())
                    out.uleb(mapPlusOne(r.uleb(), strMap))
                    out.uleb(mapPlusOne(r.uleb(), typeMap))
                    if (op == 0x04) out.uleb(mapPlusOne(r.uleb(), strMap))
                }
                0x05, 0x06 -> out.uleb(r.uleb()) // end local, restart local
                0x09 -> out.uleb(mapPlusOne(r.uleb(), strMap)) // set file
            }
        }
    }

    /** Debug info stores indices as `index + 1`, with 0 meaning none. */
    private fun mapPlusOne(value: Int, map: IntArray): Int = if (value == 0) 0 else map[value - 1] + 1

    private fun emitCode(old: Int) {
        out.align(4)
        newOff[old] = out.size
        val r = Reader(d, old)
        out.u2(r.u2()) // registers
        out.u2(r.u2()) // ins
        out.u2(r.u2()) // outs
        val tries = r.u2()
        out.u2(tries)
        out.u4(offsetOf(r.u4())) // debug info
        val units = r.u4()
        out.u4(units)

        val start = out.size
        out.bytes(d, r.pos, units * 2)
        r.pos += units * 2
        patchInstructions(start, units)

        if (tries == 0) return

        if ((units and 1) != 0) {
            out.u2(0)
            r.pos += 2
        }
        val triesAt = out.size
        out.bytes(d, r.pos, tries * 8)
        r.pos += tries * 8

        // Catch types are variable-length, so handlers may move and the tries have to follow them.
        val listOld = r.pos
        val listNew = out.size
        val handlers = r.uleb()
        out.uleb(handlers)
        val handlerOffsets = HashMap<Int, Int>()
        repeat(handlers) {
            handlerOffsets[r.pos - listOld] = out.size - listNew
            val size = r.sleb()
            out.sleb(size)
            repeat(if (size < 0) -size else size) {
                out.uleb(typeMap[r.uleb()])
                out.uleb(r.uleb())
            }
            if (size <= 0) out.uleb(r.uleb()) // catch-all
        }
        for (n in 0 until tries) {
            val at = triesAt + n * 8 + 6
            out.buf.put2(at, handlerOffsets.getValue(out.buf.u2(at)))
        }
    }

    /** Rewrites the index operands of the instructions in place. They are fixed-width, so nothing moves. */
    private fun patchInstructions(start: Int, units: Int) {
        val b = out.buf
        var pc = 0
        while (pc < units) {
            val at = start + pc * 2
            val op = b.u1(at)
            val ident = b.u1(at + 1)

            if (op == 0x00 && ident != 0) { // payload pseudo-instructions
                pc += when (ident) {
                    0x01 -> 4 + b.u2(at + 2) * 2 // packed-switch
                    0x02 -> 2 + b.u2(at + 2) * 4 // sparse-switch
                    0x03 -> 4 + ((b.u4(at + 4) * b.u2(at + 2) + 1) ushr 1) // fill-array-data
                    else -> 1
                }
                continue
            }

            when (op) {
                0x1A -> {
                    val index = strMap[b.u2(at + 2)]
                    check(index <= 0xFFFF) { "const-string index doesn't fit after relocating strings" }
                    b.put2(at + 2, index)
                }
                0x1B -> b.put4(at + 2, strMap[b.u4(at + 2)])
                0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25 -> b.put2(at + 2, typeMap[b.u2(at + 2)])
                in 0x52..0x6D -> b.put2(at + 2, fieldMap[b.u2(at + 2)])
                in 0x6E..0x72, in 0x74..0x78 -> b.put2(at + 2, methodMap[b.u2(at + 2)])
                0xFA, 0xFB -> { // invoke-polymorphic
                    b.put2(at + 2, methodMap[b.u2(at + 2)])
                    b.put2(at + 6, protoMap[b.u2(at + 6)])
                }
                0xFC, 0xFD, 0xFE -> throw IllegalArgumentException("Unsupported opcode 0x${op.toString(16)}")
                0xFF -> b.put2(at + 2, protoMap[b.u2(at + 2)]) // const-method-type
            }
            pc += width(op)
        }
    }

    /** Size in 16-bit code units. */
    private fun width(op: Int): Int = when (op) {
        0x18 -> 5
        0xFA, 0xFB -> 4
        0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C, 0xFC, 0xFD -> 3
        in 0x6E..0x72, in 0x74..0x78 -> 3
        0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20, 0x22, 0x23, 0x29, 0xFE, 0xFF -> 2
        in 0x2D..0x3D, in 0x44..0x6D, in 0x90..0xAF, in 0xD0..0xE2 -> 2
        else -> 1
    }

    /** Fields and methods of a class are listed in index order, stored as differences. */
    private fun emitClassData(old: Int) {
        newOff[old] = out.size
        val r = Reader(d, old)
        val staticFields = r.uleb()
        val instanceFields = r.uleb()
        val directMethods = r.uleb()
        val virtualMethods = r.uleb()
        out.uleb(staticFields)
        out.uleb(instanceFields)
        out.uleb(directMethods)
        out.uleb(virtualMethods)
        copyFields(r, staticFields)
        copyFields(r, instanceFields)
        copyMethods(r, directMethods)
        copyMethods(r, virtualMethods)
    }

    private fun copyFields(r: Reader, count: Int) {
        val keys = LongArray(count)
        val flags = IntArray(count)
        var index = 0
        for (n in 0 until count) {
            index += r.uleb()
            keys[n] = (fieldMap[index].toLong() shl 32) or n.toLong()
            flags[n] = r.uleb()
        }
        keys.sort()
        var previous = 0
        for (key in keys) {
            val current = (key ushr 32).toInt()
            out.uleb(current - previous)
            out.uleb(flags[(key and 0xFFFFFFFFL).toInt()])
            previous = current
        }
    }

    private fun copyMethods(r: Reader, count: Int) {
        val keys = LongArray(count)
        val flags = IntArray(count)
        val code = IntArray(count)
        var index = 0
        for (n in 0 until count) {
            index += r.uleb()
            keys[n] = (methodMap[index].toLong() shl 32) or n.toLong()
            flags[n] = r.uleb()
            code[n] = offsetOf(r.uleb())
        }
        keys.sort()
        var previous = 0
        for (key in keys) {
            val current = (key ushr 32).toInt()
            val n = (key and 0xFFFFFFFFL).toInt()
            out.uleb(current - previous)
            out.uleb(flags[n])
            out.uleb(code[n])
            previous = current
        }
    }

    // Encoded values

    /**
     * Element names are never type descriptors, so their order survives the renumbering and stays sorted.
     * Returns the new type index of the annotation.
     */
    private fun copyAnnotation(r: Reader): Int {
        val type = typeMap[r.uleb()]
        out.uleb(type)
        val size = r.uleb()
        out.uleb(size)
        repeat(size) {
            out.uleb(strMap[r.uleb()])
            copyValue(r)
        }
        return type
    }

    private fun copyValue(r: Reader) {
        val header = r.u1()
        val arg = header ushr 5
        when (header and 0x1F) {
            0x17 -> emitIndexValue(0x17, strMap[readIndex(r, arg)])
            0x18 -> emitIndexValue(0x18, typeMap[readIndex(r, arg)])
            0x19 -> emitIndexValue(0x19, fieldMap[readIndex(r, arg)])
            0x1A -> emitIndexValue(0x1A, methodMap[readIndex(r, arg)])
            0x1B -> emitIndexValue(0x1B, fieldMap[readIndex(r, arg)]) // enum
            0x1C -> {
                out.u1(header)
                val size = r.uleb()
                out.uleb(size)
                repeat(size) { copyValue(r) }
            }
            0x1D -> {
                out.u1(header)
                copyAnnotation(r)
            }
            0x1E, 0x1F -> out.u1(header) // null, boolean
            else -> { // numbers
                out.u1(header)
                out.bytes(r.bytes, r.pos, arg + 1)
                r.pos += arg + 1
            }
        }
    }

    private fun readIndex(r: Reader, arg: Int): Int {
        var value = 0
        for (n in 0..arg) value = value or (r.u1() shl (n * 8))
        return value
    }

    private fun emitIndexValue(type: Int, index: Int) {
        val size = when {
            (index ushr 8) == 0 -> 1
            (index ushr 16) == 0 -> 2
            (index ushr 24) == 0 -> 3
            else -> 4
        }
        out.u1(((size - 1) shl 5) or type)
        for (n in 0 until size) out.u1(index ushr (n * 8))
    }
}
