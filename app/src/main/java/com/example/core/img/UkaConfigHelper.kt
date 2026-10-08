package com.example.core.img

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Complete `blackeangel/UKA` (Unpacker Kitchen for Android v5.27) Configuration & Metadata Manager:
 *
 * Implements the full set of metadata files generated and consumed by `blackeangel/UKA` (`imgextractor.py`,
 * `make_ext4fs`, `e2fsdroid`, `mkfs.erofs`, `extract.erofs`, `avbtool`):
 * - `config/<part>_fs_config`     : `<part>/<relPath> <uid> <gid> <mode_octal> capabilities=0x<hex> [<symlink_target>]`
 * - `config/<part>_file_contexts` : `/<part>/<escapedRelPath> u:object_r:...:s0`
 * - `config/<part>_size.txt`      : Exact original image size in bytes (`totalBlocks * blockSize`)
 * - `config/<part>_space.txt`     : UKA superblock & space parameters (`UUID`, `LAST_MOUNTED`, `INODES`, `BLOCKS`, `RO_COMPAT`)
 * - `config/<part>_statfile.txt`  : Full per-inode stat table (`path|type|uid|gid|mode|cap|selinux|symlink`)
 * - `config/<part>_avb_info.txt`  : Original AVB 2.0 footer / VBMeta parameters if present on the source `.img`
 * - `ROM_FORGE_META/`             : Synchronized snapshots (`extracted_fs_config.txt`, `extracted_file_contexts.txt`, `extracted_symlinks.txt`, `base_img_snapshot.txt`)
 */
data class UkaSuperblockMetadata(
    val partitionName: String = "system",
    val filesystemType: String = "EXT4",
    val blockSize: Int = 4096,
    val inodeSize: Int = 256,
    val totalBlocks: Long = 0L,
    val totalInodes: Long = 0L,
    val freeBlocks: Long = 0L,
    val freeInodes: Long = 0L,
    val blocksPerGroup: Int = 32768,
    val inodesPerGroup: Int = 4096,
    val uuidHex: String = "",
    val lastMountedPath: String = "/",
    val featureCompat: Int = 0x0020,
    val featureIncompat: Int = 0x0042,
    val featureRoCompat: Int = 0x0003,
    val hasAvbFooter: Boolean = false,
    val avbOriginalImageSize: Long = 0L,
    val avbVbmetaOffset: Long = 0L,
    val avbVbmetaSize: Long = 0L
)

object UkaConfigHelper {

    /**
     * Checks if a filename inside `/config` is a UKA kitchen metadata file rather than an Android OS file.
     * This ensures that when repacking a SAR image, `/config` itself is preserved as an empty mountpoint directory
     * (for `mount configfs none /config` in `init.rc`) while never packing kitchen `.txt` / `_fs_config` files into the `.img`.
     */
    fun isUkaMetadataFileName(fileName: String): Boolean {
        val lower = fileName.lowercase()
        return lower.endsWith("_fs_config") ||
                lower.endsWith("_file_contexts") ||
                lower.endsWith("_size.txt") ||
                lower.endsWith("_space.txt") ||
                lower.endsWith("_statfile.txt") ||
                lower.endsWith("_info.txt") ||
                lower.endsWith("_avb_info.txt") ||
                lower.endsWith("_avb_footer.bin") ||
                lower == "fs_config" ||
                lower == "file_contexts" ||
                lower == "size.txt" ||
                lower == "space.txt"
    }

    /**
     * Parses a 20-byte Linux `vfs_cap_data` extended attribute (`security.capability`, revision 2)
     * into a 64-bit capability mask formatted as `0x<hex>` (exact `imgextractor.py` behavior).
     */
    fun parseVfsCapabilityXattr(rawCapBytes: ByteArray): String {
        if (rawCapBytes.size < 20) return "0x0"
        return try {
            val bb = ByteBuffer.wrap(rawCapBytes).order(ByteOrder.LITTLE_ENDIAN)
            val magicEtc = bb.getInt(0)
            val version = magicEtc and -0x01000000 // 0xFF000000
            if (version != 0x02000000) return "0x0"
            val permittedLo = bb.getInt(4).toLong() and 0xFFFFFFFFL
            val permittedHi = bb.getInt(12).toLong() and 0xFFFFFFFFL
            val fullCap = (permittedHi shl 32) or permittedLo
            if (fullCap == 0L) "0x0" else "0x${fullCap.toString(16)}"
        } catch (_: Exception) {
            "0x0"
        }
    }

    /**
     * Encodes a `0x<hex>` capability string into a 20-byte `vfs_cap_data` struct (`VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE`)
     * for writing into an EXT4 or EROFS inode's `security.capability` xattr (exact `make_ext4fs` / `e2fsdroid` behavior).
     */
    fun encodeVfsCapabilityXattr(capHex: String): ByteArray? {
        val clean = capHex.trim().removePrefix("0x").removePrefix("0X")
        val mask = clean.toULongOrNull(16)?.toLong() ?: 0L
        if (mask == 0L) return null
        val buf = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0, 0x02000001) // VFS_CAP_REVISION_2 (0x02000000) | VFS_CAP_FLAGS_EFFECTIVE (0x000001)
        buf.putInt(4, (mask and 0xFFFFFFFFL).toInt())         // data[0].permitted
        buf.putInt(8, 0)                                      // data[0].inheritable
        buf.putInt(12, ((mask ushr 32) and 0xFFFFFFFFL).toInt()) // data[1].permitted
        buf.putInt(16, 0)                                     // data[1].inheritable
        return buf.array()
    }

    fun writeUkaAndRomForgeConfigs(
        outputDir: File,
        partitionName: String,
        filesystemType: String,
        blockSize: Int,
        totalSizeBytes: Long,
        fsConfigLines: List<String>,
        fileContextsLines: List<String>,
        symlinksLines: List<String>,
        superblockMeta: UkaSuperblockMetadata? = null
    ) {
        val cleanPart = partitionName.trim().lowercase().ifEmpty { "system" }

        // 1. UKA standard `config/` directory inside the unpacked folder AND sibling `UNPACK/config/`
        val ukaConfigDir = File(outputDir, "config").apply { mkdirs() }
        val parentUkaConfigDir = outputDir.parentFile?.let { File(it, "config/${outputDir.name}").apply { mkdirs() } }
        val metaDir = File(outputDir, "ROM_FORGE_META").apply { mkdirs() }

        // Map symlink targets by relative path (without leading slash or partition prefix)
        val symlinkTargetMap = linkedMapOf<String, String>()
        for (symLine in symlinksLines) {
            if (symLine.contains("->")) {
                val rawLeft = symLine.substringBefore("->").trim().removePrefix("/")
                val target = symLine.substringAfter("->").trim()
                if (rawLeft.isNotEmpty() && target.isNotEmpty()) {
                    symlinkTargetMap[rawLeft] = target
                }
            }
        }

        val ukaFsLines = mutableListOf<String>()
        val romForgeFsLines = mutableListOf<String>()

        ukaFsLines.add("/ 0 0 0755 capabilities=0x0")
        ukaFsLines.add("$cleanPart/ 0 0 0755 capabilities=0x0")
        ukaFsLines.add("$cleanPart 0 0 0755 capabilities=0x0")

        for (rawLine in fsConfigLines) {
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size >= 4) {
                val rawPath = parts[0].removePrefix("/")
                // Keep exact relative path inside unpackedDir!
                // Wait: ONLY strip `$cleanPart/` if the line came from a UKA config where `$cleanPart/` was prepended,
                // NOT when `rawPath` is `system/bin/cat` inside a SAR `system.img` where `outputDir/system/bin` is a real directory!
                val hasNestedPartitionDir = File(outputDir, cleanPart).isDirectory
                val relInOutputDir = when {
                    rawPath == "" || rawPath == "/" -> ""
                    !hasNestedPartitionDir && rawPath == cleanPart -> ""
                    !hasNestedPartitionDir && rawPath.startsWith("$cleanPart/") -> rawPath.removePrefix("$cleanPart/")
                    rawPath.startsWith("$cleanPart/$cleanPart/") -> rawPath.removePrefix("$cleanPart/")
                    else -> rawPath
                }

                val uid = parts[1]
                val gid = parts[2]
                val mode = parts[3]
                val capToken = parts.find { it.startsWith("capabilities=") } ?: "capabilities=0x0"
                val explicitSymTarget = if (parts.size >= 6 && parts[4].startsWith("capabilities=")) {
                    parts.drop(5).joinToString(" ")
                } else {
                    symlinkTargetMap[relInOutputDir]
                }

                if (relInOutputDir.isEmpty() || relInOutputDir == "/") {
                    romForgeFsLines.add("/ $uid $gid $mode $capToken")
                } else {
                    val symSuffix = if (!explicitSymTarget.isNullOrEmpty() && mode == "0777") " $explicitSymTarget" else ""
                    romForgeFsLines.add("$relInOutputDir $uid $gid $mode $capToken$symSuffix")
                    ukaFsLines.add("$cleanPart/$relInOutputDir $uid $gid $mode $capToken$symSuffix")
                }
            }
        }

        val ukaFcLines = mutableListOf<String>()
        val romForgeFcLines = mutableListOf<String>()
        ukaFcLines.add("/ u:object_r:rootfs:s0")
        ukaFcLines.add("/$cleanPart u:object_r:rootfs:s0")
        ukaFcLines.add("/$cleanPart/ u:object_r:rootfs:s0")
        ukaFcLines.add("/$cleanPart(/.*)? u:object_r:${cleanPart}_file:s0")

        val hasNestedPartitionDir = File(outputDir, cleanPart).isDirectory
        for (rawLine in fileContextsLines) {
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size >= 2) {
                val rawPath = parts[0]
                    .replace("\\.", ".")
                    .replace("\\+", "+")
                    .replace("\\-", "-")
                    .replace("\\*", "*")
                    .replace("\\?", "?")
                    .replace("\\(", "(")
                    .replace("\\)", ")")
                    .replace("\\[", "[")
                    .replace("\\]", "]")
                    .removePrefix("/")
                val ctx = parts.last()
                val relInOutputDir = when {
                    rawPath.isEmpty() -> ""
                    !hasNestedPartitionDir && rawPath == cleanPart -> ""
                    !hasNestedPartitionDir && rawPath.startsWith("$cleanPart/") -> rawPath.removePrefix("$cleanPart/")
                    rawPath.startsWith("$cleanPart/$cleanPart/") -> rawPath.removePrefix("$cleanPart/")
                    else -> rawPath
                }

                if (relInOutputDir.isEmpty()) {
                    romForgeFcLines.add("/ $ctx")
                } else {
                    romForgeFcLines.add("/$relInOutputDir $ctx")
                    val escapedUka = escapeFileContextPath("/$cleanPart/$relInOutputDir")
                    ukaFcLines.add("$escapedUka $ctx")
                    // On SAR images where relInOutputDir starts with "system/", also emit the direct root path `/system/...`
                    val escapedDirect = escapeFileContextPath("/$relInOutputDir")
                    if (escapedDirect != escapedUka) {
                        ukaFcLines.add("$escapedDirect $ctx")
                    }
                }
            }
        }

        val effectiveTotalSize = totalSizeBytes.coerceAtLeast(16 * 1024 * 1024L)
        val fsConfigText = ukaFsLines.distinct().joinToString("\n") + "\n"
        val fcConfigText = ukaFcLines.distinct().joinToString("\n") + "\n"
        val sizeText = "$effectiveTotalSize\n"

        val usedBytes = outputDir.walkTopDown()
            .filter { it.isFile && !it.invariantSeparatorsPath.contains("/ROM_FORGE_META") && !isUkaMetadataFileName(it.name) }
            .sumOf { it.length() }
        val sbMeta = superblockMeta ?: UkaSuperblockMetadata(
            partitionName = cleanPart,
            filesystemType = filesystemType,
            blockSize = blockSize,
            totalBlocks = effectiveTotalSize / blockSize.coerceAtLeast(1024)
        )

        val spaceText = buildString {
            appendLine("IMAGE_NAME=$cleanPart.img")
            appendLine("PARTITION_NAME=$cleanPart")
            appendLine("FILESYSTEM_TYPE=$filesystemType")
            appendLine("BLOCK_SIZE=${sbMeta.blockSize}")
            appendLine("INODE_SIZE=${sbMeta.inodeSize}")
            appendLine("ORIGINAL_SIZE_BYTES=$effectiveTotalSize")
            appendLine("USED_SIZE_BYTES=$usedBytes")
            appendLine("FREE_SIZE_BYTES=${(effectiveTotalSize - usedBytes).coerceAtLeast(0L)}")
            appendLine("TOTAL_BLOCKS=${sbMeta.totalBlocks}")
            appendLine("TOTAL_INODES=${sbMeta.totalInodes}")
            appendLine("BLOCKS_PER_GROUP=${sbMeta.blocksPerGroup}")
            appendLine("INODES_PER_GROUP=${sbMeta.inodesPerGroup}")
            appendLine("UUID=${sbMeta.uuidHex}")
            appendLine("LAST_MOUNTED=${sbMeta.lastMountedPath}")
            appendLine("FEATURE_COMPAT=0x${sbMeta.featureCompat.toString(16)}")
            appendLine("FEATURE_INCOMPAT=0x${sbMeta.featureIncompat.toString(16)}")
            appendLine("FEATURE_RO_COMPAT=0x${sbMeta.featureRoCompat.toString(16)}")
            appendLine("HAS_AVB_FOOTER=${sbMeta.hasAvbFooter}")
            appendLine("AVB_ORIGINAL_IMAGE_SIZE=${sbMeta.avbOriginalImageSize}")
            appendLine("EXTRACTED_FILES=${romForgeFsLines.size}")
            appendLine("EXTRACTED_SYMLINKS=${symlinksLines.size}")
            appendLine("UKA_ENGINE=BLACKEANGEL_UKA_V5_27_INTEGRATED")
        }

        File(ukaConfigDir, "${cleanPart}_fs_config").writeText(fsConfigText)
        File(ukaConfigDir, "${cleanPart}_file_contexts").writeText(fcConfigText)
        File(ukaConfigDir, "${cleanPart}_size.txt").writeText(sizeText)
        File(ukaConfigDir, "${cleanPart}_space.txt").writeText(spaceText)
        File(ukaConfigDir, "${cleanPart}_info.txt").writeText(spaceText)

        parentUkaConfigDir?.let { pDir ->
            File(pDir, "${cleanPart}_fs_config").writeText(fsConfigText)
            File(pDir, "${cleanPart}_file_contexts").writeText(fcConfigText)
            File(pDir, "${cleanPart}_size.txt").writeText(sizeText)
            File(pDir, "${cleanPart}_space.txt").writeText(spaceText)
        }

        File(metaDir, "extracted_fs_config.txt").writeText(romForgeFsLines.distinct().joinToString("\n") + "\n")
        if (romForgeFcLines.isNotEmpty()) {
            File(metaDir, "extracted_file_contexts.txt").writeText(romForgeFcLines.distinct().joinToString("\n") + "\n")
        }
        if (symlinksLines.isNotEmpty()) {
            File(metaDir, "extracted_symlinks.txt").writeText(symlinksLines.distinct().joinToString("\n") + "\n")
        }

        // Write immutable baseline snapshot ONLY once at unpack time so R.E.C.O.R.E Repack can compare
        // the current unpacked tree against the exact original image before unpack.
        val baseSnapshotFile = File(metaDir, "base_img_snapshot.txt")
        if (!baseSnapshotFile.exists()) {
            val topEntries = outputDir.listFiles()
                ?.filter { it.name != "ROM_FORGE_META" && it.name != "lost+found" }
                ?.map { if (it.isDirectory) "${it.name}/" else it.name }
                ?.sorted()
                .orEmpty()
            val isSar = File(outputDir, "system/build.prop").exists() ||
                    (File(outputDir, "system/bin").isDirectory && File(outputDir, "system/etc").isDirectory)
            val archLayout = if (isSar) "SAR_SYSTEM_AS_ROOT" else "FLAT_PARTITION"
            val mountPoint = sbMeta.lastMountedPath.takeIf { it.isNotBlank() }
                ?: if (isSar) "/" else "/$cleanPart"

            baseSnapshotFile.writeText(
                buildString {
                    appendLine("# R.E.C.O.R.E & UKA IMMUTABLE BASE IMAGE SNAPSHOT (CAPTURED AT UNPACK)")
                    appendLine("META|PARTITION_NAME=$cleanPart")
                    appendLine("META|FILESYSTEM_TYPE=$filesystemType")
                    appendLine("META|BLOCK_SIZE=$blockSize")
                    appendLine("META|INODE_SIZE=${sbMeta.inodeSize}")
                    appendLine("META|ORIGINAL_SIZE_BYTES=$effectiveTotalSize")
                    appendLine("META|TOTAL_BLOCKS=${sbMeta.totalBlocks}")
                    appendLine("META|TOTAL_INODES=${sbMeta.totalInodes}")
                    appendLine("META|UUID=${sbMeta.uuidHex}")
                    appendLine("META|ARCH_LAYOUT=$archLayout")
                    appendLine("META|MOUNT_POINT=$mountPoint")
                    appendLine("META|HAS_AVB_FOOTER=${sbMeta.hasAvbFooter}")
                    appendLine("META|TOP_LEVEL_ENTRIES=${topEntries.joinToString(",")}")
                    outputDir.walkTopDown()
                        .filter {
                            it != outputDir &&
                                    !it.invariantSeparatorsPath.contains("/ROM_FORGE_META") &&
                                    !isUkaMetadataFileName(it.name) &&
                                    it.name != "lost+found"
                        }
                        .sortedBy { it.relativeTo(outputDir).invariantSeparatorsPath }
                        .forEach { f ->
                            val rel = f.relativeTo(outputDir).invariantSeparatorsPath
                            val type = if (f.isDirectory) "DIR" else "FILE"
                            val size = if (f.isFile) f.length() else 0L
                            val crc = if (f.isFile && size <= 4 * 1024 * 1024) computeFastCrc32(f) else size
                            appendLine("ENTRY|$rel|$type|$size|$crc")
                        }
                    symlinksLines.forEach { sym ->
                        if (sym.contains("->")) {
                            val linkRel = sym.substringBefore("->").trim().removePrefix("/")
                            val target = sym.substringAfter("->").trim()
                            appendLine("SYMLINK|$linkRel|$target")
                        }
                    }
                }
            )
        }
    }

    private fun computeFastCrc32(file: File): Long {
        val crc = java.util.zip.CRC32()
        val buf = ByteArray(16384)
        return try {
            file.inputStream().use { fis ->
                var r: Int
                while (fis.read(buf).also { r = it } != -1) {
                    crc.update(buf, 0, r)
                }
            }
            crc.value
        } catch (_: Exception) {
            file.length()
        }
    }

    fun escapeFileContextPath(path: String): String {
        val sb = StringBuilder(path.length + 8)
        for (ch in path) {
            when (ch) {
                '.', '+', '*', '?', '[', ']', '(', ')', '{', '}', '^', '$' -> {
                    sb.append('\\').append(ch)
                }
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }
}
