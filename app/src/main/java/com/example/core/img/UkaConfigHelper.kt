package com.example.core.img

import java.io.File

/**
 * Helper inspired by `blackeangel/UKA` (Unpacker Kitchen for Android):
 * Synchronizes partition metadata between:
 * - `config/<partition>_fs_config` (UKA format: `<partition>/<relPath> <uid> <gid> <mode> capabilities=0x0 [symlink]`)
 * - `config/<partition>_file_contexts` (UKA format: `/<partition>/<relPath> u:object_r:...:s0`)
 * - `config/<partition>_size.txt` & `config/<partition>_info.txt`
 * - `ROM_FORGE_META/extracted_fs_config.txt`, `extracted_file_contexts.txt`, `extracted_symlinks.txt`
 * - `etc/fs_config` & `etc/selinux/plat_file_contexts`
 */
object UkaConfigHelper {

    fun writeUkaAndRomForgeConfigs(
        outputDir: File,
        partitionName: String,
        filesystemType: String,
        blockSize: Int,
        totalSizeBytes: Long,
        fsConfigLines: List<String>,
        fileContextsLines: List<String>,
        symlinksLines: List<String>
    ) {
        val cleanPart = partitionName.trim().lowercase().ifEmpty { "system" }

        // 1. UKA standard `config/` directory inside the unpacked folder (and parent UNPACK/config if needed)
        val ukaConfigDir = File(outputDir, "config").apply { mkdirs() }
        val metaDir = File(outputDir, "ROM_FORGE_META").apply { mkdirs() }

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
                val relWithoutPart = if (rawPath == cleanPart) "" else rawPath.removePrefix("$cleanPart/")
                val uid = parts[1]
                val gid = parts[2]
                val mode = parts[3]
                val extra = if (parts.size > 4) parts.drop(4).joinToString(" ") else "capabilities=0x0"

                if (relWithoutPart.isEmpty() || relWithoutPart == "/") {
                    romForgeFsLines.add("/ $uid $gid $mode")
                } else {
                    romForgeFsLines.add("$relWithoutPart $uid $gid $mode")
                    ukaFsLines.add("$cleanPart/$relWithoutPart $uid $gid $mode $extra")
                }
            }
        }

        val ukaFcLines = mutableListOf<String>()
        val romForgeFcLines = mutableListOf<String>()
        ukaFcLines.add("/ u:object_r:rootfs:s0")
        ukaFcLines.add("/$cleanPart(/.*)? u:object_r:${cleanPart}_file:s0")

        for (rawLine in fileContextsLines) {
            val trimmed = rawLine.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size >= 2) {
                val rawPath = parts[0].removePrefix("/")
                val ctx = parts.last()
                val relWithoutPart = if (rawPath == cleanPart) "" else rawPath.removePrefix("$cleanPart/")
                if (relWithoutPart.isEmpty()) {
                    romForgeFcLines.add("/ $ctx")
                } else {
                    romForgeFcLines.add("/$relWithoutPart $ctx")
                    val escaped = escapeFileContextPath("/$cleanPart/$relWithoutPart")
                    ukaFcLines.add("$escaped $ctx")
                }
            }
        }

        File(ukaConfigDir, "${cleanPart}_fs_config").writeText(ukaFsLines.distinct().joinToString("\n") + "\n")
        File(ukaConfigDir, "${cleanPart}_file_contexts").writeText(ukaFcLines.distinct().joinToString("\n") + "\n")
        File(ukaConfigDir, "${cleanPart}_size.txt").writeText("${totalSizeBytes.coerceAtLeast(64 * 1024 * 1024L)}\n")
        File(ukaConfigDir, "${cleanPart}_info.txt").writeText(
            buildString {
                appendLine("IMAGE_NAME=$cleanPart.img")
                appendLine("PARTITION_NAME=$cleanPart")
                appendLine("FILESYSTEM_TYPE=$filesystemType")
                appendLine("BLOCK_SIZE=$blockSize")
                appendLine("ORIGINAL_SIZE_BYTES=$totalSizeBytes")
                appendLine("EXTRACTED_FILES=${romForgeFsLines.size}")
                appendLine("EXTRACTED_SYMLINKS=${symlinksLines.size}")
                appendLine("UKA_ENGINE=ROM_FORGE_UKA_V2")
            }
        )

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
                ?.filter { it.name != "ROM_FORGE_META" && it.name != "config" && it.name != "lost+found" }
                ?.map { if (it.isDirectory) "${it.name}/" else it.name }
                ?.sorted()
                .orEmpty()
            val isSar = File(outputDir, "system/build.prop").exists() ||
                    (File(outputDir, "system/bin").isDirectory && File(outputDir, "system/etc").isDirectory)
            val archLayout = if (isSar) "SAR_SYSTEM_AS_ROOT" else "FLAT_PARTITION"
            val mountPoint = if (isSar) "/" else "/$cleanPart"

            baseSnapshotFile.writeText(
                buildString {
                    appendLine("# R.E.C.O.R.E IMMUTABLE BASE IMAGE SNAPSHOT (CAPTURED AT UNPACK)")
                    appendLine("META|PARTITION_NAME=$cleanPart")
                    appendLine("META|FILESYSTEM_TYPE=$filesystemType")
                    appendLine("META|BLOCK_SIZE=$blockSize")
                    appendLine("META|ORIGINAL_SIZE_BYTES=$totalSizeBytes")
                    appendLine("META|ARCH_LAYOUT=$archLayout")
                    appendLine("META|MOUNT_POINT=$mountPoint")
                    appendLine("META|TOP_LEVEL_ENTRIES=${topEntries.joinToString(",")}")
                    outputDir.walkTopDown()
                        .filter {
                            it != outputDir &&
                                    !it.invariantSeparatorsPath.contains("/ROM_FORGE_META") &&
                                    !it.invariantSeparatorsPath.contains("/config") &&
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
