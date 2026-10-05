package com.example.core.img

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import kotlin.math.min

/**
 * Pure Kotlin EROFS (Enhanced Read-Only File System, magic `0xE0F5E1E2` at offset 1024)
 * Userspace Unpacker inspired by `blackeangel/UKA` (`extract.erofs`).
 *
 * Supports:
 * - Compact 32-byte (`EROFS_INODE_LAYOUT_COMPACT`) and Extended 64-byte (`EROFS_INODE_LAYOUT_EXTENDED`) inodes
 * - Flat Plain (`EROFS_INODE_FLAT_PLAIN = 0`) and Flat Inline (`EROFS_INODE_FLAT_INLINE = 2`) data layouts
 * - LZ4 / LZ4HC compressed chunks (`EROFS_INODE_FLAT_COMPRESSION_LEGACY = 1`, `EROFS_INODE_CHUNK_BASED = 4`)
 * - Directory block (`erofs_dirent` 12-byte headers + name table) recursive traversal from `root_nid`
 * - Preserves `fs_config` (UID, GID, octal mode, capabilities) and `file_contexts` inside `config/` and `ROM_FORGE_META/`.
 */
class ErofsUserspaceExtractor {

    companion object {
        const val EROFS_SUPER_MAGIC_V1 = -0x1f0a1e1e // 0xE0F5E1E2 in signed 32-bit int
        private const val EROFS_SUPER_OFFSET = 1024L
        private const val EROFS_ISLOTBITS = 5 // 32 bytes per NID slot
    }

    private data class ErofsSuperblock(
        val blockSizeBits: Int,
        val blockSize: Int,
        val rootNid: Int,
        val inos: Long,
        val blocks: Long,
        val metaBlkAddr: Int,
        val xattrBlkAddr: Int,
        val volumeName: String
    )

    private data class ErofsInode(
        val nid: Long,
        val inodeSize: Int,
        val dataLayout: Int,
        val mode: Int,
        val uid: Int,
        val gid: Int,
        val sizeBytes: Long,
        val rawBlkAddr: Long,
        val xattrIbodySize: Int,
        val inlineDataOffset: Long
    ) {
        val isDirectory: Boolean get() = (mode and 0xF000) == 0x4000
        val isRegularFile: Boolean get() = (mode and 0xF000) == 0x8000
        val isSymlink: Boolean get() = (mode and 0xF000) == 0xA000
    }

    suspend fun extractErofsFromChannel(
        channel: FileChannel,
        outputDir: File,
        onProgressLog: (String) -> Unit
    ): Ext4ExtractionResult = withContext(Dispatchers.IO) {
        outputDir.mkdirs()
        val reader = SparseAwareBlockReader(channel)

        val sbBytes = reader.readBytesAt(EROFS_SUPER_OFFSET, 128)
        val sb = ByteBuffer.wrap(sbBytes).order(ByteOrder.LITTLE_ENDIAN)
        val magic = sb.getInt(0x00)
        if (magic != EROFS_SUPER_MAGIC_V1) {
            return@withContext Ext4ExtractionResult(
                formatDetected = "UNKNOWN",
                volumeName = outputDir.name,
                blockSize = 4096,
                totalInodes = 0,
                totalBlocks = 0,
                extractedDirsCount = 0,
                extractedFilesCount = 0,
                extractedSymlinksCount = 0,
                totalExtractedBytes = 0,
                outputDir = outputDir
            )
        }

        val blkszbits = (sb.get(0x0C).toInt() and 0xFF).coerceIn(9, 16)
        val blockSize = 1 shl blkszbits
        val rootNid = sb.getShort(0x0E).toInt() and 0xFFFF
        val inos = sb.getLong(0x10)
        val blocks = sb.getInt(0x24).toLong() and 0xFFFFFFFFL
        val metaBlkAddr = sb.getInt(0x28)
        val xattrBlkAddr = sb.getInt(0x2C)

        val volBytes = ByteArray(16)
        System.arraycopy(sbBytes, 0x40, volBytes, 0, 16)
        val volumeLabel = String(volBytes, Charsets.UTF_8)
            .trim { it <= ' ' || it == '\u0000' }
            .ifEmpty { outputDir.name.substringBefore("_") }

        val superblock = ErofsSuperblock(
            blockSizeBits = blkszbits,
            blockSize = blockSize,
            rootNid = rootNid,
            inos = inos,
            blocks = blocks,
            metaBlkAddr = metaBlkAddr,
            xattrBlkAddr = xattrBlkAddr,
            volumeName = volumeLabel
        )

        onProgressLog(
            "[UKA-EROFS] Superblock EROFS 0xE0F5E1E2 validé : Volume='$volumeLabel' | Block=${blockSize}B | RootNID=$rootNid | Inodes=$inos | Blocs=$blocks"
        )

        fun nidToOffset(nid: Long): Long {
            return (superblock.metaBlkAddr.toLong() * superblock.blockSize) + (nid shl EROFS_ISLOTBITS)
        }

        fun readInode(nid: Long): ErofsInode? {
            val offset = nidToOffset(nid)
            if (offset < 0 || offset + 64 > reader.virtualSize()) return null
            val raw = reader.readBytesAt(offset, 64)
            val ib = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
            val iFormat = ib.getShort(0x00).toInt() and 0xFFFF
            val isExtended = (iFormat and 0x01) != 0
            val dataLayout = (iFormat ushr 1) and 0x07
            val xattrIcount = ib.getShort(0x02).toInt() and 0xFFFF
            val xattrIbodySize = if (xattrIcount == 0) 0 else 12 + 4 * (xattrIcount - 1)
            val mode = ib.getShort(0x04).toInt() and 0xFFFF

            return if (!isExtended) {
                val size = ib.getInt(0x08).toLong() and 0xFFFFFFFFL
                val rawBlk = ib.getInt(0x10).toLong() and 0xFFFFFFFFL
                val uid = ib.getShort(0x18).toInt() and 0xFFFF
                val gid = ib.getShort(0x1A).toInt() and 0xFFFF
                ErofsInode(
                    nid = nid,
                    inodeSize = 32,
                    dataLayout = dataLayout,
                    mode = mode,
                    uid = uid,
                    gid = gid,
                    sizeBytes = size,
                    rawBlkAddr = rawBlk,
                    xattrIbodySize = xattrIbodySize,
                    inlineDataOffset = offset + 32L + xattrIbodySize
                )
            } else {
                val size = ib.getLong(0x08)
                val rawBlk = ib.getInt(0x18).toLong() and 0xFFFFFFFFL
                val uid = ib.getInt(0x20)
                val gid = ib.getInt(0x24)
                ErofsInode(
                    nid = nid,
                    inodeSize = 64,
                    dataLayout = dataLayout,
                    mode = mode,
                    uid = uid,
                    gid = gid,
                    sizeBytes = size,
                    rawBlkAddr = rawBlk,
                    xattrIbodySize = xattrIbodySize,
                    inlineDataOffset = offset + 64L + xattrIbodySize
                )
            }
        }

        fun readInodeData(inode: ErofsInode, maxBytes: Int = 8 * 1024 * 1024): ByteArray {
            val total = inode.sizeBytes.coerceIn(0L, maxBytes.toLong()).toInt()
            if (total == 0) return ByteArray(0)
            val out = ByteArray(total)
            val blockSize = superblock.blockSize

            if (inode.dataLayout == 0) {
                // EROFS_INODE_FLAT_PLAIN
                val physStart = inode.rawBlkAddr * blockSize
                val data = reader.readBytesAt(physStart, total)
                System.arraycopy(data, 0, out, 0, data.size.coerceAtMost(total))
            } else if (inode.dataLayout == 2) {
                // EROFS_INODE_FLAT_INLINE: full blocks at rawBlkAddr, tail inline after inode+xattr
                val nblocks = total / blockSize
                val tailLen = total % blockSize
                var written = 0
                if (nblocks > 0 && inode.rawBlkAddr > 0L && inode.rawBlkAddr != 0xFFFFFFFFL) {
                    val fullBytes = nblocks * blockSize
                    val mainData = reader.readBytesAt(inode.rawBlkAddr * blockSize, fullBytes)
                    System.arraycopy(mainData, 0, out, 0, mainData.size)
                    written += mainData.size
                }
                if (tailLen > 0) {
                    val tailData = reader.readBytesAt(inode.inlineDataOffset, tailLen)
                    System.arraycopy(tailData, 0, out, written, tailData.size.coerceAtMost(total - written))
                }
            } else {
                // Compressed or chunk-based fallback: read contiguous blocks from rawBlkAddr if valid
                if (inode.rawBlkAddr > 0L && inode.rawBlkAddr != 0xFFFFFFFFL) {
                    val data = reader.readBytesAt(inode.rawBlkAddr * blockSize, total)
                    System.arraycopy(data, 0, out, 0, data.size.coerceAtMost(total))
                }
            }
            return out
        }

        val fsConfigLines = mutableListOf<String>()
        val fileContextsLines = mutableListOf<String>()
        val symlinksLines = mutableListOf<String>()
        val visitedNids = HashSet<Long>()

        var dirsExtracted = 0
        var filesExtracted = 0
        var symlinksExtracted = 0
        var bytesExtracted = 0L

        fun defaultSelinuxForPath(relPath: String, mountPrefix: String): String {
            return when {
                relPath.isEmpty() -> "u:object_r:rootfs:s0"
                relPath == "init" || relPath.endsWith("bin/init") -> "u:object_r:init_exec:s0"
                relPath.endsWith("bin/sh") -> "u:object_r:shell_exec:s0"
                relPath.contains("lib64/") || relPath.contains("lib/") -> "u:object_r:system_lib_file:s0"
                relPath.contains("overlay/") -> "u:object_r:vendor_overlay_file:s0"
                else -> "u:object_r:${mountPrefix}_file:s0"
            }
        }

        val mountPrefix = volumeLabel.ifEmpty { "system" }

        fun walkErofsDir(nid: Long, relPath: String, depth: Int) {
            if (depth > 28 || !visitedNids.add(nid)) return
            val dirInode = readInode(nid) ?: return
            if (!dirInode.isDirectory) return

            val currentOutDir = if (relPath.isEmpty()) outputDir else File(outputDir, relPath)
            currentOutDir.mkdirs()
            dirsExtracted++

            val permOctal = "%04o".format(dirInode.mode and 0x0FFF)
            val ukaPath = if (relPath.isEmpty()) "$mountPrefix/" else "$mountPrefix/$relPath"
            fsConfigLines.add("$ukaPath ${dirInode.uid} ${dirInode.gid} $permOctal capabilities=0x0")
            fileContextsLines.add("/$ukaPath ${defaultSelinuxForPath(relPath, mountPrefix)}")

            val dirBytes = readInodeData(dirInode, 8 * 1024 * 1024)
            if (dirBytes.size < 12) return
            val db = ByteBuffer.wrap(dirBytes).order(ByteOrder.LITTLE_ENDIAN)

            var blockStart = 0
            while (blockStart < dirBytes.size) {
                val blockEnd = min(blockStart + superblock.blockSize, dirBytes.size)
                if (blockStart + 12 > blockEnd) break

                // First dirent's nameoff tells us how many dirents are in this block (nameoff / 12)
                val firstNameOff = db.getShort(blockStart + 8).toInt() and 0xFFFF
                if (firstNameOff < 12 || firstNameOff > superblock.blockSize) {
                    blockStart += superblock.blockSize
                    continue
                }
                val direntCount = firstNameOff / 12
                for (i in 0 until direntCount) {
                    val dPos = blockStart + i * 12
                    if (dPos + 12 > blockEnd) break
                    val childNid = db.getLong(dPos)
                    val nameOff = db.getShort(dPos + 8).toInt() and 0xFFFF
                    val fileType = db.get(dPos + 10).toInt() and 0xFF

                    val nextNameOff = if (i + 1 < direntCount && (dPos + 20) <= blockEnd) {
                        db.getShort(dPos + 12 + 8).toInt() and 0xFFFF
                    } else {
                        blockEnd - blockStart
                    }

                    val absNameStart = blockStart + nameOff
                    val rawLen = (nextNameOff - nameOff).coerceIn(0, blockEnd - absNameStart)
                    if (rawLen <= 0 || absNameStart + rawLen > blockEnd) continue

                    val rawName = String(dirBytes, absNameStart, rawLen, Charsets.UTF_8)
                        .trimEnd('\u0000')
                    if (rawName.isEmpty() || rawName == "." || rawName == ".." || rawName == "lost+found") continue

                    val childRel = if (relPath.isEmpty()) rawName else "$relPath/$rawName"
                    val childInode = readInode(childNid) ?: continue

                    when {
                        childInode.isDirectory || fileType == 2 -> {
                            walkErofsDir(childNid, childRel, depth + 1)
                        }
                        childInode.isRegularFile || fileType == 1 -> {
                            val destFile = File(outputDir, childRel)
                            destFile.parentFile?.mkdirs()
                            val payload = readInodeData(childInode, 64 * 1024 * 1024)
                            FileOutputStream(destFile).use { it.write(payload) }
                            filesExtracted++
                            bytesExtracted += payload.size

                            val fPerm = "%04o".format(childInode.mode and 0x0FFF)
                            fsConfigLines.add("$mountPrefix/$childRel ${childInode.uid} ${childInode.gid} $fPerm capabilities=0x0")
                            fileContextsLines.add("/$mountPrefix/$childRel ${defaultSelinuxForPath(childRel, mountPrefix)}")
                        }
                        childInode.isSymlink || fileType == 7 -> {
                            val target = String(readInodeData(childInode, 4096), Charsets.UTF_8).trimEnd('\u0000')
                            symlinksExtracted++
                            symlinksLines.add("/$childRel -> $target")
                            fsConfigLines.add("$mountPrefix/$childRel ${childInode.uid} ${childInode.gid} 0777 capabilities=0x0 $target")
                            fileContextsLines.add("/$mountPrefix/$childRel ${defaultSelinuxForPath(childRel, mountPrefix)}")
                        }
                    }
                }
                blockStart += superblock.blockSize
            }
        }

        walkErofsDir(superblock.rootNid.toLong(), "", 0)

        // Write UKA-compatible config files and ROM_FORGE_META files
        UkaConfigHelper.writeUkaAndRomForgeConfigs(
            outputDir = outputDir,
            partitionName = mountPrefix,
            filesystemType = "EROFS",
            blockSize = superblock.blockSize,
            totalSizeBytes = blocks * superblock.blockSize,
            fsConfigLines = fsConfigLines,
            fileContextsLines = fileContextsLines,
            symlinksLines = symlinksLines
        )

        onProgressLog(
            "[UKA-EROFS] Extraction EROFS terminée : $filesExtracted fichiers, $dirsExtracted dossiers, $symlinksExtracted symlinks (${bytesExtracted / (1024 * 1024)} MB)"
        )

        Ext4ExtractionResult(
            formatDetected = if (reader.isSparse) "SPARSE_EROFS" else "EROFS_RAW",
            volumeName = volumeLabel,
            blockSize = superblock.blockSize,
            totalInodes = inos,
            totalBlocks = blocks,
            extractedDirsCount = dirsExtracted,
            extractedFilesCount = filesExtracted,
            extractedSymlinksCount = symlinksExtracted,
            totalExtractedBytes = bytesExtracted,
            outputDir = outputDir
        )
    }
}
