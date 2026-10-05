package com.example.core.img

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import kotlin.math.min

data class Ext4ExtractionResult(
    val formatDetected: String,
    val volumeName: String,
    val blockSize: Int,
    val totalInodes: Long,
    val totalBlocks: Long,
    val extractedDirsCount: Int,
    val extractedFilesCount: Int,
    val extractedSymlinksCount: Int,
    val totalExtractedBytes: Long,
    val outputDir: File
)

private data class SparseSegment(
    val virtualStartOffset: Long,
    val byteLength: Long,
    val physicalFileOffset: Long, // -1L for zero/dont_care fill
    val fillValue: Int = 0
)

/**
 * Provides random-access reads over either a Raw image or an Android Sparse image (0xED26FF3A)
 * directly from a FileChannel without requiring a multi-gigabyte temporary unsparse file on disk.
 */
class SparseAwareBlockReader(private val channel: FileChannel) {
    val isSparse: Boolean
    private val segments = mutableListOf<SparseSegment>()
    private var totalVirtualSize: Long = 0L

    fun virtualSize(): Long = if (isSparse) totalVirtualSize else channel.size()

    init {
        val headerBuf = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN)
        channel.read(headerBuf, 0L)
        headerBuf.flip()
        val magic = headerBuf.int
        if (magic == -0x12d900c6) { // 0xED26FF3A in signed 32-bit int
            isSparse = true
            val major = headerBuf.short.toInt() and 0xFFFF
            val minor = headerBuf.short.toInt() and 0xFFFF
            val fileHdrSz = headerBuf.short.toInt() and 0xFFFF
            val chunkHdrSz = headerBuf.short.toInt() and 0xFFFF
            val blkSz = headerBuf.int.toLong() and 0xFFFFFFFFL
            val totalBlks = headerBuf.int.toLong() and 0xFFFFFFFFL
            val totalChunks = headerBuf.int.toLong() and 0xFFFFFFFFL

            var physPos = fileHdrSz.toLong()
            var virtPos = 0L
            val chunkBuf = ByteBuffer.allocate(chunkHdrSz.coerceAtLeast(12)).order(ByteOrder.LITTLE_ENDIAN)

            for (i in 0 until totalChunks) {
                if (physPos + chunkHdrSz > channel.size()) break
                chunkBuf.clear()
                channel.read(chunkBuf, physPos)
                chunkBuf.flip()
                val chunkType = chunkBuf.short.toInt() and 0xFFFF
                chunkBuf.short // reserved
                val chunkSzBlks = chunkBuf.int.toLong() and 0xFFFFFFFFL
                val totalSzBytes = chunkBuf.int.toLong() and 0xFFFFFFFFL
                val virtLen = chunkSzBlks * blkSz
                val dataOffset = physPos + chunkHdrSz

                when (chunkType) {
                    0xCAC1 -> { // CHUNK_TYPE_RAW
                        segments.add(
                            SparseSegment(
                                virtualStartOffset = virtPos,
                                byteLength = virtLen,
                                physicalFileOffset = dataOffset
                            )
                        )
                    }
                    0xCAC2 -> { // CHUNK_TYPE_FILL
                        val fillBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                        channel.read(fillBuf, dataOffset)
                        fillBuf.flip()
                        segments.add(
                            SparseSegment(
                                virtualStartOffset = virtPos,
                                byteLength = virtLen,
                                physicalFileOffset = -1L,
                                fillValue = fillBuf.int
                            )
                        )
                    }
                    else -> { // CHUNK_TYPE_DONT_CARE (0xCAC3) or CRC32 (0xCAC4)
                        segments.add(
                            SparseSegment(
                                virtualStartOffset = virtPos,
                                byteLength = virtLen,
                                physicalFileOffset = -1L,
                                fillValue = 0
                            )
                        )
                    }
                }
                virtPos += virtLen
                physPos += totalSzBytes
            }
            totalVirtualSize = virtPos
        } else {
            isSparse = false
            totalVirtualSize = channel.size()
        }
    }

    fun readBytesAt(virtualOffset: Long, length: Int): ByteArray {
        val out = ByteArray(length)
        if (!isSparse) {
            val buf = ByteBuffer.wrap(out)
            var totalRead = 0
            while (totalRead < length && (virtualOffset + totalRead) < channel.size()) {
                val r = channel.read(buf, virtualOffset + totalRead)
                if (r <= 0) break
                totalRead += r
            }
            return out
        }

        // Binary search in sparse segments
        var remaining = length
        var curVirt = virtualOffset
        var outPos = 0

        while (remaining > 0) {
            val seg = findSegment(curVirt) ?: break
            val offsetInSeg = curVirt - seg.virtualStartOffset
            val availInSeg = (seg.byteLength - offsetInSeg).coerceAtMost(remaining.toLong()).toInt()
            if (availInSeg <= 0) break

            if (seg.physicalFileOffset >= 0L) {
                val slice = ByteBuffer.wrap(out, outPos, availInSeg)
                channel.read(slice, seg.physicalFileOffset + offsetInSeg)
            }
            curVirt += availInSeg
            outPos += availInSeg
            remaining -= availInSeg
        }
        return out
    }

    private fun findSegment(virtOffset: Long): SparseSegment? {
        var low = 0
        var high = segments.lastIndex
        while (low <= high) {
            val mid = (low + high) ushr 1
            val s = segments[mid]
            if (virtOffset < s.virtualStartOffset) {
                high = mid - 1
            } else if (virtOffset >= s.virtualStartOffset + s.byteLength) {
                low = mid + 1
            } else {
                return s
            }
        }
        return null
    }
}

private data class Ext4ExtentRun(
    val logicalBlock: Long,
    val physicalBlock: Long,
    val blockCount: Int,
    val isUninitialized: Boolean
)

private data class ParsedInode(
    val inodeNumber: Long,
    val mode: Int,
    val uid: Int,
    val gid: Int,
    val sizeBytes: Long,
    val flags: Int,
    val rawBlockArea: ByteArray,
    val selinuxContext: String?
) {
    val isDirectory: Boolean get() = (mode and 0xF000) == 0x4000
    val isRegularFile: Boolean get() = (mode and 0xF000) == 0x8000
    val isSymlink: Boolean get() = (mode and 0xF000) == 0xA000
    val usesExtents: Boolean get() = (flags and 0x00080000) != 0
    val hasInlineData: Boolean get() = (flags and 0x10000000) != 0
}

/**
 * Full Userspace EXT4 (and Sparse-EXT4) Filesystem Unpacker for Android AOSP / GSI `.img` files.
 * Reads the EXT4 Superblock, 32/64-bit Block Group Descriptor Table, Inode Tables, Extent Trees (`0xF30A`),
 * HTree/Linear Directory entries (`ext4_dir_entry_2`), Symlinks, and SELinux Xattrs (`0xEA020000`),
 * writing the complete filesystem tree into `/storage/emulated/0/ROM_FORGE/decompiled_imgs/<name>/`.
 */
class Ext4UserspaceExtractor {

    companion object {
        private const val EXT4_SUPER_MAGIC = 0xEF53
        private const val EXT4_EXTENT_MAGIC = 0xF30A
        private const val EXT4_XATTR_MAGIC = -0x15fe0000 // 0xEA020000
    }

    suspend fun extractImageFromChannel(
        channel: FileChannel,
        outputDir: File,
        onProgressLog: (String) -> Unit
    ): Ext4ExtractionResult = withContext(Dispatchers.IO) {
        outputDir.mkdirs()
        val reader = SparseAwareBlockReader(channel)

        // Read Superblock at virtual offset 1024 (size 1024 bytes)
        val sbBytes = reader.readBytesAt(1024L, 1024)
        val sb = ByteBuffer.wrap(sbBytes).order(ByteOrder.LITTLE_ENDIAN)

        val inodesCount = sb.getInt(0x00).toLong() and 0xFFFFFFFFL
        val blocksCountLo = sb.getInt(0x04).toLong() and 0xFFFFFFFFL
        val logBlockSize = sb.getInt(0x18)
        val blockSize = 1024 shl logBlockSize
        val blocksPerGroup = sb.getInt(0x20).toLong() and 0xFFFFFFFFL
        val inodesPerGroup = sb.getInt(0x28).toLong() and 0xFFFFFFFFL
        val magic = sb.getShort(0x38).toInt() and 0xFFFF

        if (magic != EXT4_SUPER_MAGIC) {
            onProgressLog("[IMG-UNPACK] Image non-EXT4 détectée (Magic=0x${magic.toString(16)})")
            return@withContext Ext4ExtractionResult(
                formatDetected = if (reader.isSparse) "SPARSE_RAW" else "RAW_IMAGE",
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

        val inodeSize = (sb.getShort(0x58).toInt() and 0xFFFF).let { if (it == 0) 128 else it }
        val featureIncompat = sb.getInt(0x60)
        val is64Bit = (featureIncompat and 0x80) != 0
        val blocksCountHi = if (is64Bit) (sb.getInt(0x150).toLong() and 0xFFFFFFFFL) else 0L
        val totalBlocks = (blocksCountHi shl 32) or blocksCountLo

        val rawDescSize = sb.getShort(0xFE).toInt() and 0xFFFF
        val groupDescSize = if (is64Bit && rawDescSize >= 64) rawDescSize else 32

        val volumeNameBytes = ByteArray(16)
        System.arraycopy(sbBytes, 0x78, volumeNameBytes, 0, 16)
        val volumeLabel = String(volumeNameBytes, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }
            .ifEmpty { "system" }

        val formatName = if (reader.isSparse) "SPARSE_EXT4" else "EXT4_RAW"
        onProgressLog(
            "[EXT4-ENGINE] Superblock validé : Format=$formatName | Label='$volumeLabel' | Block=${blockSize}B | Inode=${inodeSize}B | Blocs=$totalBlocks | Inodes=$inodesCount"
        )

        val gdtBaseOffset = if (blockSize == 1024) 2048L else blockSize.toLong()
        val totalGroups = ((totalBlocks + blocksPerGroup - 1) / blocksPerGroup).toInt().coerceAtLeast(1)
        val gdtBytes = reader.readBytesAt(gdtBaseOffset, totalGroups * groupDescSize)
        val gdtBuf = ByteBuffer.wrap(gdtBytes).order(ByteOrder.LITTLE_ENDIAN)

        fun getInodeTableBlockForGroup(groupIdx: Int): Long {
            val base = groupIdx * groupDescSize
            if (base + 12 > gdtBytes.size) return 0L
            val lo = gdtBuf.getInt(base + 0x08).toLong() and 0xFFFFFFFFL
            val hi = if (groupDescSize >= 64 && base + 0x2C <= gdtBytes.size) {
                gdtBuf.getInt(base + 0x28).toLong() and 0xFFFFFFFFL
            } else 0L
            return (hi shl 32) or lo
        }

        fun readInode(inodeNum: Long): ParsedInode? {
            if (inodeNum < 1 || inodeNum > inodesCount) return null
            val groupIdx = ((inodeNum - 1) / inodesPerGroup).toInt()
            val indexInGroup = (inodeNum - 1) % inodesPerGroup
            val inodeTableBlock = getInodeTableBlockForGroup(groupIdx)
            if (inodeTableBlock <= 0L) return null

            val inodeByteOffset = inodeTableBlock * blockSize + indexInGroup * inodeSize
            val rawInode = reader.readBytesAt(inodeByteOffset, inodeSize)
            val ib = ByteBuffer.wrap(rawInode).order(ByteOrder.LITTLE_ENDIAN)

            val mode = ib.getShort(0x00).toInt() and 0xFFFF
            val uidLo = ib.getShort(0x02).toInt() and 0xFFFF
            val sizeLo = ib.getInt(0x04).toLong() and 0xFFFFFFFFL
            val gidLo = ib.getShort(0x18).toInt() and 0xFFFF
            val flags = ib.getInt(0x20)
            val sizeHi = if (inodeSize > 0x70) (ib.getInt(0x6C).toLong() and 0xFFFFFFFFL) else 0L
            val uidHi = if (inodeSize > 0x7C) (ib.getShort(0x78).toInt() and 0xFFFF) else 0
            val gidHi = if (inodeSize > 0x7E) (ib.getShort(0x7A).toInt() and 0xFFFF) else 0

            val fullSize = if ((mode and 0xF000) == 0x8000 || (mode and 0xF000) == 0x4000) {
                (sizeHi shl 32) or sizeLo
            } else {
                sizeLo
            }

            val blockArea = ByteArray(60)
            System.arraycopy(rawInode, 0x28, blockArea, 0, 60)

            // Parse inline or external SELinux xattr if present
            var selinuxCtx: String? = null
            if (inodeSize > 128) {
                val extraIsize = ib.getShort(0x80).toInt() and 0xFFFF
                val inlineXattrOffset = 128 + extraIsize
                if (inlineXattrOffset + 4 < inodeSize) {
                    val xattrMagic = ib.getInt(inlineXattrOffset)
                    if (xattrMagic == EXT4_XATTR_MAGIC) {
                        selinuxCtx = parseSelinuxFromXattrArea(
                            rawInode,
                            inlineXattrOffset + 4,
                            inlineXattrOffset + 4,
                            inodeSize - (inlineXattrOffset + 4)
                        )
                    }
                }
            }
            if (selinuxCtx == null) {
                val aclLo = ib.getInt(0x68).toLong() and 0xFFFFFFFFL
                val aclHi = if (inodeSize > 0x76) (ib.getShort(0x74).toLong() and 0xFFFFL) else 0L
                val xattrBlock = (aclHi shl 32) or aclLo
                if (xattrBlock > 0L) {
                    val xblk = reader.readBytesAt(xattrBlock * blockSize, blockSize)
                    val xb = ByteBuffer.wrap(xblk).order(ByteOrder.LITTLE_ENDIAN)
                    if (xb.getInt(0) == EXT4_XATTR_MAGIC) {
                        selinuxCtx = parseSelinuxFromXattrArea(xblk, 32, 0, blockSize)
                    }
                }
            }

            return ParsedInode(
                inodeNumber = inodeNum,
                mode = mode,
                uid = (uidHi shl 16) or uidLo,
                gid = (gidHi shl 16) or gidLo,
                sizeBytes = fullSize,
                flags = flags,
                rawBlockArea = blockArea,
                selinuxContext = selinuxCtx
            )
        }

        fun collectExtentRunsFromHeader(bufBytes: ByteArray): List<Ext4ExtentRun> {
            val runs = mutableListOf<Ext4ExtentRun>()
            val bb = ByteBuffer.wrap(bufBytes).order(ByteOrder.LITTLE_ENDIAN)
            if (bufBytes.size < 12) return runs
            val ehMagic = bb.getShort(0).toInt() and 0xFFFF
            if (ehMagic != EXT4_EXTENT_MAGIC) return runs
            val ehEntries = bb.getShort(2).toInt() and 0xFFFF
            val ehDepth = bb.getShort(6).toInt() and 0xFFFF

            if (ehDepth == 0) {
                for (i in 0 until ehEntries) {
                    val pos = 12 + i * 12
                    if (pos + 12 > bufBytes.size) break
                    val eeBlock = bb.getInt(pos).toLong() and 0xFFFFFFFFL
                    val rawLen = bb.getShort(pos + 4).toInt() and 0xFFFF
                    val startHi = bb.getShort(pos + 6).toLong() and 0xFFFFL
                    val startLo = bb.getInt(pos + 8).toLong() and 0xFFFFFFFFL
                    val physBlock = (startHi shl 32) or startLo
                    val uninit = rawLen > 32768
                    val actualLen = if (uninit) rawLen - 32768 else rawLen
                    if (actualLen > 0) {
                        runs.add(Ext4ExtentRun(eeBlock, physBlock, actualLen, uninit))
                    }
                }
            } else {
                for (i in 0 until ehEntries) {
                    val pos = 12 + i * 12
                    if (pos + 12 > bufBytes.size) break
                    val leafLo = bb.getInt(pos + 4).toLong() and 0xFFFFFFFFL
                    val leafHi = bb.getShort(pos + 8).toLong() and 0xFFFFL
                    val childBlock = (leafHi shl 32) or leafLo
                    if (childBlock > 0L) {
                        val childBytes = reader.readBytesAt(childBlock * blockSize, blockSize)
                        runs.addAll(collectExtentRunsFromHeader(childBytes))
                    }
                }
            }
            return runs
        }

        fun resolveDataRuns(inode: ParsedInode): List<Ext4ExtentRun> {
            if (inode.usesExtents) {
                return collectExtentRunsFromHeader(inode.rawBlockArea).sortedBy { it.logicalBlock }
            }
            // Direct blocks 0..11 + Single/Double Indirect blocks (12, 13) for non-extent inodes
            val bb = ByteBuffer.wrap(inode.rawBlockArea).order(ByteOrder.LITTLE_ENDIAN)
            val runs = mutableListOf<Ext4ExtentRun>()
            var logicalCursor = 0L

            for (i in 0 until 12) {
                val blk = bb.getInt(i * 4).toLong() and 0xFFFFFFFFL
                if (blk > 0L) {
                    runs.add(Ext4ExtentRun(logicalCursor, blk, 1, false))
                }
                logicalCursor++
            }

            val pointersPerBlock = blockSize / 4
            // Single indirect block (index 12)
            val singleIndBlk = bb.getInt(12 * 4).toLong() and 0xFFFFFFFFL
            if (singleIndBlk > 0L) {
                val indBytes = reader.readBytesAt(singleIndBlk * blockSize, blockSize)
                val indBuf = ByteBuffer.wrap(indBytes).order(ByteOrder.LITTLE_ENDIAN)
                for (j in 0 until pointersPerBlock) {
                    val dataBlk = indBuf.getInt(j * 4).toLong() and 0xFFFFFFFFL
                    if (dataBlk > 0L) {
                        runs.add(Ext4ExtentRun(logicalCursor, dataBlk, 1, false))
                    }
                    logicalCursor++
                }
            }

            // Double indirect block (index 13)
            val doubleIndBlk = bb.getInt(13 * 4).toLong() and 0xFFFFFFFFL
            if (doubleIndBlk > 0L) {
                val dIndBytes = reader.readBytesAt(doubleIndBlk * blockSize, blockSize)
                val dIndBuf = ByteBuffer.wrap(dIndBytes).order(ByteOrder.LITTLE_ENDIAN)
                for (k in 0 until pointersPerBlock) {
                    val sBlk = dIndBuf.getInt(k * 4).toLong() and 0xFFFFFFFFL
                    if (sBlk > 0L) {
                        val sBytes = reader.readBytesAt(sBlk * blockSize, blockSize)
                        val sBuf = ByteBuffer.wrap(sBytes).order(ByteOrder.LITTLE_ENDIAN)
                        for (j in 0 until pointersPerBlock) {
                            val dataBlk = sBuf.getInt(j * 4).toLong() and 0xFFFFFFFFL
                            if (dataBlk > 0L) {
                                runs.add(Ext4ExtentRun(logicalCursor, dataBlk, 1, false))
                            }
                            logicalCursor++
                        }
                    } else {
                        logicalCursor += pointersPerBlock
                    }
                }
            }
            return runs
        }

        fun readInodePayloadToMemory(inode: ParsedInode, maxBytes: Int = 8 * 1024 * 1024): ByteArray {
            val targetSize = inode.sizeBytes.coerceAtMost(maxBytes.toLong()).toInt()
            if (targetSize <= 0) return ByteArray(0)
            if (inode.hasInlineData && targetSize <= 60) {
                return inode.rawBlockArea.copyOf(targetSize)
            }
            val out = ByteArray(targetSize)
            val runs = resolveDataRuns(inode)
            for (run in runs) {
                val logicalByteStart = run.logicalBlock * blockSize
                if (logicalByteStart >= targetSize) break
                val runByteLen = (run.blockCount.toLong() * blockSize)
                    .coerceAtMost(targetSize - logicalByteStart)
                    .toInt()
                if (runByteLen <= 0) continue
                if (!run.isUninitialized && run.physicalBlock > 0L) {
                    val data = reader.readBytesAt(run.physicalBlock * blockSize, runByteLen)
                    System.arraycopy(data, 0, out, logicalByteStart.toInt(), data.size)
                }
            }
            return out
        }

        fun extractRegularFileToDisk(inode: ParsedInode, destFile: File): Long {
            destFile.parentFile?.mkdirs()
            val totalSize = inode.sizeBytes
            if (totalSize <= 0L) {
                destFile.writeBytes(ByteArray(0))
                return 0L
            }
            if (inode.hasInlineData && totalSize <= 60L) {
                destFile.writeBytes(inode.rawBlockArea.copyOf(totalSize.toInt()))
                return totalSize
            }

            val runs = resolveDataRuns(inode)
            FileOutputStream(destFile).use { fos ->
                val outChannel = fos.channel
                val chunkLimit = 256 * 1024 // 256 KB streaming chunks
                var writtenUpTo = 0L

                for (run in runs) {
                    val runStartByte = run.logicalBlock * blockSize
                    if (runStartByte >= totalSize) break

                    // Fill any sparse hole between previous extent and this extent
                    if (runStartByte > writtenUpTo) {
                        var holeRemaining = (runStartByte - writtenUpTo).coerceAtMost(totalSize - writtenUpTo)
                        val zeros = ByteArray(min(holeRemaining, 65536L).toInt())
                        while (holeRemaining > 0) {
                            val step = min(holeRemaining, zeros.size.toLong()).toInt()
                            outChannel.write(ByteBuffer.wrap(zeros, 0, step))
                            holeRemaining -= step
                        }
                        writtenUpTo = runStartByte
                    }

                    var runBytesRemaining = (run.blockCount.toLong() * blockSize)
                        .coerceAtMost(totalSize - runStartByte)
                    var physCursor = run.physicalBlock * blockSize

                    if (run.isUninitialized || run.physicalBlock <= 0L) {
                        val zeros = ByteArray(min(runBytesRemaining, 65536L).toInt())
                        while (runBytesRemaining > 0) {
                            val step = min(runBytesRemaining, zeros.size.toLong()).toInt()
                            outChannel.write(ByteBuffer.wrap(zeros, 0, step))
                            runBytesRemaining -= step
                            writtenUpTo += step
                        }
                    } else {
                        while (runBytesRemaining > 0) {
                            val step = min(runBytesRemaining, chunkLimit.toLong()).toInt()
                            val chunk = reader.readBytesAt(physCursor, step)
                            outChannel.write(ByteBuffer.wrap(chunk))
                            physCursor += step
                            runBytesRemaining -= step
                            writtenUpTo += step
                        }
                    }
                }
            }
            return totalSize
        }

        val fsConfigLines = mutableListOf<String>()
        val fileContextsLines = mutableListOf<String>()
        val symlinksLines = mutableListOf<String>()
        val visitedInodes = HashSet<Long>()

        var dirsExtracted = 0
        var filesExtracted = 0
        var symlinksExtracted = 0
        var bytesExtracted = 0L
        var lastLoggedCount = 0

        fun walkDirectory(dirInodeNum: Long, relPath: String, depth: Int) {
            if (depth > 24 || !visitedInodes.add(dirInodeNum)) return
            val dirInode = readInode(dirInodeNum) ?: return
            if (!dirInode.isDirectory) return

            val currentOutDir = if (relPath.isEmpty()) outputDir else File(outputDir, relPath)
            currentOutDir.mkdirs()
            dirsExtracted++

            val permOctal = "%04o".format(dirInode.mode and 0x0FFF)
            val fsPath = if (relPath.isEmpty()) "/" else relPath
            fsConfigLines.add("$fsPath ${dirInode.uid} ${dirInode.gid} $permOctal")
            dirInode.selinuxContext?.let { ctx ->
                fileContextsLines.add("/$relPath $ctx")
            }

            val dirBytes = readInodePayloadToMemory(dirInode, maxBytes = 16 * 1024 * 1024)
            val db = ByteBuffer.wrap(dirBytes).order(ByteOrder.LITTLE_ENDIAN)

            // Parse ext4_dir_entry_2 block by block (supports both linear and HTree dx_root/dx_node blocks)
            var blockOffset = 0
            while (blockOffset < dirBytes.size) {
                val blockEnd = min(blockOffset + blockSize, dirBytes.size)
                var pos = blockOffset
                while (pos + 8 <= blockEnd) {
                    val childInodeNum = db.getInt(pos).toLong() and 0xFFFFFFFFL
                    val recLen = db.getShort(pos + 4).toInt() and 0xFFFF
                    val nameLen = db.get(pos + 6).toInt() and 0xFF
                    val fileType = db.get(pos + 7).toInt() and 0xFF

                    if (recLen < 8 || (recLen % 4 != 0) || pos + recLen > blockEnd) break

                    // HTree dx_node / dx_tail pseudo-entry check (inode == 0 && nameLen == 0)
                    if (childInodeNum > 0L && childInodeNum <= inodesCount && nameLen in 1..255 && pos + 8 + nameLen <= blockEnd) {
                        val rawName = String(dirBytes, pos + 8, nameLen, Charsets.UTF_8)
                        // Ignore non-printable binary HTree hash table buckets
                        val isPrintable = rawName.all { ch -> ch.code in 32..126 || ch.code > 160 }
                        val cleanName = rawName.replace("/", "_").trim('\u0000')
                        if (isPrintable && cleanName.isNotEmpty() && cleanName != "." && cleanName != ".." && cleanName != "lost+found") {
                            val childRelPath = if (relPath.isEmpty()) cleanName else "$relPath/$cleanName"
                            val childInode = readInode(childInodeNum)

                            if (childInode != null) {
                                when {
                                    childInode.isDirectory || fileType == 2 -> {
                                        walkDirectory(childInodeNum, childRelPath, depth + 1)
                                    }
                                    childInode.isRegularFile || fileType == 1 -> {
                                        val destFile = File(outputDir, childRelPath)
                                        val written = extractRegularFileToDisk(childInode, destFile)
                                        filesExtracted++
                                        bytesExtracted += written

                                        val fPerm = "%04o".format(childInode.mode and 0x0FFF)
                                        fsConfigLines.add("$childRelPath ${childInode.uid} ${childInode.gid} $fPerm")
                                        childInode.selinuxContext?.let { ctx ->
                                            fileContextsLines.add("/$childRelPath $ctx")
                                        }

                                        if (filesExtracted - lastLoggedCount >= 50) {
                                            lastLoggedCount = filesExtracted
                                            onProgressLog(
                                                "[EXT4-EXTRACT] $filesExtracted fichiers / $dirsExtracted dossiers extraits (${bytesExtracted / (1024 * 1024)} MB) -> $childRelPath"
                                            )
                                        }
                                    }
                                    childInode.isSymlink || fileType == 7 -> {
                                        val targetBytes = if (!childInode.usesExtents && childInode.sizeBytes <= 60) {
                                            childInode.rawBlockArea.copyOf(childInode.sizeBytes.toInt().coerceAtLeast(0))
                                        } else {
                                            readInodePayloadToMemory(childInode, 4096)
                                        }
                                        val linkTarget = String(targetBytes, Charsets.UTF_8).trimEnd('\u0000')
                                        symlinksExtracted++
                                        symlinksLines.add("/$childRelPath -> $linkTarget")
                                        fsConfigLines.add("$childRelPath ${childInode.uid} ${childInode.gid} 0777 capabilities=0x0")
                                    }
                                }
                            }
                        }
                    }
                    pos += recLen
                }
                blockOffset += blockSize
            }
        }

        // Start recursive extraction from EXT4 Root Inode (Inode 2)
        onProgressLog("[EXT4-EXTRACT] Lecture de la table d'inodes depuis la racine (Inode #2)...")
        walkDirectory(dirInodeNum = 2L, relPath = "", depth = 0)

        // Save UKA-compatible config/<partition>_fs_config, config/<partition>_file_contexts, config/<partition>_size.txt & ROM_FORGE_META/
        UkaConfigHelper.writeUkaAndRomForgeConfigs(
            outputDir = outputDir,
            partitionName = volumeLabel,
            filesystemType = formatName,
            blockSize = blockSize,
            totalSizeBytes = totalBlocks * blockSize,
            fsConfigLines = fsConfigLines,
            fileContextsLines = fileContextsLines,
            symlinksLines = symlinksLines
        )

        onProgressLog(
            "[UKA-EXT4-SUCCESS] Décompilation complète terminée : $filesExtracted fichiers, $dirsExtracted dossiers, $symlinksExtracted symlinks (${bytesExtracted / (1024 * 1024)} MB) + config/${volumeLabel}_fs_config & ${volumeLabel}_file_contexts dans ${outputDir.absolutePath}"
        )

        Ext4ExtractionResult(
            formatDetected = formatName,
            volumeName = volumeLabel,
            blockSize = blockSize,
            totalInodes = inodesCount,
            totalBlocks = totalBlocks,
            extractedDirsCount = dirsExtracted,
            extractedFilesCount = filesExtracted,
            extractedSymlinksCount = symlinksExtracted,
            totalExtractedBytes = bytesExtracted,
            outputDir = outputDir
        )
    }

    private fun parseSelinuxFromXattrArea(
        buffer: ByteArray,
        entriesStartOffset: Int,
        valueBaseOffset: Int,
        maxLength: Int
    ): String? {
        try {
            val bb = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN)
            var pos = entriesStartOffset
            val limit = (entriesStartOffset + maxLength).coerceAtMost(buffer.size)
            while (pos + 16 <= limit) {
                val nameLen = bb.get(pos).toInt() and 0xFF
                val nameIndex = bb.get(pos + 1).toInt() and 0xFF
                val valueOff = bb.getShort(pos + 2).toInt() and 0xFFFF
                val valueInum = bb.getInt(pos + 4)
                val valueSize = bb.getInt(pos + 8)

                if (nameLen == 0 && nameIndex == 0 && valueOff == 0 && valueInum == 0) break
                if (pos + 16 + nameLen > buffer.size) break

                val attrName = String(buffer, pos + 16, nameLen, Charsets.UTF_8)
                // nameIndex == 6 corresponds to EXT4_XATTR_INDEX_SECURITY ("security.")
                if ((nameIndex == 6 && attrName == "selinux") || attrName.contains("selinux")) {
                    val absValOffset = valueBaseOffset + valueOff
                    if (valueSize in 1..256 && absValOffset >= 0 && absValOffset + valueSize <= buffer.size) {
                        return String(buffer, absValOffset, valueSize, Charsets.UTF_8).trimEnd('\u0000')
                    }
                }
                // Advance to next 4-byte aligned entry
                val entrySize = (16 + nameLen + 3) and -4
                pos += entrySize
            }
        } catch (_: Exception) {
        }
        return null
    }
}
