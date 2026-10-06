package com.example.core.img

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import kotlin.math.min

/**
 * Pure Kotlin EXT4 Image Builder (`Ext4UserspaceBuilder`) inspired by `blackeangel/UKA` (`make_ext4fs` / `e2fsdroid`):
 * Constructs a 100% standard, multi-block-group compliant, mountable EXT4 filesystem `.img`
 * directly from any unpacked directory in `ROM_FORGE/UNPACK/<name>/` or `ROM_FORGE/PORT/<name>/`.
 *
 * Why ZArchiver / 7-Zip (`ExtHandler.cpp`) & Linux `mount -o loop` / `e2fsck` open this image cleanly:
 * - Standard 4096-byte blocks (`s_blocks_per_group = 32768`, `s_inodes_per_group = 4096`, `INODE_SIZE = 256`)
 * - Proper multi-block-group division when `totalBlocks > 32768` (7-Zip rejects any EXT4 image where `s_blocks_per_group > 32768`!)
 * - Populated Block Bitmaps and Inode Bitmaps for every Block Group
 * - Up to 4 direct `ext4_extent` runs in the inode (`eh_depth = 0`) + 1-level `ext4_extent_idx` index block (`eh_depth = 1`) for files > 128 MB
 * - Linear `ext4_dir_entry_2` directory blocks (`.`, `..`, and all children) excluding internal kitchen metadata (`ROM_FORGE_META`, `config`)
 * - Synchronizes UKA `config/<partition>_fs_config`, `config/<partition>_file_contexts`, and `config/<partition>_size.txt`
 * - Inline SELinux Extended Attributes (`EXT4_XATTR_MAGIC = 0xEA020000`, `security.selinux`).
 */
class Ext4UserspaceBuilder {

    companion object {
        private const val BLOCK_SIZE = 4096
        private const val INODE_SIZE = 256
        private const val BLOCKS_PER_GROUP = 32768 // Max blocks per group for 4096B block bitmap (32768 bits)
        private const val INODES_PER_GROUP = 4096  // 4096 inodes * 256B = 256 blocks per group
        private const val EXT4_SUPER_MAGIC: Short = 0xEF53.toShort()
        private const val EXT4_EXTENT_MAGIC: Short = 0xF30A.toShort()
        private const val EXT4_XATTR_MAGIC: Int = -0x15fe0000 // 0xEA020000
        private const val EXT4_EXTENTS_FL = 0x00080000
        private const val MAX_EXTENT_LEN = 32768
    }

    private data class PlannedExtent(
        val logicalBlock: Int,
        val physicalBlock: Int,
        val blockCount: Int
    )

    private data class PlannedInode(
        val inodeNum: Int,
        val relPath: String,
        val name: String,
        val mode: Int,
        val uid: Int,
        val gid: Int,
        val isDir: Boolean,
        val isSymlink: Boolean,
        val symlinkTarget: String = "",
        val sourceFile: File? = null,
        val selinuxContext: String = "u:object_r:system_file:s0",
        val capabilitiesHex: String = "0x0",
        val children: MutableList<PlannedInode> = mutableListOf(),
        var parentInodeNum: Int = 2,
        val extents: MutableList<PlannedExtent> = mutableListOf(),
        var extentIndexBlock: Int = 0, // Used only when extents.size > 4
        var totalAllocatedBlocks: Int = 0,
        var payloadSize: Long = 0L,
        var dirPayloadBytes: ByteArray = ByteArray(0)
    )

    private data class GroupLayout(
        val groupIndex: Int,
        val groupStartBlock: Int,
        val blockBitmapBlock: Int,
        val inodeBitmapBlock: Int,
        val inodeTableStartBlock: Int,
        val firstDataBlock: Int,
        var freeDataCursor: Int,
        val groupEndBlockExclusive: Int
    )

    suspend fun buildExt4ImageFromDirectory(
        sourceDir: File,
        targetImgFile: File,
        volumeLabel: String = "system",
        onLog: (String) -> Unit
    ): Long = withContext(Dispatchers.IO) {
        targetImgFile.parentFile?.mkdirs()
        if (targetImgFile.exists()) targetImgFile.delete()

        val cleanVolume = volumeLabel.trim().lowercase().ifEmpty { "system" }

        // 0. Autonomously inspect and heal SAR vs Flat partition topology before building EXT4
        AospTopologyResolver.inspectAndResolve(
            unpackedRoot = sourceDir,
            autoHealSarConflicts = true,
            onLog = onLog
        )

        // 1. Load UKA `config/<part>_fs_config` + `ROM_FORGE_META/extracted_fs_config.txt` + `etc/fs_config`
        val fsConfigMap = loadFsConfigMap(sourceDir, cleanVolume)
        val fileContextsMap = loadFileContextsMap(sourceDir, cleanVolume)
        val symlinksMap = loadSymlinksMap(sourceDir, cleanVolume)

        val allInodes = mutableListOf<PlannedInode>()
        var nextInodeNum = 11 // Inode 2 is root; Inode 11 is lost+found; 12+ are filesystem entries

        val rootInode = PlannedInode(
            inodeNum = 2,
            relPath = "",
            name = "",
            mode = 0x41ED, // 040755 (directory)
            uid = 0,
            gid = 0,
            isDir = true,
            isSymlink = false,
            selinuxContext = fileContextsMap[""] ?: "u:object_r:rootfs:s0",
            parentInodeNum = 2
        )
        allInodes.add(rootInode)

        // Create standard lost+found directory at Inode 11 so e2fsck & 7-Zip see a canonical EXT4 root
        val lostAndFoundInode = PlannedInode(
            inodeNum = nextInodeNum++,
            relPath = "lost+found",
            name = "lost+found",
            mode = 0x41C0, // 040700
            uid = 0,
            gid = 0,
            isDir = true,
            isSymlink = false,
            selinuxContext = "u:object_r:rootfs:s0",
            parentInodeNum = 2
        )
        rootInode.children.add(lostAndFoundInode)
        allInodes.add(lostAndFoundInode)

        fun scanRecursive(currentDir: File, parentPlanned: PlannedInode, relPrefix: String) {
            val childrenFiles = currentDir.listFiles()
                ?.filter {
                    !it.name.endsWith(".signing.tmp") &&
                            it.name != "ROM_FORGE_META" &&
                            !(relPrefix.isEmpty() && it.name == "lost+found") &&
                            !(relPrefix.isEmpty() && it.name == "config" && File(it, "${cleanVolume}_fs_config").exists())
                }
                ?.sortedBy { it.name }
                ?: emptyList()

            for (child in childrenFiles) {
                val childRel = if (relPrefix.isEmpty()) child.name else "$relPrefix/${child.name}"
                val ino = nextInodeNum++
                val cfg = fsConfigMap[childRel]
                val selinux = resolveSelinuxContext(childRel, cleanVolume, fileContextsMap)

                if (child.isDirectory) {
                    val mode = 0x4000 or (cfg?.mode ?: 0x1ED) // 0755
                    val dirPlanned = PlannedInode(
                        inodeNum = ino,
                        relPath = childRel,
                        name = child.name,
                        mode = mode,
                        uid = cfg?.uid ?: 0,
                        gid = cfg?.gid ?: 0,
                        isDir = true,
                        isSymlink = false,
                        selinuxContext = selinux,
                        capabilitiesHex = cfg?.capabilities ?: "0x0",
                        parentInodeNum = parentPlanned.inodeNum
                    )
                    parentPlanned.children.add(dirPlanned)
                    allInodes.add(dirPlanned)
                    scanRecursive(child, dirPlanned, childRel)
                } else {
                    val isExecutableBin = childRel.startsWith("bin/") ||
                            childRel.startsWith("system/bin/") ||
                            childRel.startsWith("xbin/") ||
                            childRel == "init"
                    val defaultPerm = if (childRel.endsWith("bin/init") || childRel == "init") 0x1E8 // 0750
                    else if (isExecutableBin) 0x1ED // 0755
                    else 0x1A4 // 0644
                    val defaultGid = if (isExecutableBin) 2000 else 0
                    val mode = 0x8000 or (cfg?.mode ?: defaultPerm)

                    val filePlanned = PlannedInode(
                        inodeNum = ino,
                        relPath = childRel,
                        name = child.name,
                        mode = mode,
                        uid = cfg?.uid ?: 0,
                        gid = cfg?.gid ?: defaultGid,
                        isDir = false,
                        isSymlink = false,
                        sourceFile = child,
                        selinuxContext = selinux,
                        capabilitiesHex = cfg?.capabilities ?: "0x0",
                        parentInodeNum = parentPlanned.inodeNum,
                        payloadSize = child.length()
                    )
                    parentPlanned.children.add(filePlanned)
                    allInodes.add(filePlanned)
                }
            }

            // Attach symbolic links belonging to this directory
            val dirSymlinks = symlinksMap.filter { (linkPath, _) ->
                val parentPath = linkPath.substringBeforeLast("/", "")
                parentPath == relPrefix && parentPlanned.children.none { it.name == linkPath.substringAfterLast("/") }
            }
            for ((linkRel, linkTarget) in dirSymlinks) {
                val linkName = linkRel.substringAfterLast("/")
                if (linkName.isNotEmpty()) {
                    val ino = nextInodeNum++
                    val cfg = fsConfigMap[linkRel]
                    val symPlanned = PlannedInode(
                        inodeNum = ino,
                        relPath = linkRel,
                        name = linkName,
                        mode = 0xA1FF, // 0120777 symlink
                        uid = cfg?.uid ?: 0,
                        gid = cfg?.gid ?: 0,
                        isDir = false,
                        isSymlink = true,
                        symlinkTarget = linkTarget,
                        selinuxContext = resolveSelinuxContext(linkRel, cleanVolume, fileContextsMap),
                        parentInodeNum = parentPlanned.inodeNum,
                        payloadSize = linkTarget.toByteArray(Charsets.UTF_8).size.toLong()
                    )
                    parentPlanned.children.add(symPlanned)
                    allInodes.add(symPlanned)
                }
            }
        }

        scanRecursive(sourceDir, rootInode, "")

        // Synchronize UKA `config/` and `ROM_FORGE_META/` before building so any newly added APK/overlay is registered
        syncUpdatedUkaConfigFiles(sourceDir, cleanVolume, allInodes)

        // 2. Build directory entry payloads (`ext4_dir_entry_2`) for all directories
        for (node in allInodes) {
            if (node.isDir) {
                node.dirPayloadBytes = buildDirectoryBlocks(node.inodeNum, node.parentInodeNum, node.children)
                node.payloadSize = node.dirPayloadBytes.size.toLong()
            }
        }

        // 3. Calculate required data blocks and multi-group layout (strictly <= 32768 blocks per group)
        var estimatedDataBlocks = 0
        for (node in allInodes) {
            estimatedDataBlocks += when {
                node.isDir -> (node.dirPayloadBytes.size + BLOCK_SIZE - 1) / BLOCK_SIZE
                node.isSymlink -> if (node.symlinkTarget.toByteArray(Charsets.UTF_8).size > 60) 1 else 0
                else -> ((node.payloadSize + BLOCK_SIZE - 1) / BLOCK_SIZE).toInt() + 1
            }
        }

        val inodeTableBlocksPerGroup = (INODES_PER_GROUP * INODE_SIZE) / BLOCK_SIZE // 256 blocks
        val minGroupsForInodes = ((nextInodeNum + INODES_PER_GROUP - 1) / INODES_PER_GROUP).coerceAtLeast(1)
        val usableDataBlocksPerGroup = BLOCKS_PER_GROUP - (4 + inodeTableBlocksPerGroup)
        val minGroupsForData = ((estimatedDataBlocks + usableDataBlocksPerGroup - 1) / usableDataBlocksPerGroup).coerceAtLeast(1)
        val numGroups = maxOf(minGroupsForInodes, minGroupsForData, 1)

        val totalInodes = numGroups * INODES_PER_GROUP
        val gdtBlocks = ((numGroups * 32) + BLOCK_SIZE - 1) / BLOCK_SIZE

        // Initialize Block Groups
        val groups = ArrayList<GroupLayout>(numGroups)
        for (g in 0 until numGroups) {
            val gStart = g * BLOCKS_PER_GROUP
            val reservedHeaderBlocks = if (g == 0) (1 + gdtBlocks) else 0
            val blkBmp = gStart + reservedHeaderBlocks
            val inoBmp = blkBmp + 1
            val inoTbl = inoBmp + 1
            val firstData = inoTbl + inodeTableBlocksPerGroup
            groups.add(
                GroupLayout(
                    groupIndex = g,
                    groupStartBlock = gStart,
                    blockBitmapBlock = blkBmp,
                    inodeBitmapBlock = inoBmp,
                    inodeTableStartBlock = inoTbl,
                    firstDataBlock = firstData,
                    freeDataCursor = firstData,
                    groupEndBlockExclusive = gStart + BLOCKS_PER_GROUP
                )
            )
        }

        fun allocateContiguousRun(requestedBlocks: Int): Pair<Int, Int> {
            val maxSingleRun = requestedBlocks.coerceAtMost(MAX_EXTENT_LEN)
            for (g in groups) {
                val avail = g.groupEndBlockExclusive - g.freeDataCursor
                if (avail > 0) {
                    val take = min(maxSingleRun, avail)
                    val startBlk = g.freeDataCursor
                    g.freeDataCursor += take
                    return startBlk to take
                }
            }
            // Dynamically append a new Block Group if needed
            val newIdx = groups.size
            val gStart = newIdx * BLOCKS_PER_GROUP
            val blkBmp = gStart
            val inoBmp = blkBmp + 1
            val inoTbl = inoBmp + 1
            val firstData = inoTbl + inodeTableBlocksPerGroup
            val take = min(maxSingleRun, (gStart + BLOCKS_PER_GROUP) - firstData)
            val newGroup = GroupLayout(
                groupIndex = newIdx,
                groupStartBlock = gStart,
                blockBitmapBlock = blkBmp,
                inodeBitmapBlock = inoBmp,
                inodeTableStartBlock = inoTbl,
                firstDataBlock = firstData,
                freeDataCursor = firstData + take,
                groupEndBlockExclusive = gStart + BLOCKS_PER_GROUP
            )
            groups.add(newGroup)
            return firstData to take
        }

        // Allocate data extents for every inode
        for (node in allInodes) {
            val neededBlocks = when {
                node.isDir -> (node.dirPayloadBytes.size + BLOCK_SIZE - 1) / BLOCK_SIZE
                node.isSymlink -> if (node.symlinkTarget.toByteArray(Charsets.UTF_8).size > 60) 1 else 0
                else -> ((node.payloadSize + BLOCK_SIZE - 1) / BLOCK_SIZE).toInt()
            }

            var remaining = neededBlocks
            var logicalCur = 0
            while (remaining > 0) {
                val (physStart, count) = allocateContiguousRun(remaining)
                node.extents.add(PlannedExtent(logicalCur, physStart, count))
                logicalCur += count
                remaining -= count
            }
            node.totalAllocatedBlocks = neededBlocks

            if (node.extents.size > 4) {
                val (idxBlk, _) = allocateContiguousRun(1)
                node.extentIndexBlock = idxBlk
                node.totalAllocatedBlocks += 1
            }
        }

        val finalGroupCount = groups.size
        val finalTotalInodes = finalGroupCount * INODES_PER_GROUP
        val lastGroup = groups.last()
        val totalBlocks = if (finalGroupCount == 1) {
            (lastGroup.freeDataCursor + 64).coerceIn(512, BLOCKS_PER_GROUP)
        } else {
            (finalGroupCount - 1) * BLOCKS_PER_GROUP + (lastGroup.freeDataCursor - lastGroup.groupStartBlock + 64).coerceAtMost(BLOCKS_PER_GROUP)
        }
        lastGroup.let {
            // Adjust last group's actual end block to totalBlocks
            groups[groups.lastIndex] = it.copy(groupEndBlockExclusive = totalBlocks)
        }

        val totalImageBytes = totalBlocks.toLong() * BLOCK_SIZE
        val totalFreeBlocks = groups.sumOf { (it.groupEndBlockExclusive - it.freeDataCursor).coerceAtLeast(0) }
        val totalFreeInodes = (finalTotalInodes - nextInodeNum).coerceAtLeast(0)

        onLog(
            "[UKA-EXT4-BUILDER] Construction EXT4 (compatible ZArchiver/7-Zip & Linux mount) : ${allInodes.size} inodes, $finalGroupCount groupe(s), $totalBlocks blocs (${totalImageBytes / 1024} KB)..."
        )

        RandomAccessFile(targetImgFile, "rw").use { raf ->
            raf.setLength(totalImageBytes)

            // 4. Write EXT4 Superblock at byte offset 1024
            val sbBuf = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)
            sbBuf.putInt(0x00, finalTotalInodes)                  // s_inodes_count
            sbBuf.putInt(0x04, totalBlocks)                       // s_blocks_count_lo
            sbBuf.putInt(0x08, 0)                                 // s_r_blocks_count_lo
            sbBuf.putInt(0x0C, totalFreeBlocks)                   // s_free_blocks_count_lo
            sbBuf.putInt(0x10, totalFreeInodes)                   // s_free_inodes_count
            sbBuf.putInt(0x14, 0)                                 // s_first_data_block (0 for 4K blocks)
            sbBuf.putInt(0x18, 2)                                 // s_log_block_size (1024 << 2 = 4096)
            sbBuf.putInt(0x1C, 2)                                 // s_log_cluster_size (2 = 4096)
            sbBuf.putInt(0x20, BLOCKS_PER_GROUP)                  // s_blocks_per_group = 32768 (MANDATORY <= 32768!)
            sbBuf.putInt(0x24, BLOCKS_PER_GROUP)                  // s_clusters_per_group = 32768
            sbBuf.putInt(0x28, INODES_PER_GROUP)                  // s_inodes_per_group = 4096
            sbBuf.putInt(0x2C, (System.currentTimeMillis() / 1000).toInt()) // s_mtime
            sbBuf.putInt(0x30, (System.currentTimeMillis() / 1000).toInt()) // s_wtime
            sbBuf.putShort(0x34, 1)                               // s_mnt_count
            sbBuf.putShort(0x36, 20)                              // s_max_mnt_count
            sbBuf.putShort(0x38, EXT4_SUPER_MAGIC)                // s_magic = 0xEF53
            sbBuf.putShort(0x3A, 1)                               // s_state = EXT4_VALID_FS
            sbBuf.putShort(0x3C, 1)                               // s_errors = continue
            sbBuf.putShort(0x3E, 0)                               // s_minor_rev_level
            sbBuf.putInt(0x40, (System.currentTimeMillis() / 1000).toInt()) // s_lastcheck
            sbBuf.putInt(0x4C, 1)                                 // s_rev_level = EXT4_DYNAMIC_REV
            sbBuf.putInt(0x54, 11)                                // s_first_ino = 11
            sbBuf.putShort(0x58, INODE_SIZE.toShort())            // s_inode_size = 256
            sbBuf.putShort(0x5A, 0)                               // s_block_group_nr = 0
            sbBuf.putInt(0x5C, 0x0020)                            // s_feature_compat (EXT_ATTR)
            sbBuf.putInt(0x60, 0x0042)                            // s_feature_incompat (FILETYPE | EXTENTS)
            sbBuf.putInt(0x64, 0x0003)                            // s_feature_ro_compat (SPARSE_SUPER | LARGE_FILE)

            val uuid = UUID.nameUUIDFromBytes(cleanVolume.toByteArray())
            sbBuf.position(0x68)
            sbBuf.putLong(uuid.mostSignificantBits)
            sbBuf.putLong(uuid.leastSignificantBits)

            val labelBytes = cleanVolume.toByteArray(Charsets.UTF_8).copyOf(16)
            sbBuf.position(0x78)
            sbBuf.put(labelBytes)

            val mntBytes = "/$cleanVolume".toByteArray(Charsets.UTF_8).copyOf(64)
            sbBuf.position(0x88)
            sbBuf.put(mntBytes)

            sbBuf.putShort(0xFE, 32.toShort())                    // s_desc_size = 32
            sbBuf.putShort(0x15C, 32.toShort())                   // s_min_extra_isize = 32
            sbBuf.putShort(0x15E, 32.toShort())                   // s_want_extra_isize = 32

            raf.seek(1024L)
            raf.write(sbBuf.array())

            // 5. Write Block Group Descriptor Table (GDT) starting at Block 1 (offset 4096) and Bitmaps per group
            val gdtTotalBytes = ByteBuffer.allocate(finalGroupCount * 32).order(ByteOrder.LITTLE_ENDIAN)
            for (g in groups) {
                val base = g.groupIndex * 32
                val freeBlocksInGroup = (g.groupEndBlockExclusive - g.freeDataCursor).coerceAtLeast(0)
                val groupInodeStart = g.groupIndex * INODES_PER_GROUP + 1
                val groupInodeEnd = (g.groupIndex + 1) * INODES_PER_GROUP
                val usedInodesInGroup = when {
                    nextInodeNum - 1 >= groupInodeEnd -> INODES_PER_GROUP
                    nextInodeNum - 1 >= groupInodeStart -> (nextInodeNum - groupInodeStart)
                    else -> 0
                }
                val freeInodesInGroup = (INODES_PER_GROUP - usedInodesInGroup).coerceAtLeast(0)
                val dirsInGroup = allInodes.count {
                    it.isDir && it.inodeNum in groupInodeStart..groupInodeEnd
                }

                gdtTotalBytes.putInt(base + 0x00, g.blockBitmapBlock)
                gdtTotalBytes.putInt(base + 0x04, g.inodeBitmapBlock)
                gdtTotalBytes.putInt(base + 0x08, g.inodeTableStartBlock)
                gdtTotalBytes.putShort(base + 0x0C, freeBlocksInGroup.coerceAtMost(65535).toShort())
                gdtTotalBytes.putShort(base + 0x0E, freeInodesInGroup.coerceAtMost(65535).toShort())
                gdtTotalBytes.putShort(base + 0x10, dirsInGroup.coerceAtMost(65535).toShort())

                // Populate Block Bitmap for group g
                val blockBitmap = ByteArray(BLOCK_SIZE)
                val allocatedBlocksInGroup = (g.freeDataCursor - g.groupStartBlock).coerceIn(0, BLOCKS_PER_GROUP)
                for (bit in 0 until allocatedBlocksInGroup) {
                    blockBitmap[bit ushr 3] = (blockBitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
                }
                // Pad out-of-bounds trailing bits in last group as allocated (1) per EXT4 specification
                val validBlocksInGroup = (g.groupEndBlockExclusive - g.groupStartBlock).coerceIn(0, BLOCKS_PER_GROUP)
                for (bit in validBlocksInGroup until BLOCKS_PER_GROUP) {
                    blockBitmap[bit ushr 3] = (blockBitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
                }
                raf.seek(g.blockBitmapBlock.toLong() * BLOCK_SIZE)
                raf.write(blockBitmap)

                // Populate Inode Bitmap for group g
                val inodeBitmap = ByteArray(BLOCK_SIZE)
                val reservedAndUsed = if (g.groupIndex == 0) usedInodesInGroup.coerceAtLeast(10) else usedInodesInGroup
                for (bit in 0 until reservedAndUsed) {
                    inodeBitmap[bit ushr 3] = (inodeBitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
                }
                for (bit in INODES_PER_GROUP until (BLOCK_SIZE * 8)) {
                    inodeBitmap[bit ushr 3] = (inodeBitmap[bit ushr 3].toInt() or (1 shl (bit and 7))).toByte()
                }
                raf.seek(g.inodeBitmapBlock.toLong() * BLOCK_SIZE)
                raf.write(inodeBitmap)
            }

            raf.seek(BLOCK_SIZE.toLong())
            raf.write(gdtTotalBytes.array())

            // 6. Write Inodes into their Group's Inode Table and Data Payloads into Data Blocks
            val copyBuf = ByteArray(65536)
            for (node in allInodes) {
                val groupIdx = (node.inodeNum - 1) / INODES_PER_GROUP
                val indexInGroup = (node.inodeNum - 1) % INODES_PER_GROUP
                val inodeTableBlk = groups[groupIdx].inodeTableStartBlock
                val inodeOffset = inodeTableBlk.toLong() * BLOCK_SIZE + indexInGroup.toLong() * INODE_SIZE

                val inodeBytes = buildInodeBytes(node)
                raf.seek(inodeOffset)
                raf.write(inodeBytes)

                if (node.extentIndexBlock > 0 && node.extents.size > 4) {
                    val leafBlkBytes = buildExtentLeafBlock(node.extents)
                    raf.seek(node.extentIndexBlock.toLong() * BLOCK_SIZE)
                    raf.write(leafBlkBytes)
                }

                // Write data blocks across extent runs
                if (node.isDir && node.dirPayloadBytes.isNotEmpty()) {
                    var byteCursor = 0
                    for (ext in node.extents) {
                        val toWrite = min(ext.blockCount * BLOCK_SIZE, node.dirPayloadBytes.size - byteCursor)
                        if (toWrite > 0) {
                            raf.seek(ext.physicalBlock.toLong() * BLOCK_SIZE)
                            raf.write(node.dirPayloadBytes, byteCursor, toWrite)
                            byteCursor += toWrite
                        }
                    }
                } else if (node.isSymlink && node.extents.isNotEmpty()) {
                    val symBytes = node.symlinkTarget.toByteArray(Charsets.UTF_8)
                    raf.seek(node.extents.first().physicalBlock.toLong() * BLOCK_SIZE)
                    raf.write(symBytes)
                } else if (!node.isDir && !node.isSymlink && node.extents.isNotEmpty() && node.sourceFile != null) {
                    node.sourceFile.inputStream().use { input ->
                        for (ext in node.extents) {
                            raf.seek(ext.physicalBlock.toLong() * BLOCK_SIZE)
                            var bytesLeftInExtent = ext.blockCount.toLong() * BLOCK_SIZE
                            while (bytesLeftInExtent > 0) {
                                val step = min(bytesLeftInExtent, copyBuf.size.toLong()).toInt()
                                val r = input.read(copyBuf, 0, step)
                                if (r <= 0) break
                                raf.write(copyBuf, 0, r)
                                bytesLeftInExtent -= r
                            }
                        }
                    }
                }
            }
        }

        onLog("[UKA-EXT4-BUILDER] Image EXT4 prête : ${targetImgFile.absolutePath} (${targetImgFile.length() / 1024} KB)")
        targetImgFile.length()
    }

    private fun buildInodeBytes(node: PlannedInode): ByteArray {
        val raw = ByteArray(INODE_SIZE)
        val ib = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN)
        val nowSec = (System.currentTimeMillis() / 1000).toInt()

        val usesExtents = !(node.isSymlink && node.payloadSize <= 60)
        val flags = if (usesExtents) EXT4_EXTENTS_FL else 0

        ib.putShort(0x00, node.mode.toShort())
        ib.putShort(0x02, (node.uid and 0xFFFF).toShort())
        ib.putInt(0x04, (node.payloadSize and 0xFFFFFFFFL).toInt())
        ib.putInt(0x08, nowSec) // atime
        ib.putInt(0x0C, nowSec) // ctime
        ib.putInt(0x10, nowSec) // mtime
        ib.putShort(0x18, (node.gid and 0xFFFF).toShort())
        ib.putShort(0x1A, if (node.isDir) (2 + node.children.count { it.isDir }).toShort() else 1.toShort())
        ib.putInt(0x1C, node.totalAllocatedBlocks * (BLOCK_SIZE / 512)) // i_blocks_lo in 512B sectors
        ib.putInt(0x20, flags)
        ib.putInt(0x6C, ((node.payloadSize ushr 32) and 0xFFFFFFFFL).toInt()) // i_size_high

        if (!usesExtents && node.isSymlink) {
            val targetBytes = node.symlinkTarget.toByteArray(Charsets.UTF_8)
            System.arraycopy(targetBytes, 0, raw, 0x28, targetBytes.size.coerceAtMost(60))
        } else if (node.extents.size <= 4) {
            // Depth 0 leaf extents directly in inode i_block (up to 4 extents)
            ib.putShort(0x28, EXT4_EXTENT_MAGIC) // eh_magic = 0xF30A
            ib.putShort(0x2A, node.extents.size.toShort()) // eh_entries
            ib.putShort(0x2C, 4.toShort())       // eh_max = 4
            ib.putShort(0x2E, 0.toShort())       // eh_depth = 0 (leaf)
            ib.putInt(0x30, 0)                   // eh_generation

            for (i in node.extents.indices) {
                val ext = node.extents[i]
                val pos = 0x34 + i * 12
                ib.putInt(pos, ext.logicalBlock)
                ib.putShort(pos + 4, ext.blockCount.coerceAtMost(MAX_EXTENT_LEN).toShort())
                ib.putShort(pos + 6, 0.toShort())
                ib.putInt(pos + 8, ext.physicalBlock)
            }
        } else {
            // Depth 1 extent index pointing to node.extentIndexBlock
            ib.putShort(0x28, EXT4_EXTENT_MAGIC)
            ib.putShort(0x2A, 1.toShort())       // eh_entries = 1 index node
            ib.putShort(0x2C, 4.toShort())       // eh_max = 4
            ib.putShort(0x2E, 1.toShort())       // eh_depth = 1
            ib.putInt(0x30, 0)

            // ext4_extent_idx at 0x34
            ib.putInt(0x34, 0)                   // ei_block = 0
            ib.putInt(0x38, node.extentIndexBlock) // ei_leaf_lo
            ib.putShort(0x3C, 0.toShort())       // ei_leaf_hi
            ib.putShort(0x3E, 0.toShort())       // ei_unused
        }

        // Extra inode size (32 bytes -> inline xattr starts at 128 + 32 = 160)
        ib.putShort(0x80, 32.toShort())

        // Write inline SELinux xattr (`security.selinux`) at offset 160
        val xattrStart = 160
        ib.putInt(xattrStart, EXT4_XATTR_MAGIC)
        val entryPos = xattrStart + 4
        val nameBytes = "selinux".toByteArray(Charsets.UTF_8)
        val valBytes = (node.selinuxContext + "\u0000").toByteArray(Charsets.UTF_8)
        val valOffsetInArea = 48

        if (entryPos + valOffsetInArea + valBytes.size <= INODE_SIZE) {
            raw[entryPos] = nameBytes.size.toByte() // e_name_len = 7
            raw[entryPos + 1] = 6.toByte()          // e_name_index = 6 (EXT4_XATTR_INDEX_SECURITY)
            ib.putShort(entryPos + 2, valOffsetInArea.toShort())
            ib.putInt(entryPos + 4, 0)              // e_value_inum = 0
            ib.putInt(entryPos + 8, valBytes.size)  // e_value_size
            System.arraycopy(nameBytes, 0, raw, entryPos + 16, nameBytes.size)
            System.arraycopy(valBytes, 0, raw, entryPos + valOffsetInArea, valBytes.size)
        }

        return raw
    }

    private fun buildExtentLeafBlock(extents: List<PlannedExtent>): ByteArray {
        val blk = ByteArray(BLOCK_SIZE)
        val bb = ByteBuffer.wrap(blk).order(ByteOrder.LITTLE_ENDIAN)
        val maxEntries = (BLOCK_SIZE - 12) / 12
        val count = extents.size.coerceAtMost(maxEntries)

        bb.putShort(0x00, EXT4_EXTENT_MAGIC)
        bb.putShort(0x02, count.toShort())
        bb.putShort(0x04, maxEntries.toShort())
        bb.putShort(0x06, 0.toShort()) // depth = 0
        bb.putInt(0x08, 0)

        for (i in 0 until count) {
            val ext = extents[i]
            val pos = 12 + i * 12
            bb.putInt(pos, ext.logicalBlock)
            bb.putShort(pos + 4, ext.blockCount.coerceAtMost(MAX_EXTENT_LEN).toShort())
            bb.putShort(pos + 6, 0.toShort())
            bb.putInt(pos + 8, ext.physicalBlock)
        }
        return blk
    }

    private fun buildDirectoryBlocks(
        selfInode: Int,
        parentInode: Int,
        children: List<PlannedInode>
    ): ByteArray {
        data class DirItem(val ino: Int, val fileType: Int, val name: String)

        val entries = mutableListOf<DirItem>()
        entries.add(DirItem(selfInode, 2, "."))
        entries.add(DirItem(parentInode, 2, ".."))
        for (c in children) {
            val ft = when {
                c.isDir -> 2
                c.isSymlink -> 7
                else -> 1
            }
            entries.add(DirItem(c.inodeNum, ft, c.name))
        }

        val blocksOut = ByteArrayOutputStream()
        var currentBlock = ByteArray(BLOCK_SIZE)
        var bb = ByteBuffer.wrap(currentBlock).order(ByteOrder.LITTLE_ENDIAN)
        var posInBlock = 0
        var lastEntryOffset = 0

        for (i in entries.indices) {
            val e = entries[i]
            val nameBytes = e.name.toByteArray(Charsets.UTF_8)
            val neededLen = (8 + nameBytes.size + 3) and -4

            if (posInBlock + neededLen > BLOCK_SIZE) {
                val prevRecLen = BLOCK_SIZE - lastEntryOffset
                bb.putShort(lastEntryOffset + 4, prevRecLen.toShort())
                blocksOut.write(currentBlock)

                currentBlock = ByteArray(BLOCK_SIZE)
                bb = ByteBuffer.wrap(currentBlock).order(ByteOrder.LITTLE_ENDIAN)
                posInBlock = 0
                lastEntryOffset = 0
            }

            val isLastOverall = (i == entries.lastIndex)
            val recLen = if (isLastOverall) (BLOCK_SIZE - posInBlock) else neededLen

            bb.putInt(posInBlock, e.ino)
            bb.putShort(posInBlock + 4, recLen.toShort())
            currentBlock[posInBlock + 6] = nameBytes.size.toByte()
            currentBlock[posInBlock + 7] = e.fileType.toByte()
            System.arraycopy(nameBytes, 0, currentBlock, posInBlock + 8, nameBytes.size)

            lastEntryOffset = posInBlock
            posInBlock += recLen
        }

        blocksOut.write(currentBlock)
        return blocksOut.toByteArray()
    }

    private data class FsConfigEntry(
        val uid: Int,
        val gid: Int,
        val mode: Int,
        val capabilities: String = "0x0"
    )

    private fun loadFsConfigMap(sourceDir: File, partitionName: String): Map<String, FsConfigEntry> {
        val map = mutableMapOf<String, FsConfigEntry>()
        val candidates = listOf(
            File(sourceDir, "config/${partitionName}_fs_config"),
            File(sourceDir, "ROM_FORGE_META/extracted_fs_config.txt"),
            File(sourceDir, "etc/fs_config")
        )
        for (f in candidates) {
            if (f.exists()) {
                f.readLines().forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size >= 4) {
                        var path = parts[0].removePrefix("/")
                        if (path == partitionName) path = ""
                        else if (path.startsWith("$partitionName/")) path = path.removePrefix("$partitionName/")
                        val uid = parts[1].toIntOrNull() ?: 0
                        val gid = parts[2].toIntOrNull() ?: 0
                        val perm = parts[3].toIntOrNull(8) ?: 0x1A4
                        val cap = parts.find { it.startsWith("capabilities=") }?.substringAfter("=") ?: "0x0"
                        map[path] = FsConfigEntry(uid, gid, perm, cap)
                    }
                }
            }
        }
        return map
    }

    private fun loadFileContextsMap(sourceDir: File, partitionName: String): Map<String, String> {
        val map = mutableMapOf<String, String>()
        val candidates = listOf(
            File(sourceDir, "config/${partitionName}_file_contexts"),
            File(sourceDir, "ROM_FORGE_META/extracted_file_contexts.txt"),
            File(sourceDir, "etc/selinux/plat_file_contexts")
        )
        for (f in candidates) {
            if (f.exists()) {
                f.readLines().forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size >= 2) {
                        var path = parts[0]
                            .replace("\\.", ".")
                            .replace("\\+", "+")
                            .replace("\\-", "-")
                            .removePrefix("/")
                        if (path == partitionName) path = ""
                        else if (path.startsWith("$partitionName/")) path = path.removePrefix("$partitionName/")
                        val ctx = parts.last()
                        if (ctx.startsWith("u:object_r:")) {
                            map[path] = ctx
                        }
                    }
                }
            }
        }
        return map
    }

    private fun loadSymlinksMap(sourceDir: File, partitionName: String): Map<String, String> {
        val map = linkedMapOf<String, String>()
        val symFile = File(sourceDir, "ROM_FORGE_META/extracted_symlinks.txt")
        if (symFile.exists()) {
            symFile.readLines().forEach { line ->
                if (line.contains("->")) {
                    var left = line.substringBefore("->").trim().removePrefix("/")
                    if (left.startsWith("$partitionName/")) left = left.removePrefix("$partitionName/")
                    val right = line.substringAfter("->").trim()
                    if (left.isNotEmpty() && right.isNotEmpty()) {
                        map[left] = right
                    }
                }
            }
        }
        // Also parse UKA 6-column symlink entries from `config/<partition>_fs_config`
        val ukaFs = File(sourceDir, "config/${partitionName}_fs_config")
        if (ukaFs.exists()) {
            ukaFs.readLines().forEach { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 6 && parts[3] == "0777" && parts[4].startsWith("capabilities=")) {
                    val left = parts[0].removePrefix("/").removePrefix("$partitionName/")
                    val target = parts[5]
                    if (left.isNotEmpty() && target.isNotEmpty()) {
                        map.putIfAbsent(left, target)
                    }
                }
            }
        }
        return map
    }

    private fun syncUpdatedUkaConfigFiles(
        sourceDir: File,
        partitionName: String,
        allInodes: List<PlannedInode>
    ) {
        val fsLines = mutableListOf<String>()
        val fcLines = mutableListOf<String>()
        val symLines = mutableListOf<String>()

        for (node in allInodes) {
            if (node.name == "lost+found") continue
            val octal = "%04o".format(node.mode and 0x0FFF)
            if (node.relPath.isEmpty()) {
                fsLines.add("/ ${node.uid} ${node.gid} $octal capabilities=0x0")
                fcLines.add("/ ${node.selinuxContext}")
            } else if (node.isSymlink) {
                fsLines.add("${node.relPath} ${node.uid} ${node.gid} 0777 capabilities=0x0 ${node.symlinkTarget}")
                fcLines.add("/${node.relPath} ${node.selinuxContext}")
                symLines.add("/${node.relPath} -> ${node.symlinkTarget}")
            } else {
                fsLines.add("${node.relPath} ${node.uid} ${node.gid} $octal capabilities=${node.capabilitiesHex}")
                fcLines.add("/${node.relPath} ${node.selinuxContext}")
            }
        }

        val totalSize = allInodes.sumOf { it.payloadSize } + 16L * 1024 * 1024
        UkaConfigHelper.writeUkaAndRomForgeConfigs(
            outputDir = sourceDir,
            partitionName = partitionName,
            filesystemType = "EXT4",
            blockSize = BLOCK_SIZE,
            totalSizeBytes = totalSize,
            fsConfigLines = fsLines,
            fileContextsLines = fcLines,
            symlinksLines = symLines
        )
    }

    private fun resolveSelinuxContext(relPath: String, partitionName: String, map: Map<String, String>): String {
        map[relPath]?.let { return it }
        return when {
            relPath.isEmpty() -> "u:object_r:rootfs:s0"
            relPath == "init" || relPath.endsWith("bin/init") -> "u:object_r:init_exec:s0"
            relPath.endsWith("bin/sh") -> "u:object_r:shell_exec:s0"
            relPath.endsWith("bin/servicemanager") -> "u:object_r:servicemanager_exec:s0"
            relPath.endsWith("bin/surfaceflinger") -> "u:object_r:surfaceflinger_exec:s0"
            relPath.contains("lib64/") || relPath.contains("lib/") -> "u:object_r:system_lib_file:s0"
            relPath.contains("overlay/") -> "u:object_r:vendor_overlay_file:s0"
            else -> "u:object_r:${partitionName}_file:s0"
        }
    }
}
