package com.example.core.img

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * Pure Kotlin EROFS (Enhanced Read-Only File System, magic `0xE0F5E1E2`) Image Builder
 * inspired by `blackeangel/UKA` (`mkfs.erofs`).
 *
 * Produces a genuine, standard EROFS v1 image with:
 * - EROFS Superblock at byte offset 1024 (`0xE0F5E1E2`, 4096-byte blocks, `meta_blkaddr = 1`)
 * - 32-byte compact inodes (`EROFS_INODE_LAYOUT_COMPACT`, 32-byte NID slots)
 * - Sorted `erofs_dirent` directory blocks (`.`, `..`, and all children sorted lexicographically as required by EROFS binary search)
 * - 4K block-aligned file payloads (`EROFS_INODE_FLAT_PLAIN`)
 * - Full compatibility with `ErofsUserspaceExtractor`, 7-Zip/ZArchiver EROFS parser, and Linux `mount -t erofs`.
 */
class ErofsUserspaceBuilder {

    companion object {
        private const val BLOCK_SIZE = 4096
        private const val EROFS_SUPER_MAGIC_V1 = -0x1f0a1e1e // 0xE0F5E1E2
        private const val EROFS_SUPER_OFFSET = 1024L
        private const val META_BLK_ADDR = 1
        private const val INODE_SLOT_SIZE = 32
    }

    private data class PlannedErofsNode(
        var nid: Int = 0,
        val relPath: String,
        val name: String,
        val mode: Int,
        val uid: Int,
        val gid: Int,
        val isDir: Boolean,
        val isSymlink: Boolean,
        val symlinkTarget: String = "",
        val sourceFile: File? = null,
        val children: MutableList<PlannedErofsNode> = mutableListOf(),
        var parentNid: Int = 0,
        var rawBlkAddr: Int = 0,
        var blockCount: Int = 0,
        var payloadSize: Long = 0L,
        var dirPayloadBytes: ByteArray = ByteArray(0)
    )

    suspend fun buildErofsImageFromDirectory(
        sourceDir: File,
        targetImgFile: File,
        volumeLabel: String = "system",
        onLog: (String) -> Unit
    ): Long = withContext(Dispatchers.IO) {
        targetImgFile.parentFile?.mkdirs()
        if (targetImgFile.exists()) targetImgFile.delete()

        val allNodes = mutableListOf<PlannedErofsNode>()
        val rootNode = PlannedErofsNode(
            nid = 0,
            relPath = "",
            name = "",
            mode = 0x41ED, // 040755
            uid = 0,
            gid = 0,
            isDir = true,
            isSymlink = false
        )
        allNodes.add(rootNode)

        fun scanTree(currentDir: File, parentNode: PlannedErofsNode, relPrefix: String) {
            val files = currentDir.listFiles()
                ?.filter { !it.name.endsWith(".signing.tmp") && it.name != "ROM_FORGE_META" && it.name != "config" }
                ?.sortedBy { it.name }
                ?: emptyList()

            for (child in files) {
                val childRel = if (relPrefix.isEmpty()) child.name else "$relPrefix/${child.name}"
                if (child.isDirectory) {
                    val dirNode = PlannedErofsNode(
                        relPath = childRel,
                        name = child.name,
                        mode = 0x41ED,
                        uid = 0,
                        gid = 0,
                        isDir = true,
                        isSymlink = false
                    )
                    parentNode.children.add(dirNode)
                    allNodes.add(dirNode)
                    scanTree(child, dirNode, childRel)
                } else {
                    val isBin = childRel.startsWith("bin/") || childRel.startsWith("system/bin/")
                    val node = PlannedErofsNode(
                        relPath = childRel,
                        name = child.name,
                        mode = 0x8000 or (if (isBin) 0x1ED else 0x1A4),
                        uid = 0,
                        gid = if (isBin) 2000 else 0,
                        isDir = false,
                        isSymlink = false,
                        sourceFile = child,
                        payloadSize = child.length()
                    )
                    parentNode.children.add(node)
                    allNodes.add(node)
                }
            }
        }

        scanTree(sourceDir, rootNode, "")

        // Assign sequential 32-byte NIDs starting at NID 0 (which sits at the start of META_BLK_ADDR = block 1)
        allNodes.forEachIndexed { idx, node ->
            node.nid = idx
        }
        rootNode.parentNid = rootNode.nid
        for (node in allNodes) {
            if (node.isDir) {
                for (child in node.children) {
                    child.parentNid = node.nid
                }
            }
        }

        // Build directory payloads with sorted dirents
        for (node in allNodes) {
            if (node.isDir) {
                node.dirPayloadBytes = buildErofsDirectoryBlocks(node.nid, node.parentNid, node.children)
                node.payloadSize = node.dirPayloadBytes.size.toLong()
            }
        }

        val totalMetaBytes = allNodes.size * INODE_SLOT_SIZE
        val metaBlocks = ((totalMetaBytes + BLOCK_SIZE - 1) / BLOCK_SIZE).coerceAtLeast(1)
        var currentDataBlock = META_BLK_ADDR + metaBlocks

        for (node in allNodes) {
            if (node.isDir) {
                val blks = (node.dirPayloadBytes.size + BLOCK_SIZE - 1) / BLOCK_SIZE
                node.rawBlkAddr = currentDataBlock
                node.blockCount = blks
                currentDataBlock += blks
            } else if (node.isSymlink) {
                val bytes = node.symlinkTarget.toByteArray(Charsets.UTF_8)
                node.payloadSize = bytes.size.toLong()
                if (bytes.isNotEmpty()) {
                    node.rawBlkAddr = currentDataBlock
                    node.blockCount = 1
                    currentDataBlock += 1
                }
            } else {
                val len = node.payloadSize
                if (len > 0L) {
                    val blks = ((len + BLOCK_SIZE - 1) / BLOCK_SIZE).toInt()
                    node.rawBlkAddr = currentDataBlock
                    node.blockCount = blks
                    currentDataBlock += blks
                } else {
                    node.rawBlkAddr = 0
                    node.blockCount = 0
                }
            }
        }

        val totalBlocks = (currentDataBlock + 16).coerceAtLeast(64)
        val totalImageBytes = totalBlocks.toLong() * BLOCK_SIZE

        onLog("[UKA-EROFS-BUILDER] Construction EROFS v1 (0xE0F5E1E2) : ${allNodes.size} inodes, $totalBlocks blocs (${totalImageBytes / 1024} KB)...")

        RandomAccessFile(targetImgFile, "rw").use { raf ->
            raf.setLength(totalImageBytes)

            // Write EROFS Superblock at offset 1024
            val sb = ByteBuffer.allocate(128).order(ByteOrder.LITTLE_ENDIAN)
            sb.putInt(0x00, EROFS_SUPER_MAGIC_V1) // magic = 0xE0F5E1E2
            sb.putInt(0x04, 0)                    // checksum
            sb.putInt(0x08, 0)                    // feature_compat
            sb.put(0x0C, 12.toByte())             // blkszbits = 12 (4096B)
            sb.put(0x0D, 0.toByte())              // sb_extslots
            sb.putShort(0x0E, rootNode.nid.toShort()) // root_nid = 0
            sb.putLong(0x10, allNodes.size.toLong())  // inos
            sb.putLong(0x18, System.currentTimeMillis() / 1000L) // build_time
            sb.putInt(0x20, 0)                    // build_time_nsec
            sb.putInt(0x24, totalBlocks)          // blocks
            sb.putInt(0x28, META_BLK_ADDR)        // meta_blkaddr = 1
            sb.putInt(0x2C, 0)                    // xattr_blkaddr = 0

            val uuid = UUID.nameUUIDFromBytes(volumeLabel.toByteArray())
            sb.position(0x30)
            sb.putLong(uuid.mostSignificantBits)
            sb.putLong(uuid.leastSignificantBits)

            val labelBytes = volumeLabel.toByteArray(Charsets.UTF_8).copyOf(16)
            sb.position(0x40)
            sb.put(labelBytes)

            raf.seek(EROFS_SUPER_OFFSET)
            raf.write(sb.array())

            // Write compact inodes at Block 1 (`META_BLK_ADDR`) and data blocks
            val copyBuf = ByteArray(65536)
            for (node in allNodes) {
                val inodeOffset = (META_BLK_ADDR.toLong() * BLOCK_SIZE) + (node.nid.toLong() * INODE_SLOT_SIZE)
                val ib = ByteBuffer.allocate(INODE_SLOT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
                ib.putShort(0x00, 0.toShort()) // i_format = 0 (Compact 32B, EROFS_INODE_FLAT_PLAIN)
                ib.putShort(0x02, 0.toShort()) // i_xattr_icount = 0
                ib.putShort(0x04, node.mode.toShort())
                ib.putShort(0x06, if (node.isDir) (2 + node.children.count { it.isDir }).toShort() else 1.toShort())
                ib.putInt(0x08, node.payloadSize.toInt())
                ib.putInt(0x0C, 0) // reserved
                ib.putInt(0x10, node.rawBlkAddr)
                ib.putInt(0x14, node.nid + 1) // i_ino
                ib.putShort(0x18, (node.uid and 0xFFFF).toShort())
                ib.putShort(0x1A, (node.gid and 0xFFFF).toShort())
                ib.putInt(0x1C, 0)

                raf.seek(inodeOffset)
                raf.write(ib.array())

                if (node.isDir && node.dirPayloadBytes.isNotEmpty()) {
                    raf.seek(node.rawBlkAddr.toLong() * BLOCK_SIZE)
                    raf.write(node.dirPayloadBytes)
                } else if (!node.isDir && !node.isSymlink && node.blockCount > 0 && node.sourceFile != null) {
                    raf.seek(node.rawBlkAddr.toLong() * BLOCK_SIZE)
                    node.sourceFile.inputStream().use { input ->
                        var r: Int
                        while (input.read(copyBuf).also { r = it } != -1) {
                            raf.write(copyBuf, 0, r)
                        }
                    }
                }
            }
        }

        onLog("[UKA-EROFS-BUILDER] Image EROFS valide générée : ${targetImgFile.absolutePath} (${targetImgFile.length() / 1024} KB)")
        targetImgFile.length()
    }

    private fun buildErofsDirectoryBlocks(
        selfNid: Int,
        parentNid: Int,
        children: List<PlannedErofsNode>
    ): ByteArray {
        data class ErofsDirEntry(val nid: Long, val name: String, val fileType: Int)

        val entries = mutableListOf<ErofsDirEntry>()
        entries.add(ErofsDirEntry(selfNid.toLong(), ".", 2))
        entries.add(ErofsDirEntry(parentNid.toLong(), "..", 2))
        for (c in children) {
            val ft = when {
                c.isDir -> 2
                c.isSymlink -> 7
                else -> 1
            }
            entries.add(ErofsDirEntry(c.nid.toLong(), c.name, ft))
        }
        // EROFS requires directory entries within each block to be sorted by name!
        val sorted = entries.sortedBy { it.name }

        val outBlocks = ByteArrayOutputStream()
        var index = 0
        while (index < sorted.size) {
            val blockEntries = mutableListOf<Pair<ErofsDirEntry, ByteArray>>()
            var headersBytes = 0
            var namesBytes = 0

            while (index < sorted.size) {
                val item = sorted[index]
                val nameBytes = item.name.toByteArray(Charsets.UTF_8)
                if (headersBytes + 12 + namesBytes + nameBytes.size > BLOCK_SIZE) break
                blockEntries.add(item to nameBytes)
                headersBytes += 12
                namesBytes += nameBytes.size
                index++
            }

            val block = ByteArray(BLOCK_SIZE)
            val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
            var currentNameOff = headersBytes
            for (i in blockEntries.indices) {
                val (entry, nameBytes) = blockEntries[i]
                val dPos = i * 12
                bb.putLong(dPos, entry.nid)
                bb.putShort(dPos + 8, currentNameOff.toShort())
                block[dPos + 10] = entry.fileType.toByte()
                block[dPos + 11] = 0
                System.arraycopy(nameBytes, 0, block, currentNameOff, nameBytes.size)
                currentNameOff += nameBytes.size
            }
            outBlocks.write(block)
        }
        return outBlocks.toByteArray()
    }
}
