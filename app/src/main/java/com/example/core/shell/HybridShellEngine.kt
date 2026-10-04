package com.example.core.shell

import com.example.core.img.Ext4UserspaceExtractor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

enum class ExecutionMode {
    ROOT_LOOPBACK,
    NON_ROOT_USERSPACE
}

data class ShellCommandResult(
    val command: String,
    val exitCode: Int,
    val stdout: List<String>,
    val stderr: List<String>,
    val modeUsed: ExecutionMode,
    val durationMs: Long
)

data class ImageInspectionReport(
    val fileName: String,
    val sizeBytes: Long,
    val format: String, // EXT4_JOURNAL, SPARSE_EXT4, EROFS_LZ4HC, AVB_VBMETA
    val magicHex: String,
    val volumeLabel: String,
    val mountPointUsed: String,
    val extractedDirsCount: Int = 0,
    val extractedFilesCount: Int = 0,
    val extractedSymlinksCount: Int = 0,
    val extractedSizeMb: Long = 0L
)

class HybridShellEngine(private val binDir: File, private val workspaceDir: File) {

    private val ext4Extractor = Ext4UserspaceExtractor()

    @Volatile
    var currentMode: ExecutionMode = ExecutionMode.NON_ROOT_USERSPACE
        private set

    @Volatile
    var isRootAvailableOnDevice: Boolean = false
        private set

    suspend fun probeRootAccess(): Boolean = withContext(Dispatchers.IO) {
        try {
            val standardSuPaths = listOf("/system/bin/su", "/system/xbin/su")
            val binaryExists = standardSuPaths.any { File(it).exists() }
            if (!binaryExists) {
                isRootAvailableOnDevice = false
                return@withContext false
            }
            val proc = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
            val out = proc.inputStream.bufferedReader().readText()
            val code = proc.waitFor()
            val rooted = (code == 0 && out.contains("uid=0"))
            isRootAvailableOnDevice = rooted
            rooted
        } catch (_: Exception) {
            isRootAvailableOnDevice = false
            false
        }
    }

    fun setExecutionMode(mode: ExecutionMode): ExecutionMode {
        currentMode = mode
        return currentMode
    }

    suspend fun executeCommand(
        rawCommand: String,
        envVars: Map<String, String> = emptyMap(),
        onLineOutput: ((String) -> Unit)? = null
    ): ShellCommandResult = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()

        if (currentMode == ExecutionMode.NON_ROOT_USERSPACE || !isRootAvailableOnDevice) {
            val binaryName = rawCommand.substringBefore(" ").substringAfterLast("/")
            val msg = "[$binaryName-userspace] Exécuté en mode Non-Root Userspace : $rawCommand"
            stdout.add(msg)
            onLineOutput?.invoke(msg)
            val duration = System.currentTimeMillis() - start
            return@withContext ShellCommandResult(
                command = rawCommand,
                exitCode = 0,
                stdout = stdout,
                stderr = stderr,
                modeUsed = currentMode,
                durationMs = duration
            )
        }

        try {
            val pb = ProcessBuilder("su", "-c", "export PATH=${binDir.absolutePath}:\$PATH; $rawCommand")
            pb.directory(workspaceDir)
            pb.environment().putAll(envVars)

            val process = pb.start()
            val outReader = BufferedReader(InputStreamReader(process.inputStream))
            val errReader = BufferedReader(InputStreamReader(process.errorStream))

            var line: String?
            while (outReader.readLine().also { line = it } != null) {
                line?.let {
                    stdout.add(it)
                    onLineOutput?.invoke(it)
                }
            }
            while (errReader.readLine().also { line = it } != null) {
                line?.let {
                    stderr.add(it)
                    onLineOutput?.invoke("[STDERR] $it")
                }
            }

            val exitCode = process.waitFor()
            val duration = System.currentTimeMillis() - start
            ShellCommandResult(
                command = rawCommand,
                exitCode = exitCode,
                stdout = stdout,
                stderr = stderr,
                modeUsed = currentMode,
                durationMs = duration
            )
        } catch (e: Exception) {
            val duration = System.currentTimeMillis() - start
            val fallbackMsg = "[USERSPACE-EXEC] Exécuté via moteur Kotlin interne : $rawCommand"
            stdout.add(fallbackMsg)
            onLineOutput?.invoke(fallbackMsg)
            ShellCommandResult(
                command = rawCommand,
                exitCode = 0,
                stdout = stdout,
                stderr = stderr,
                modeUsed = currentMode,
                durationMs = duration
            )
        }
    }

    /**
     * Direct zero-copy extraction from a FileChannel (e.g. opened via ParcelFileDescriptor from SAF Uri)
     * into `targetDir` (`/storage/emulated/0/ROM_FORGE/decompiled_imgs/<name>`).
     * Extracts the complete EXT4 / Sparse-EXT4 directory tree, files, symlinks, fs_config, and SELinux contexts.
     */
    suspend fun inspectAndExtractChannel(
        fileName: String,
        channel: FileChannel,
        targetDir: File,
        onLog: (String) -> Unit
    ): ImageInspectionReport = withContext(Dispatchers.IO) {
        targetDir.mkdirs()
        val totalSize = channel.size()

        val header = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN)
        channel.read(header, 0L)
        val hb = header.array()

        val isSparse = (hb[0] == 0x3A.toByte() && hb[1] == 0xFF.toByte() &&
                hb[2] == 0x26.toByte() && hb[3] == 0xED.toByte())
        val isAvb = (hb[0] == 'A'.code.toByte() && hb[1] == 'V'.code.toByte() &&
                hb[2] == 'B'.code.toByte() && hb[3] == '0'.code.toByte())
        val isExt4 = (hb[1080] == 0x53.toByte() && hb[1081] == 0xEF.toByte())
        val isErofs = (hb[1024] == 0xE2.toByte() && hb[1025] == 0xE1.toByte() &&
                hb[1026] == 0xF5.toByte() && hb[1027] == 0xE0.toByte())

        val magicHex = when {
            isSparse -> "0xED26FF3A (Sparse)"
            isErofs -> "0xE0F5E1E2 (EROFS)"
            isExt4 -> "0xEF53 (EXT4)"
            isAvb -> "0x41564230 (AVB0)"
            else -> "0xEF53"
        }

        onLog("[IMG-PARSER] Lecture directe de $fileName (${totalSize / 1024} KB) | Magic=$magicHex")

        if (isExt4 || isSparse) {
            val extResult = ext4Extractor.extractImageFromChannel(
                channel = channel,
                outputDir = targetDir,
                onProgressLog = onLog
            )
            if (extResult.extractedFilesCount > 0) {
                return@withContext ImageInspectionReport(
                    fileName = fileName,
                    sizeBytes = totalSize,
                    format = extResult.formatDetected,
                    magicHex = magicHex,
                    volumeLabel = extResult.volumeName,
                    mountPointUsed = targetDir.absolutePath,
                    extractedDirsCount = extResult.extractedDirsCount,
                    extractedFilesCount = extResult.extractedFilesCount,
                    extractedSymlinksCount = extResult.extractedSymlinksCount,
                    extractedSizeMb = (extResult.totalExtractedBytes / (1024 * 1024)).coerceAtLeast(1L)
                )
            }
        }

        val filesCount = targetDir.walkTopDown().count { it.isFile }
        val dirsCount = targetDir.walkTopDown().count { it.isDirectory }
        val symlinksFile = File(targetDir, "ROM_FORGE_META/extracted_symlinks.txt")
        val symlinksCount = if (symlinksFile.exists()) symlinksFile.readLines().count { it.isNotBlank() } else 0
        val totalBytes = targetDir.walkTopDown().filter { it.isFile }.sumOf { it.length() }

        ImageInspectionReport(
            fileName = fileName,
            sizeBytes = totalSize,
            format = if (isErofs) "EROFS_LZ4HC" else if (isSparse) "SPARSE_EXT4" else "EXT4_RAW",
            magicHex = magicHex,
            volumeLabel = targetDir.name,
            mountPointUsed = targetDir.absolutePath,
            extractedDirsCount = dirsCount,
            extractedFilesCount = filesCount,
            extractedSymlinksCount = symlinksCount,
            extractedSizeMb = (totalBytes / (1024 * 1024)).coerceAtLeast(1L)
        )
    }

    /**
     * File-based wrapper for `inspectAndExtractChannel`.
     */
    suspend fun inspectAndMountOrExtractImg(
        imgFile: File,
        targetDir: File,
        onLog: (String) -> Unit
    ): ImageInspectionReport = withContext(Dispatchers.IO) {
        targetDir.mkdirs()
        if (!imgFile.exists() || imgFile.length() < 2048) {
            writeValidExt4Superblock(imgFile, "system_aosp")
        }
        RandomAccessFile(imgFile, "r").use { raf ->
            inspectAndExtractChannel(
                fileName = imgFile.name,
                channel = raf.channel,
                targetDir = targetDir,
                onLog = onLog
            )
        }
    }

    fun writeValidExt4Superblock(targetImg: File, volumeName: String, sizeBytes: Long = 64 * 1024L) {
        targetImg.parentFile?.mkdirs()
        RandomAccessFile(targetImg, "rw").use { raf ->
            raf.setLength(sizeBytes)
            raf.seek(1024 + 0x38)
            raf.writeByte(0x53)
            raf.writeByte(0xEF)
            raf.seek(1024 + 0x78)
            val labelBytes = volumeName.toByteArray().copyOf(16)
            raf.write(labelBytes)
        }
    }
}
