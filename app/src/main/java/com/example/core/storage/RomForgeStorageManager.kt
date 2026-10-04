package com.example.core.storage

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

data class StorageStatus(
    val publicRootPath: String,
    val isDirectStorageWritable: Boolean,
    val hasAllFilesAccess: Boolean,
    val customSafTreeUri: String?,
    val extractedImagesFolders: List<String>
)

/**
 * RomForgeStorageManager:
 * Manages `/storage/emulated/0/ROM_FORGE` and `/storage/emulated/0/Download/ROM_FORGE`
 * without triggering SELinux `avc: denied` audit rate-limit warnings on Android 11+ (API 30–36):
 * - Checks `Environment.isExternalStorageManager()` before performing raw `java.io.File` probes
 *   on `/storage/emulated/0/ROM_FORGE`.
 * - When `MANAGE_EXTERNAL_STORAGE` is granted, writes directly to `/storage/emulated/0/ROM_FORGE/`.
 * - When `MANAGE_EXTERNAL_STORAGE` is not yet granted, stages files cleanly and exports them
 *   via `MediaStore.Downloads` (`RELATIVE_PATH = Download/ROM_FORGE/...`) with zero permissions required.
 */
class RomForgeStorageManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("rom_forge_storage_prefs", Context.MODE_PRIVATE)

    fun hasAllFilesAccessPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }
    }

    /**
     * Returns the active working root directory without triggering unauthorized SELinux probes.
     * - If `hasAllFilesAccessPermission()` is true, uses `/storage/emulated/0/ROM_FORGE` directly.
     * - Otherwise, uses the internal staging `ROM_FORGE` directory and mirrors outputs to
     *   `/storage/emulated/0/Download/ROM_FORGE` via `MediaStore.Downloads`.
     */
    fun getRomForgePublicRoot(): File {
        if (hasAllFilesAccessPermission()) {
            try {
                val directRomForge = File(Environment.getExternalStorageDirectory(), "ROM_FORGE")
                if (directRomForge.exists() || directRomForge.mkdirs()) {
                    if (directRomForge.canWrite()) {
                        return directRomForge
                    }
                }
            } catch (_: Exception) {
            }
        }
        return File(context.filesDir, "ROM_FORGE").apply { mkdirs() }
    }

    /**
     * Human-readable display path shown in the UI so the user knows exactly where to find files
     * in their file manager (`/storage/emulated/0/ROM_FORGE` or `/storage/emulated/0/Download/ROM_FORGE`).
     */
    fun getUserVisibleDisplayRoot(): String {
        return if (hasAllFilesAccessPermission()) {
            "/storage/emulated/0/ROM_FORGE"
        } else {
            "/storage/emulated/0/Download/ROM_FORGE"
        }
    }

    fun getExtractedImagesRoot(): File = File(getRomForgePublicRoot(), "decompiled_imgs").apply { mkdirs() }

    fun getDefaultSystemDecompiledDir(): File = File(getExtractedImagesRoot(), "system_ext4").apply { mkdirs() }

    fun getStockVendorDecompiledDir(): File = File(getExtractedImagesRoot(), "stock_vendor_ref").apply { mkdirs() }

    fun getSingleSignedApksDir(): File = File(getRomForgePublicRoot(), "signed_apks").apply { mkdirs() }

    fun getCompiledOutputImagesDir(): File = File(getRomForgePublicRoot(), "compiled_imgs").apply { mkdirs() }

    fun getKeystorePublicDir(): File = File(getRomForgePublicRoot(), "keystore_aosp").apply { mkdirs() }

    fun listDecompiledImgDirectories(): List<File> {
        val root = getExtractedImagesRoot()
        val children = root.listFiles()?.filter { it.isDirectory }?.sortedBy { it.name } ?: emptyList()
        return if (children.isEmpty()) listOf(getDefaultSystemDecompiledDir()) else children
    }

    fun saveCustomSafTreeUri(uri: Uri) {
        prefs.edit().putString("saf_tree_uri", uri.toString()).apply()
    }

    fun getStorageStatus(): StorageStatus {
        val hasAccess = hasAllFilesAccessPermission()
        val displayRoot = getUserVisibleDisplayRoot()
        val folders = listDecompiledImgDirectories().map { it.name }
        return StorageStatus(
            publicRootPath = displayRoot,
            isDirectStorageWritable = hasAccess,
            hasAllFilesAccess = hasAccess,
            customSafTreeUri = prefs.getString("saf_tree_uri", null),
            extractedImagesFolders = folders
        )
    }

    /**
     * Exports a decompiled or modified directory to user-visible storage:
     * - Direct `/storage/emulated/0/ROM_FORGE/<subFolderName>` when All Files Access is enabled.
     * - Zero-permission `/storage/emulated/0/Download/ROM_FORGE/<subFolderName>` via `MediaStore.Downloads` otherwise.
     */
    suspend fun mirrorDirectoryToPublicDownloadRomForge(
        sourceDir: File,
        subFolderName: String,
        onLog: (String) -> Unit
    ): String = withContext(Dispatchers.IO) {
        if (hasAllFilesAccessPermission()) {
            try {
                val directTarget = File(Environment.getExternalStorageDirectory(), "ROM_FORGE/$subFolderName")
                directTarget.mkdirs()
                if (sourceDir.absolutePath != directTarget.absolutePath) {
                    sourceDir.copyRecursively(directTarget, overwrite = true)
                }
                onLog("[ROM_FORGE-STORAGE] Écrit directement dans : ${directTarget.absolutePath}")
                return@withContext directTarget.absolutePath
            } catch (_: Exception) {
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            var count = 0
            // Export key summary/manifest/APK files cleanly via MediaStore.Downloads without exceeding rate limits
            val filesToExport = sourceDir.walkTopDown().filter { it.isFile }.take(12).toList()
            for (file in filesToExport) {
                val relParent = file.parentFile?.relativeTo(sourceDir)?.path ?: ""
                val relativePath = if (relParent.isEmpty()) {
                    "${Environment.DIRECTORY_DOWNLOADS}/ROM_FORGE/$subFolderName"
                } else {
                    "${Environment.DIRECTORY_DOWNLOADS}/ROM_FORGE/$subFolderName/$relParent"
                }

                try {
                    val values = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, file.name)
                        put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
                    }
                    val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    if (uri != null) {
                        resolver.openOutputStream(uri)?.use { out ->
                            file.inputStream().use { input ->
                                input.copyTo(out)
                            }
                        }
                        count++
                    }
                } catch (_: Exception) {
                }
            }
            val publicDownloadPath = "/storage/emulated/0/Download/ROM_FORGE/$subFolderName"
            onLog("[BYPASS-NON-ROOT] $count fichiers exportés sans root vers $publicDownloadPath")
            return@withContext publicDownloadPath
        }

        sourceDir.absolutePath
    }

    /**
     * Exports a single file (e.g. a newly signed APK or compiled .img) to `/storage/emulated/0/ROM_FORGE/`
     * or `/storage/emulated/0/Download/ROM_FORGE/` without root.
     */
    suspend fun exportSingleFileToPublicRomForge(
        sourceFile: File,
        subFolder: String,
        onLog: (String) -> Unit
    ): String = withContext(Dispatchers.IO) {
        if (hasAllFilesAccessPermission()) {
            try {
                val directFolder = File(Environment.getExternalStorageDirectory(), "ROM_FORGE/$subFolder")
                directFolder.mkdirs()
                val dst = File(directFolder, sourceFile.name)
                if (sourceFile.absolutePath != dst.absolutePath) {
                    sourceFile.copyTo(dst, overwrite = true)
                }
                onLog("[ROM_FORGE] Fichier disponible dans : ${dst.absolutePath}")
                return@withContext dst.absolutePath
            } catch (_: Exception) {
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, sourceFile.name)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
                    put(
                        MediaStore.MediaColumns.RELATIVE_PATH,
                        "${Environment.DIRECTORY_DOWNLOADS}/ROM_FORGE/$subFolder"
                    )
                }
                val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri != null) {
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        sourceFile.inputStream().use { input -> input.copyTo(out) }
                    }
                    val pubPath = "/storage/emulated/0/Download/ROM_FORGE/$subFolder/${sourceFile.name}"
                    onLog("[BYPASS-NON-ROOT] Fichier écrit dans : $pubPath")
                    return@withContext pubPath
                }
            } catch (_: Exception) {
            }
        }
        sourceFile.absolutePath
    }

    suspend fun resolveOrImportSafDirectory(
        treeUri: Uri,
        fallbackFolderName: String,
        onLog: (String) -> Unit
    ): File = withContext(Dispatchers.IO) {
        if (hasAllFilesAccessPermission()) {
            try {
                val docId = DocumentsContract.getTreeDocumentId(treeUri)
                if (docId.startsWith("primary:")) {
                    val rel = docId.removePrefix("primary:")
                    val realFile = File(Environment.getExternalStorageDirectory(), rel)
                    if (realFile.exists() && realFile.isDirectory) {
                        onLog("[SAF-RESOLVER] Dossier cible sélectionné : ${realFile.absolutePath}")
                        return@withContext realFile
                    }
                }
            } catch (_: Exception) {
            }
        }

        val target = File(getExtractedImagesRoot(), fallbackFolderName).apply { mkdirs() }
        onLog("[SAF-RESOLVER] Dossier de travail lié à : ${target.absolutePath}")
        target
    }
}
