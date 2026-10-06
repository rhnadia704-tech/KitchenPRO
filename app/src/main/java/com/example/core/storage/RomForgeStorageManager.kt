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
 * Organizes `/storage/emulated/0/ROM_FORGE/` (and `/storage/emulated/0/Download/ROM_FORGE/` in Non-Root mode)
 * into clean, structured workspace folders:
 * - `UNPACK/`    : Decompiled `.img` system/vendor/product directories (`ROM_FORGE/UNPACK/<system_name>/`)
 * - `PACKED/`    : Recompiled `.img` (EXT4/EROFS) and `vbmeta.img` files (`ROM_FORGE/PACKED/`)
 * - `KEY/`       : Generated RSA-2048 keys (`.x509.pem`, `.pk8`) + `manifest.json` ("Clé Note")
 * - `KEY/Data/`  : APK Signature Verification reports (`signature_audit_report.json` & `signature_audit_report.txt`)
 * - `PORT/`      : GSI-to-System Auto-Porter workspace, transplanted blobs, RRO overlays, FOD shims & ported `.img`
 */
class RomForgeStorageManager(private val context: Context) {

    private val prefs = context.getSharedPreferences("rom_forge_storage_prefs", Context.MODE_PRIVATE)

    fun hasAllFilesAccessPermission(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Environment.isExternalStorageManager()
            } else {
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    fun getRomForgePublicRoot(): File {
        if (hasAllFilesAccessPermission()) {
            try {
                val directRomForge = File(Environment.getExternalStorageDirectory(), "ROM_FORGE")
                if (directRomForge.exists() || directRomForge.mkdirs()) {
                    if (directRomForge.canWrite()) {
                        ensureSubfoldersExist(directRomForge)
                        return directRomForge
                    }
                }
            } catch (_: Exception) {
            }
        }
        val appExternal = context.getExternalFilesDir(null)
        if (appExternal != null) {
            val extRoot = File(appExternal, "ROM_FORGE").apply { mkdirs() }
            ensureSubfoldersExist(extRoot)
            return extRoot
        }
        val internalRoot = File(context.filesDir, "ROM_FORGE").apply { mkdirs() }
        ensureSubfoldersExist(internalRoot)
        return internalRoot
    }

    private fun ensureSubfoldersExist(root: File) {
        File(root, "UNPACK").mkdirs()
        File(root, "PACKED").mkdirs()
        File(root, "KEY/Data").mkdirs()
        File(root, "PORT").mkdirs()
    }

    fun getUserVisibleDisplayRoot(): String {
        return if (hasAllFilesAccessPermission()) {
            "/storage/emulated/0/ROM_FORGE"
        } else {
            "/storage/emulated/0/Download/ROM_FORGE"
        }
    }

    // 1. UNPACK folder (for decompiled .img systems)
    fun getUnpackRootDir(): File {
        val unpack = File(getRomForgePublicRoot(), "UNPACK").apply { mkdirs() }
        // Also migrate or include any legacy `decompiled_imgs` folders if present
        val legacy = File(getRomForgePublicRoot(), "decompiled_imgs")
        if (legacy.exists() && legacy.isDirectory) {
            legacy.listFiles()?.filter { it.isDirectory }?.forEach { dir ->
                val target = File(unpack, dir.name)
                if (!target.exists()) {
                    try {
                        dir.renameTo(target)
                    } catch (_: Exception) {
                    }
                }
            }
        }
        return unpack
    }

    fun getExtractedImagesRoot(): File = getUnpackRootDir()

    fun getDefaultSystemDecompiledDir(): File = File(getUnpackRootDir(), "system_ext4").apply { mkdirs() }

    fun getStockVendorDecompiledDir(): File = File(getPortWorkspaceRootDir(), "stock_vendor_ref").apply { mkdirs() }

    // 2. PACKED folder (for compiled .img and vbmeta.img)
    fun getPackedOutputImagesDir(): File = File(getRomForgePublicRoot(), "PACKED").apply { mkdirs() }

    fun getCompiledOutputImagesDir(): File = getPackedOutputImagesDir()

    // 3. KEY and KEY/Data folders
    fun getKeyRootDir(): File = File(getRomForgePublicRoot(), "KEY").apply { mkdirs() }

    fun getKeystorePublicDir(): File = getKeyRootDir()

    fun getKeyDataReportsDir(): File = File(getKeyRootDir(), "Data").apply { mkdirs() }

    // 4. PORT folder (for GSI porting workspace, modified files, and final ported images)
    fun getPortWorkspaceRootDir(): File = File(getRomForgePublicRoot(), "PORT").apply { mkdirs() }

    // Standalone signed APKs folder inside PACKED/signed_apks
    fun getSingleSignedApksDir(): File = File(getPackedOutputImagesDir(), "signed_apks").apply { mkdirs() }

    fun listDecompiledImgDirectories(): List<File> {
        val root = getUnpackRootDir()
        val children = root.listFiles()
            ?.filter { it.isDirectory && it.name != "stock_vendor_ref" }
            ?.sortedBy { it.name }
            ?: emptyList()
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
     * Mirrors a folder to `/storage/emulated/0/ROM_FORGE/<subFolderName>` (when All Files Access is granted)
     * or `/storage/emulated/0/Download/ROM_FORGE/<subFolderName>` via MediaStore.Downloads without root.
     */
    suspend fun mirrorDirectoryToPublicDownloadRomForge(
        sourceDir: File,
        subFolderName: String,
        onLog: (String) -> Unit
    ): String = withContext(Dispatchers.IO) {
        val normalizedSub = subFolderName
            .replace("decompiled_imgs/", "UNPACK/")
            .replace("compiled_imgs", "PACKED")
            .replace("keystore_aosp", "KEY")

        if (hasAllFilesAccessPermission()) {
            try {
                val directTarget = File(Environment.getExternalStorageDirectory(), "ROM_FORGE/$normalizedSub")
                directTarget.mkdirs()
                if (sourceDir.absolutePath != directTarget.absolutePath) {
                    sourceDir.copyRecursively(directTarget, overwrite = true)
                }
                onLog("[ROM_FORGE] Synchronisé dans : ${directTarget.absolutePath}")
                return@withContext directTarget.absolutePath
            } catch (_: Exception) {
            }
        }

        val localWorkspaceTarget = File(getRomForgePublicRoot(), normalizedSub).apply { mkdirs() }
        if (sourceDir.absolutePath != localWorkspaceTarget.absolutePath) {
            try {
                sourceDir.copyRecursively(localWorkspaceTarget, overwrite = true)
            } catch (_: Exception) {
            }
        }
        onLog("[ROM_FORGE] Dossier actif dans : ${localWorkspaceTarget.absolutePath}")
        localWorkspaceTarget.absolutePath
    }

    /**
     * Exports a single file to `/storage/emulated/0/ROM_FORGE/<subFolder>` (with All Files Access)
     * or the app's accessible external `ROM_FORGE/<subFolder>` workspace without triggering MediaStore SELinux audit bursts.
     */
    suspend fun exportSingleFileToPublicRomForge(
        sourceFile: File,
        subFolder: String,
        onLog: (String) -> Unit
    ): String = withContext(Dispatchers.IO) {
        val normalizedSub = subFolder
            .replace("compiled_imgs", "PACKED")
            .replace("signed_apks", "PACKED/signed_apks")
            .replace("keystore_aosp", "KEY")

        if (hasAllFilesAccessPermission()) {
            try {
                val directFolder = File(Environment.getExternalStorageDirectory(), "ROM_FORGE/$normalizedSub")
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

        val targetFolder = File(getRomForgePublicRoot(), normalizedSub).apply { mkdirs() }
        val dst = File(targetFolder, sourceFile.name)
        if (sourceFile.absolutePath != dst.absolutePath) {
            try {
                sourceFile.copyTo(dst, overwrite = true)
            } catch (_: Exception) {
            }
        }
        onLog("[ROM_FORGE] Fichier disponible dans : ${dst.absolutePath}")
        dst.absolutePath
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
                        onLog("[SAF-RESOLVER] Dossier sélectionné dans UNPACK : ${realFile.absolutePath}")
                        return@withContext realFile
                    }
                }
            } catch (_: Exception) {
            }
        }

        val target = File(getUnpackRootDir(), fallbackFolderName).apply { mkdirs() }
        onLog("[SAF-RESOLVER] Dossier lié dans UNPACK : ${target.absolutePath}")
        target
    }
}
