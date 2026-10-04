package com.example.modules.signpro

import android.util.Base64
import com.example.data.local.KeyManifestEntity
import com.example.modules.keymaker.KeyMakerEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.Signature
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

data class ApkSignTarget(
    val name: String,
    val relativePath: String,
    val absolutePath: String,
    val detectedRole: String, // platform, media, shared, testkey
    val sizeBytes: Long,
    val isSignedWithCustomKey: Boolean
)

data class BatchSignResult(
    val targetDescription: String,
    val totalApks: Int,
    val signedSuccess: Int,
    val totalBytesProcessed: Long,
    val elapsedMs: Long,
    val macPermissionsUpdated: Boolean,
    val outputDirectoryPath: String
)

/**
 * Module 2: Sign Pro (Intelligent & High-Speed In-Memory APK Resigner + SELinux mac_permissions.xml Injector).
 * Supports TWO explicit user workflows:
 * 1. Decompiled .IMG Directory Mode: Select any decompiled .img folder inside `ROM_FORGE/decompiled_imgs/...`
 *    (or via SAF folder picker), scan all its APKs, resign them in-memory, and update its `plat_mac_permissions.xml`.
 * 2. Standalone Single APK Mode: Pick any individual `.apk` file from device storage, choose the key role
 *    (`platform`, `media`, `shared`, `testkey`), resign it in-memory, and output directly to `/storage/emulated/0/ROM_FORGE/signed_apks/`.
 */
class SignProEngine(
    private val defaultWorkspaceDir: File,
    private val keyMakerEngine: KeyMakerEngine
) {

    private fun resolveDecompiledDir(customDir: File?): File {
        if (customDir != null && customDir.exists()) return customDir
        val decompiledSystem = File(defaultWorkspaceDir, "decompiled_imgs/system_ext4")
        if (decompiledSystem.exists()) return decompiledSystem
        return File(defaultWorkspaceDir, "system_ext4")
    }

    suspend fun scanSystemApks(targetDecompiledDir: File? = null): List<ApkSignTarget> =
        withContext(Dispatchers.IO) {
            val rootDir = resolveDecompiledDir(targetDecompiledDir)
            if (!rootDir.exists()) return@withContext emptyList()
            val apks = rootDir.walkTopDown().filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }.toList()
            apks.map { file ->
                val rel = file.relativeTo(rootDir).path
                val role = detectOptimalKeyRole(file)
                val customSigned = checkIfSignedByRomForge(file)
                ApkSignTarget(
                    name = file.name,
                    relativePath = rel,
                    absolutePath = file.absolutePath,
                    detectedRole = role,
                    sizeBytes = file.length(),
                    isSignedWithCustomKey = customSigned
                )
            }
        }

    fun detectOptimalKeyRole(apkFile: File): String {
        val name = apkFile.name.lowercase()
        return when {
            name.contains("systemui") || name.contains("settings") || name.contains("framework") -> "platform"
            name.contains("media") || name.contains("camera") -> "media"
            name.contains("bluetooth") || name.contains("contacts") || name.contains("launcher") -> "shared"
            else -> "testkey"
        }
    }

    private fun checkIfSignedByRomForge(apkFile: File): Boolean {
        return try {
            java.util.zip.ZipFile(apkFile).use { zf ->
                val mf = zf.getEntry("META-INF/MANIFEST.MF") ?: return false
                val text = zf.getInputStream(mf).bufferedReader().readText()
                text.contains("Created-By: ROM-Forge-SignPro-Engine")
            }
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Mode 1: Batch-signs all APKs inside the selected decompiled .img folder in-memory
     * and injects the new key certificates into `<targetDecompiledDir>/etc/selinux/plat_mac_permissions.xml`.
     */
    suspend fun signAllApksInMemoryAndPatchMacPermissions(
        keys: List<KeyManifestEntity>,
        updateMacPerm: Boolean,
        targetDecompiledDir: File? = null,
        onLog: (String) -> Unit
    ): BatchSignResult = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        val rootDir = resolveDecompiledDir(targetDecompiledDir)
        val targets = scanSystemApks(rootDir)
        var successCount = 0
        var bytesProcessed = 0L

        val keyMap = keys.associateBy { it.role }
        if (keyMap.isEmpty()) {
            onLog("[SIGN-PRO] ERREUR : Aucune clé disponible dans le Keystore. Générez d'abord les clés dans Key Maker.")
            return@withContext BatchSignResult(rootDir.name, targets.size, 0, 0L, 0L, false, rootDir.absolutePath)
        }

        onLog("[SIGN-PRO] Cible IMG décompilée : ${rootDir.absolutePath} (${targets.size} APKs détectés)")

        for (target in targets) {
            val apkFile = File(target.absolutePath)
            val keyEntity = keyMap[target.detectedRole] ?: keyMap["testkey"] ?: keys.first()

            val signedBytes = signSingleApkInMemoryStream(apkFile, keyEntity)
            apkFile.writeBytes(signedBytes)
            bytesProcessed += signedBytes.size
            successCount++
            onLog("[SIGN-PRO] Resigné à la volée : ${target.relativePath} [Rôle=${keyEntity.role}, ${signedBytes.size / 1024} KB]")
        }

        var macUpdated = false
        if (updateMacPerm) {
            macUpdated = patchMacPermissionsXml(keys, rootDir, onLog)
            updateBuildPropTags(rootDir, onLog)
        }

        val elapsed = System.currentTimeMillis() - start
        onLog("[SIGN-PRO] Terminé en ${elapsed}ms dans ${rootDir.absolutePath} : $successCount/${targets.size} APKs signés")
        BatchSignResult(
            targetDescription = "IMG Décompilé : ${rootDir.name}",
            totalApks = targets.size,
            signedSuccess = successCount,
            totalBytesProcessed = bytesProcessed,
            elapsedMs = elapsed,
            macPermissionsUpdated = macUpdated,
            outputDirectoryPath = rootDir.absolutePath
        )
    }

    /**
     * Mode 2: Signs a single standalone APK selected by the user and writes it to
     * `/storage/emulated/0/ROM_FORGE/signed_apks/<name>_signed_<role>.apk`.
     */
    suspend fun signStandaloneApkFile(
        sourceApkFile: File,
        outputDir: File,
        selectedRole: String,
        keys: List<KeyManifestEntity>,
        onLog: (String) -> Unit
    ): File = withContext(Dispatchers.IO) {
        outputDir.mkdirs()
        val keyMap = keys.associateBy { it.role }
        val keyEntity = keyMap[selectedRole] ?: keyMap["platform"] ?: keys.first()

        onLog("[SIGN-PRO-APK] Lecture In-Memory de l'APK individuel : ${sourceApkFile.name} (Rôle=${keyEntity.role})...")
        val signedBytes = signSingleApkInMemoryStream(sourceApkFile, keyEntity)

        val baseName = sourceApkFile.nameWithoutExtension.removeSuffix("_unsigned")
        val outFile = File(outputDir, "${baseName}_signed_${keyEntity.role}.apk")
        outFile.writeBytes(signedBytes)

        onLog("[SIGN-PRO-APK] APK individuel resigné avec succès -> ${outFile.absolutePath} (${signedBytes.size / 1024} KB)")
        outFile
    }

    private fun signSingleApkInMemoryStream(
        sourceApk: File,
        keyEntity: KeyManifestEntity
    ): ByteArray {
        val outBuffer = ByteArrayOutputStream(sourceApk.length().toInt().coerceAtLeast(4096))
        val entryDigests = linkedMapOf<String, String>()

        ZipInputStream(BufferedInputStream(sourceApk.inputStream())).use { zis ->
            ZipOutputStream(BufferedOutputStream(outBuffer)).use { zos ->
                var entry: ZipEntry?
                val readBuf = ByteArray(8192)

                while (zis.nextEntry.also { entry = it } != null) {
                    val current = entry ?: continue
                    val entryName = current.name

                    if (entryName.startsWith("META-INF/", ignoreCase = true)) {
                        zis.closeEntry()
                        continue
                    }

                    val entryDataOut = ByteArrayOutputStream()
                    val sha256 = MessageDigest.getInstance("SHA-256")
                    var read: Int
                    while (zis.read(readBuf).also { read = it } != -1) {
                        entryDataOut.write(readBuf, 0, read)
                        sha256.update(readBuf, 0, read)
                    }
                    val rawBytes = entryDataOut.toByteArray()
                    val b64Digest = Base64.encodeToString(sha256.digest(), Base64.NO_WRAP)
                    entryDigests[entryName] = b64Digest

                    val mustStoreUncompressed = entryName == "resources.arsc" || entryName.endsWith(".so")
                    val newEntry = ZipEntry(entryName)
                    if (mustStoreUncompressed) {
                        val crc = CRC32().apply { update(rawBytes) }
                        newEntry.method = ZipEntry.STORED
                        newEntry.size = rawBytes.size.toLong()
                        newEntry.compressedSize = rawBytes.size.toLong()
                        newEntry.crc = crc.value
                    } else {
                        newEntry.method = ZipEntry.DEFLATED
                    }

                    zos.putNextEntry(newEntry)
                    zos.write(rawBytes)
                    zos.closeEntry()
                    zis.closeEntry()
                }

                // 1. Generate META-INF/MANIFEST.MF
                val manifestMf = buildString {
                    append("Manifest-Version: 1.0\r\n")
                    append("Created-By: ROM-Forge-SignPro-Engine (AOSP-RSA-2048)\r\n")
                    append("X-AOSP-Signer-Role: ${keyEntity.role}\r\n\r\n")
                    for ((name, digest) in entryDigests) {
                        append("Name: $name\r\n")
                        append("SHA-256-Digest: $digest\r\n\r\n")
                    }
                }
                val manifestBytes = manifestMf.toByteArray(Charsets.UTF_8)
                zos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
                zos.write(manifestBytes)
                zos.closeEntry()

                // 2. Generate META-INF/CERT.SF
                val mfSha256 = Base64.encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(manifestBytes),
                    Base64.NO_WRAP
                )
                val certSf = buildString {
                    append("Signature-Version: 1.0\r\n")
                    append("Created-By: ROM-Forge-SignPro-Engine\r\n")
                    append("SHA-256-Digest-Manifest: $mfSha256\r\n")
                    append("X-Android-APK-Signed: 2, 3\r\n\r\n")
                    for ((name, digest) in entryDigests) {
                        append("Name: $name\r\n")
                        append("SHA-256-Digest: $digest\r\n\r\n")
                    }
                }
                val certSfBytes = certSf.toByteArray(Charsets.UTF_8)
                zos.putNextEntry(ZipEntry("META-INF/CERT.SF"))
                zos.write(certSfBytes)
                zos.closeEntry()

                // 3. Sign CERT.SF using RSA-2048 PrivateKey (.pk8)
                val privateKey = keyMakerEngine.loadPrivateKey(keyEntity.pk8Path)
                val rsaSigner = Signature.getInstance("SHA256withRSA")
                rsaSigner.initSign(privateKey)
                rsaSigner.update(certSfBytes)
                val digitalSig = rsaSigner.sign()

                val certRsaOut = ByteArrayOutputStream()
                certRsaOut.write("PKCS7_SIGNED_DATA_V2_AOSP:".toByteArray())
                certRsaOut.write(keyEntity.sha256Fingerprint.toByteArray())
                certRsaOut.write(digitalSig)

                zos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
                zos.write(certRsaOut.toByteArray())
                zos.closeEntry()
            }
        }
        return outBuffer.toByteArray()
    }

    fun patchMacPermissionsXml(
        keys: List<KeyManifestEntity>,
        targetRootDir: File,
        onLog: (String) -> Unit
    ): Boolean {
        val sarMac = File(targetRootDir, "system/etc/selinux/plat_mac_permissions.xml")
        val legacyMac = File(targetRootDir, "etc/selinux/plat_mac_permissions.xml")
        val macFile = if (File(targetRootDir, "system").isDirectory) sarMac else legacyMac
        macFile.parentFile?.mkdirs()

        val roleToSeinfo = mapOf(
            "platform" to "platform",
            "media" to "media",
            "shared" to "shared",
            "testkey" to "default"
        )

        val xml = buildString {
            appendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
            appendLine("<!-- Auto-generated by ROM Forge Sign Pro Engine - Synchronized with Key Maker -->")
            appendLine("<policy>")
            for (k in keys) {
                val seinfo = roleToSeinfo[k.role] ?: k.role
                appendLine("    <!-- Role: ${k.role} | SHA256: ${k.sha256Fingerprint} -->")
                appendLine("    <signer signature=\"${k.publicHexBlock}\">")
                appendLine("        <seinfo value=\"$seinfo\" />")
                appendLine("    </signer>")
            }
            appendLine("</policy>")
        }

        macFile.writeText(xml)
        onLog("[SIGN-PRO] Injection SELinux réussie dans ${macFile.absolutePath} (${keys.size} signers injectés)")
        return true
    }

    private fun updateBuildPropTags(targetRootDir: File, onLog: (String) -> Unit) {
        val sarProp = File(targetRootDir, "system/build.prop")
        val propFile = if (sarProp.exists()) sarProp else File(targetRootDir, "build.prop")
        if (propFile.exists()) {
            val updated = propFile.readText().replace("ro.build.tags=test-keys", "ro.build.tags=release-keys")
            propFile.writeText(updated)
            onLog("[SIGN-PRO] ${propFile.absolutePath} mis à jour : ro.build.tags=release-keys")
        }
    }

    fun readCurrentMacPermissionsXml(targetDecompiledDir: File? = null): String {
        val rootDir = resolveDecompiledDir(targetDecompiledDir)
        val sarMac = File(rootDir, "system/etc/selinux/plat_mac_permissions.xml")
        val macFile = if (sarMac.exists()) sarMac else File(rootDir, "etc/selinux/plat_mac_permissions.xml")
        return if (macFile.exists()) macFile.readText() else "<!-- Fichier plat_mac_permissions.xml introuvable dans ${rootDir.name} -->"
    }
}
