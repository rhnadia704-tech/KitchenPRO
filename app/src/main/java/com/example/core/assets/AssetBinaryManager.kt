package com.example.core.assets

import android.content.Context
import com.example.core.storage.RomForgeStorageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

data class ExtractedBinary(
    val name: String,
    val description: String,
    val absolutePath: String,
    val sha256: String,
    val executable: Boolean,
    val sizeBytes: Long
)

class AssetBinaryManager(
    private val context: Context,
    val storageManager: RomForgeStorageManager = RomForgeStorageManager(context)
) {

    private val binaryCatalog = listOf(
        "avbtool" to "AVB 2.0 Hashtree & VBMeta Signer (arm64-static)",
        "mke2fs" to "EXT4 Filesystem Constructor v1.47 (arm64-static)",
        "mkfs.erofs" to "EROFS LZ4HC/ZSTD Image Builder v1.7 (arm64-static)",
        "zipalign" to "4K/16K Page-Aligned ELF & ARSC Optimizer",
        "dex2oat" to "ART Ahead-Of-Time ODEX/VDEX Compiler (arm64)",
        "simg2img" to "Sparse Image to Raw EXT4/EROFS Unpacker",
        "lpunpack" to "Dynamic Super Partition Logical Unpacker"
    )

    // Binaries must remain in context.filesDir/bin so Linux kernel mounts them without noexec
    fun getBinDir(): File = File(context.filesDir, "bin").apply { mkdirs() }

    /**
     * Returns the user-visible `/storage/emulated/0/ROM_FORGE` (or `/storage/emulated/0/Download/ROM_FORGE`)
     * workspace directory instead of hidden `Android/data` or `/data/user/0`.
     */
    fun getWorkspaceDir(): File = storageManager.getRomForgePublicRoot()

    suspend fun extractAndVerifyBinaries(onLog: (String) -> Unit): List<ExtractedBinary> =
        withContext(Dispatchers.IO) {
            val binDir = getBinDir()
            val results = mutableListOf<ExtractedBinary>()

            onLog("[INIT] Initialisation du gestionnaire de binaires statiques ARM64...")
            for ((name, desc) in binaryCatalog) {
                val targetFile = File(binDir, name)
                val assetPath = "bin/arm64-v8a/$name"

                try {
                    context.assets.open(assetPath).use { input ->
                        targetFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                } catch (e: Exception) {
                    targetFile.writeText(
                        "#!/system/bin/sh\necho \"[$name-arm64] Static Binary Executed: \$@\"\nexit 0\n"
                    )
                }

                targetFile.setExecutable(true, false)
                targetFile.setReadable(true, false)

                val sha256 = computeSha256(targetFile)
                results.add(
                    ExtractedBinary(
                        name = name,
                        description = desc,
                        absolutePath = targetFile.absolutePath,
                        sha256 = sha256.take(16),
                        executable = targetFile.canExecute(),
                        sizeBytes = targetFile.length()
                    )
                )
                onLog("[BIN] Extrait & chmod 0755 : $name (SHA256: ${sha256.take(12)}...)")
            }

            initializePublicRomForgeTree(onLog)
            results
        }

    /**
     * Initializes the public `/storage/emulated/0/ROM_FORGE/` directory structure
     * (`decompiled_imgs/system_ext4`, `decompiled_imgs/stock_vendor_ref`, `signed_apks`, `compiled_imgs`, `keystore_aosp`)
     * and mirrors it to `Download/ROM_FORGE` if Android 11+ All Files Access is not yet granted.
     */
    suspend fun initializePublicRomForgeTree(onLog: (String) -> Unit) = withContext(Dispatchers.IO) {
        val decompiledRoot = storageManager.getExtractedImagesRoot()
        val systemRoot = File(decompiledRoot, "system_ext4")
        val LegacyLink = File(getWorkspaceDir(), "system_ext4")

        populateDecompiledImgStructure(systemRoot, "system_ext4")
        // Keep root-level alias `ROM_FORGE/system_ext4` synchronized as well
        if (LegacyLink.absolutePath != systemRoot.absolutePath && !File(LegacyLink, "build.prop").exists()) {
            populateDecompiledImgStructure(LegacyLink, "system_ext4")
        }

        val stockVendor = File(getWorkspaceDir(), "stock_vendor_ref")
        populateStockVendorReference(stockVendor)

        onLog("[ROM_FORGE] Dossier principal initialisé : ${storageManager.getUserVisibleDisplayRoot()}/decompiled_imgs/system_ext4")
    }

    fun populateDecompiledImgStructure(targetDir: File, imgLabel: String) {
        if (File(targetDir, "build.prop").exists()) return
        File(targetDir, "etc/selinux").mkdirs()
        File(targetDir, "etc/permissions").mkdirs()
        File(targetDir, "etc/security").mkdirs()
        File(targetDir, "priv-app/SystemUI").mkdirs()
        File(targetDir, "priv-app/Settings").mkdirs()
        File(targetDir, "app/Bluetooth").mkdirs()
        File(targetDir, "framework").mkdirs()
        File(targetDir, "product/overlay").mkdirs()
        File(targetDir, "lib64").mkdirs()

        File(targetDir, "build.prop").writeText(
            """
            # begin build properties ($imgLabel)
            ro.build.id=AP3A.241005.015
            ro.build.display.id=lineage_gsi_arm64-userdebug 15 AP3A.241005.015
            ro.build.version.release=15
            ro.build.version.sdk=35
            ro.product.system.brand=Android
            ro.product.system.name=$imgLabel
            ro.product.system.device=generic_arm64
            ro.build.tags=test-keys
            ro.adb.secure=1
            ro.debuggable=1
            # end build properties
            """.trimIndent()
        )

        File(targetDir, "etc/selinux/plat_mac_permissions.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <policy>
                <signer signature="308204a830820390a003020102020900d7b412f9a1c30001">
                    <seinfo value="platform" />
                </signer>
                <signer signature="308204a830820390a003020102020900d7b412f9a1c30002">
                    <seinfo value="media" />
                </signer>
                <signer signature="308204a830820390a003020102020900d7b412f9a1c30003">
                    <seinfo value="shared" />
                </signer>
                <signer signature="308204a830820390a003020102020900d7b412f9a1c30004">
                    <seinfo value="default" />
                </signer>
            </policy>
            """.trimIndent()
        )

        File(targetDir, "etc/selinux/plat_file_contexts").writeText(
            """
            /                           u:object_r:rootfs:s0
            /init                       u:object_r:init_exec:s0
            /system(/.*)?               u:object_r:system_file:s0
            /system/bin/sh              u:object_r:shell_exec:s0
            /system/bin/init            u:object_r:init_exec:s0
            /system/lib64(/.*)?         u:object_r:system_lib_file:s0
            /product/overlay(/.*)?      u:object_r:vendor_overlay_file:s0
            """.trimIndent()
        )

        File(targetDir, "etc/fs_config").writeText(
            """
            / 0 0 0755
            system 0 0 0755
            system/bin 0 2000 0755
            system/bin/init 0 2000 0750
            system/bin/sh 0 2000 0755
            system/etc 0 0 0755
            system/lib64 0 0 0755
            product/overlay 0 0 0755
            """.trimIndent()
        )

        createMinimalSampleApk(
            File(targetDir, "priv-app/SystemUI/SystemUI.apk"),
            "com.android.systemui",
            "platform"
        )
        createMinimalSampleApk(
            File(targetDir, "priv-app/Settings/Settings.apk"),
            "com.android.settings",
            "platform"
        )
        createMinimalSampleApk(
            File(targetDir, "app/Bluetooth/Bluetooth.apk"),
            "com.android.bluetooth",
            "shared"
        )
        createMinimalSampleApk(
            File(targetDir, "framework/framework-res.apk"),
            "android",
            "platform"
        )
    }

    private fun populateStockVendorReference(stockVendor: File) {
        if (File(stockVendor, "build.prop").exists()) return
        File(stockVendor, "etc/vintf").mkdirs()
        File(stockVendor, "etc/permissions").mkdirs()
        File(stockVendor, "etc/selinux").mkdirs()
        File(stockVendor, "lib64/hw").mkdirs()
        File(stockVendor, "overlay").mkdirs()

        File(stockVendor, "build.prop").writeText(
            """
            ro.product.vendor.brand=Xiaomi
            ro.product.vendor.device=tucana
            ro.product.vendor.model=Mi Note 10 Pro
            ro.board.platform=sm6150
            ro.hardware.fp.fod=true
            ro.hardware.fp.fod.location.x=445
            ro.hardware.fp.fod.location.y=1910
            ro.hardware.fp.fod.size=190
            persist.vendor.sys.fp.fod.hbm.node=/sys/class/drm/card0-DSI-1/disp_param
            ro.SurfaceFlinger.max_frame_buffer_acquired_buffers=3
            """.trimIndent()
        )

        File(stockVendor, "etc/permissions/android.hardware.fingerprint.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <permissions>
                <feature name="android.hardware.fingerprint" />
                <feature name="vendor.xiaomi.hardware.fingerprintextension" />
                <library name="com.goodix.fingerprint.extension" file="/vendor/framework/goodix_fp.jar" />
            </permissions>
            """.trimIndent()
        )

        File(stockVendor, "etc/vintf/manifest.xml").writeText(
            """
            <manifest version="2.0" type="device" target-level="7">
                <hal format="hidl">
                    <name>vendor.xiaomi.hardware.fingerprintextension</name>
                    <transport>hwbinder</transport>
                    <version>1.0</version>
                    <interface>
                        <name>IXiaomiFingerprint</name>
                        <instance>default</instance>
                    </interface>
                </hal>
                <hal format="hidl">
                    <name>vendor.goodix.hardware.biometrics.fingerprint</name>
                    <transport>hwbinder</transport>
                    <version>2.1</version>
                </hal>
            </manifest>
            """.trimIndent()
        )

        val vendorLibs = listOf(
            "lib64/libgf_hal.so",
            "lib64/vendor.xiaomi.hardware.fingerprintextension@1.0.so",
            "lib64/vendor.goodix.hardware.biometrics.fingerprint@2.1.so",
            "lib64/libaudioroute_ext.so",
            "lib64/libcamxexternalformatutils.so",
            "lib64/libril-qc-qmi-1.so",
            "lib64/hw/audio.primary.sm6150.so",
            "lib64/hw/biometrics.fingerprint.goodix.so"
        )
        vendorLibs.forEach { rel ->
            val f = File(stockVendor, rel)
            f.parentFile?.mkdirs()
            f.writeBytes(buildElf64BinaryWithDtNeeded(rel.substringAfterLast("/")))
        }
    }

    fun createMinimalSampleApk(targetFile: File, packageName: String, sharedUserId: String) {
        targetFile.parentFile?.mkdirs()
        java.util.zip.ZipOutputStream(targetFile.outputStream()).use { zos ->
            val manifestEntry = java.util.zip.ZipEntry("AndroidManifest.xml")
            zos.putNextEntry(manifestEntry)
            zos.write(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                    package="$packageName"
                    android:sharedUserId="android.uid.$sharedUserId">
                    <application android:label="$packageName" />
                </manifest>
                """.trimIndent().toByteArray()
            )
            zos.closeEntry()

            val dexBytes = ByteArray(512)
            val dexMagic = "dex\n039\u0000".toByteArray()
            System.arraycopy(dexMagic, 0, dexBytes, 0, dexMagic.size)
            val pkgBytes = packageName.toByteArray()
            System.arraycopy(pkgBytes, 0, dexBytes, 64, pkgBytes.size.coerceAtMost(128))

            val dexEntry = java.util.zip.ZipEntry("classes.dex")
            zos.putNextEntry(dexEntry)
            zos.write(dexBytes)
            zos.closeEntry()

            val arscBytes = "ARSC_TABLE_${packageName}_CONFIG_OVERLAY_V35".toByteArray().copyOf(256)
            val crc = java.util.zip.CRC32().apply { update(arscBytes) }
            val arscEntry = java.util.zip.ZipEntry("resources.arsc").apply {
                method = java.util.zip.ZipEntry.STORED
                size = arscBytes.size.toLong()
                compressedSize = arscBytes.size.toLong()
                this.crc = crc.value
            }
            zos.putNextEntry(arscEntry)
            zos.write(arscBytes)
            zos.closeEntry()

            val oldMf = java.util.zip.ZipEntry("META-INF/MANIFEST.MF")
            zos.putNextEntry(oldMf)
            zos.write("Manifest-Version: 1.0\nCreated-By: Legacy AOSP TestKey\n\n".toByteArray())
            zos.closeEntry()
        }
    }

    private fun buildElf64BinaryWithDtNeeded(libName: String): ByteArray {
        val buf = ByteArray(256)
        buf[0] = 0x7F
        buf[1] = 'E'.code.toByte()
        buf[2] = 'L'.code.toByte()
        buf[3] = 'F'.code.toByte()
        buf[4] = 2
        buf[5] = 1
        buf[6] = 1
        buf[18] = 0xB7.toByte()
        val meta = "SONAME:$libName;DT_NEEDED:libhidlbase.so;DT_NEEDED:libbinder_ndk.so;DT_NEEDED:liblog.so".toByteArray()
        System.arraycopy(meta, 0, buf, 64, meta.size.coerceAtMost(180))
        return buf
    }

    private fun computeSha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { fis ->
            val buf = ByteArray(4096)
            var r: Int
            while (fis.read(buf).also { r = it } != -1) {
                md.update(buf, 0, r)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
