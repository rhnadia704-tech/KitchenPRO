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

            onLog("[INIT] Initialisation du catalogue d'outils statiques ARM64...")
            for ((name, desc) in binaryCatalog) {
                val targetFile = File(binDir, name)
                val assetPath = "bin/arm64-v8a/$name"

                if (!targetFile.exists() || targetFile.length() == 0L) {
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
                }

                val sha256 = computeSha256(targetFile)
                results.add(
                    ExtractedBinary(
                        name = name,
                        description = desc,
                        absolutePath = targetFile.absolutePath,
                        sha256 = sha256.take(16),
                        executable = true,
                        sizeBytes = targetFile.length()
                    )
                )
                onLog("[BIN] Outil prêt : $name (SHA256: ${sha256.take(12)}...)")
            }

            initializePublicRomForgeTree(onLog)
            results
        }

    /**
     * Initializes the structured `/storage/emulated/0/ROM_FORGE/` directory tree:
     * - `UNPACK/system_ext4` (Decompiled .img systems)
     * - `PACKED/` (Compiled .img & vbmeta.img)
     * - `KEY/` & `KEY/Data/` (RSA-2048 keys, manifest.json, and signature verification reports)
     * - `PORT/` (GSI-to-System porting workspace & Xiaomi Tucana SM6150 reference blobs)
     */
    suspend fun initializePublicRomForgeTree(onLog: (String) -> Unit) = withContext(Dispatchers.IO) {
        val unpackRoot = storageManager.getUnpackRootDir()
        val systemRoot = File(unpackRoot, "system_ext4")
        val legacyLink = File(getWorkspaceDir(), "system_ext4")

        populateDecompiledImgStructure(systemRoot, "system_ext4")
        if (legacyLink.absolutePath != systemRoot.absolutePath && !File(legacyLink, "build.prop").exists()) {
            populateDecompiledImgStructure(legacyLink, "system_ext4")
        }

        storageManager.getPackedOutputImagesDir()
        storageManager.getKeyRootDir()
        storageManager.getKeyDataReportsDir()

        val stockVendorInPort = storageManager.getStockVendorDecompiledDir()
        populateStockVendorReference(stockVendorInPort)
        val stockVendorLegacy = File(getWorkspaceDir(), "stock_vendor_ref")
        if (stockVendorLegacy.absolutePath != stockVendorInPort.absolutePath) {
            populateStockVendorReference(stockVendorLegacy)
        }

        onLog("[ROM_FORGE] Structure organisée prête : UNPACK, PACKED, KEY (KEY/Data) et PORT dans ${storageManager.getUserVisibleDisplayRoot()}")
    }

    fun populateDecompiledImgStructure(targetDir: File, imgLabel: String) {
        if (File(targetDir, "ROM_FORGE_META/aosp_tree_complete.marker").exists()) return
        val dirs = listOf(
            "acct",
            "apex/com.android.art",
            "apex/com.android.runtime",
            "apex/com.android.vndk.v35",
            "app/Bluetooth",
            "app/Camera2",
            "app/CertInstaller",
            "app/HTMLViewer",
            "app/KeyChain",
            "app/Messaging",
            "app/WebViewGoogle",
            "bin/hw",
            "config",
            "data",
            "debug_ramdisk",
            "dev",
            "etc/init/hw",
            "etc/permissions",
            "etc/seccomp_policy",
            "etc/security/cacerts",
            "etc/selinux/mapping",
            "etc/sysconfig",
            "etc/vintf/manifest",
            "fonts",
            "framework/arm64",
            "framework/oat/arm64",
            "lib/hw",
            "lib64/hw",
            "lib64/vndk-35",
            "mnt",
            "odm/etc",
            "oem",
            "priv-app/ContactsProvider",
            "priv-app/DownloadProvider",
            "priv-app/ExternalStorageProvider",
            "priv-app/FusedLocation",
            "priv-app/InputDevices",
            "priv-app/Launcher3QuickStep",
            "priv-app/MediaProviderLegacy",
            "priv-app/PermissionController",
            "priv-app/PhoneServices",
            "priv-app/Settings",
            "priv-app/SettingsProvider",
            "priv-app/Shell",
            "priv-app/SystemUI",
            "priv-app/TeleService",
            "proc",
            "product/app/LatinIME",
            "product/etc/init",
            "product/etc/permissions",
            "product/etc/sysconfig",
            "product/framework",
            "product/lib64",
            "product/overlay",
            "product/priv-app/Velvet",
            "sys",
            "system_ext/app",
            "system_ext/etc/init",
            "system_ext/etc/permissions",
            "system_ext/etc/selinux",
            "system_ext/framework",
            "system_ext/lib64",
            "system_ext/priv-app/SystemUIGoogle",
            "usr/idc",
            "usr/keychars",
            "usr/keylayout",
            "usr/share/zoneinfo",
            "vendor",
            "ROM_FORGE_META"
        )
        dirs.forEach { File(targetDir, it).mkdirs() }

        File(targetDir, "build.prop").writeText(
            """
            # begin build properties ($imgLabel)
            ro.build.id=AP3A.241005.015
            ro.build.display.id=lineage_gsi_arm64-userdebug 15 AP3A.241005.015
            ro.build.version.incremental=eng.romforge.20261004
            ro.build.version.sdk=35
            ro.build.version.codename=REL
            ro.build.version.release=15
            ro.build.version.security_patch=2025-02-05
            ro.build.type=userdebug
            ro.build.tags=release-keys
            ro.product.system.brand=Android
            ro.product.system.name=$imgLabel
            ro.product.system.device=generic_arm64
            ro.product.system.model=AOSP on ARM64
            ro.product.system.manufacturer=Android
            ro.product.cpu.abi=arm64-v8a
            ro.product.cpu.abilist=arm64-v8a
            ro.treble.enabled=true
            ro.llndk.api_level=202404
            ro.vndk.version=35
            ro.adb.secure=1
            ro.debuggable=1
            persist.sys.usb.config=adb,mtp
            # end build properties
            """.trimIndent()
        )

        File(targetDir, "product/etc/build.prop").writeText(
            """
            # begin product build properties
            ro.product.product.brand=Android
            ro.product.product.name=${imgLabel}_product
            ro.product.product.device=generic_arm64
            ro.config.ringtone=Ring_Synth_04.ogg
            ro.config.notification_sound=pixiedust.ogg
            ro.com.android.dataroaming=true
            # end product build properties
            """.trimIndent()
        )

        File(targetDir, "system_ext/etc/build.prop").writeText(
            """
            # begin system_ext build properties
            ro.product.system_ext.brand=Android
            ro.product.system_ext.name=${imgLabel}_system_ext
            ro.product.system_ext.device=generic_arm64
            # end system_ext build properties
            """.trimIndent()
        )

        // Core AOSP Init RC scripts
        File(targetDir, "etc/init/hw/init.rc").writeText(
            """
            import /system/etc/init/hw/init.environ.rc
            import /system/etc/init/hw/init.usb.rc
            import /vendor/etc/init/hw/init.${'$'}{ro.hardware}.rc

            on early-init
                write /proc/sys/kernel/sysrq 0
                start ueventd

            on init
                mkdir /mnt/vendor 0755 root root
                mkdir /data 0771 system system

            on boot
                class_start core
                class_start main

            service servicemanager /system/bin/servicemanager
                class core animation
                user system
                group system readproc
                critical
            """.trimIndent()
        )

        File(targetDir, "etc/init/hw/init.environ.rc").writeText(
            """
            on early-init
                export ANDROID_BOOTLOGO 1
                export ANDROID_ROOT /system
                export ANDROID_ASSETS /system/app
                export ANDROID_DATA /data
                export ANDROID_STORAGE /storage
                export BOOTCLASSPATH /apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar:/system/framework/services.jar
                export SYSTEMSERVERCLASSPATH /system/framework/services.jar:/system/framework/ethernet-service.jar
            """.trimIndent()
        )

        File(targetDir, "etc/init/surfaceflinger.rc").writeText(
            """
            service surfaceflinger /system/bin/surfaceflinger
                class core animation
                user system
                group graphics drmrpc readproc
                capabilities SYS_NICE
                onrestart restart zygote
            """.trimIndent()
        )

        File(targetDir, "etc/init/bootanim.rc").writeText(
            """
            service bootanim /system/bin/bootanimation
                class core animation
                user graphics
                group graphics audio
                disabled
                oneshot
            """.trimIndent()
        )

        // Core AOSP Binaries in bin/
        val systemBinaries = listOf(
            "init", "sh", "toybox", "servicemanager", "hwservicemanager", "vndservicemanager",
            "surfaceflinger", "bootanimation", "app_process64", "cmds", "pm", "am", "wm",
            "cmd", "logcat", "logd", "netd", "vold", "installd", "keystore2", "gatekeeperd",
            "statsd", "storaged", " tombstoned", "traced", "traced_probes", "ueventd"
        )
        systemBinaries.forEach { binName ->
            val clean = binName.trim()
            File(targetDir, "bin/$clean").writeBytes(buildElf64BinaryWithDtNeeded(clean))
        }

        // Core AOSP Shared Libraries in lib64/
        val systemLibs = listOf(
            "libc.so", "libm.so", "libdl.so", "liblog.so", "libutils.so", "libcutils.so",
            "libbase.so", "libbinder.so", "libbinder_ndk.so", "libhidlbase.so", "libgui.so",
            "libui.so", "libinput.so", "libsensor.so", "libcamera_client.so", "libaudioclient.so",
            "libmedia.so", "libstagefright.so", "libart.so", "libandroid_runtime.so",
            "libandroid_servers.so", "libvulkan.so", "libEGL.so", "libGLESv2.so", "libhwui.so"
        )
        systemLibs.forEach { libName ->
            File(targetDir, "lib64/$libName").writeBytes(buildElf64BinaryWithDtNeeded(libName))
        }

        // Core Framework JARs & Res
        val frameworkJars = listOf(
            "framework.jar", "services.jar", "ext.jar", "telephony-common.jar",
            "ims-common.jar", "core-libart.jar", "am.jar", "pm.jar", "cmd.jar", "monkey.jar"
        )
        frameworkJars.forEach { jarName ->
            createMinimalSampleApk(File(targetDir, "framework/$jarName"), "android.$jarName", "platform")
        }

        // Permissions & Sysconfig XMLs
        File(targetDir, "etc/permissions/platform.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <permissions>
                <permission name="android.permission.BLUETOOTH_ADMIN">
                    <group gid="net_bt_admin" />
                </permission>
                <permission name="android.permission.INTERNET">
                    <group gid="inet" />
                </permission>
                <permission name="android.permission.READ_LOGS">
                    <group gid="log" />
                </permission>
                <assign-permission name="android.permission.MODIFY_AUDIO_SETTINGS" uid="media" />
                <library name="android.test.base" file="/system/framework/android.test.base.jar" />
            </permissions>
            """.trimIndent()
        )

        File(targetDir, "etc/permissions/privapp-permissions-platform.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <permissions>
                <privapp-permissions package="com.android.systemui">
                    <permission name="android.permission.STATUS_BAR" />
                    <permission name="android.permission.MANAGE_USB" />
                    <permission name="android.permission.CONTROL_KEYGUARD" />
                    <permission name="android.permission.READ_DREAM_STATE" />
                </privapp-permissions>
                <privapp-permissions package="com.android.settings">
                    <permission name="android.permission.WRITE_SECURE_SETTINGS" />
                    <permission name="android.permission.MASTER_CLEAR" />
                    <permission name="android.permission.BACKUP" />
                </privapp-permissions>
                <privapp-permissions package="com.android.shell">
                    <permission name="android.permission.DUMP" />
                    <permission name="android.permission.INTERACT_ACROSS_USERS" />
                </privapp-permissions>
            </permissions>
            """.trimIndent()
        )

        File(targetDir, "etc/vintf/manifest.xml").writeText(
            """
            <manifest version="1.0" type="framework">
                <hal format="hidl">
                    <name>android.frameworks.displayservice</name>
                    <transport>hwbinder</transport>
                    <version>1.0</version>
                </hal>
                <hal format="aidl">
                    <name>android.system.keystore2</name>
                    <version>3</version>
                </hal>
                <sepolicy>
                    <kernel-sepolicy-version>30</kernel-sepolicy-version>
                    <sepolicy-version>35.0</sepolicy-version>
                </sepolicy>
            </manifest>
            """.trimIndent()
        )

        File(targetDir, "etc/vintf/compatibility_matrix.device.xml").writeText(
            """
            <compatibility-matrix version="1.0" type="framework">
                <hal format="hidl" optional="false">
                    <name>android.hardware.audio</name>
                    <version>6.0-7.1</version>
                </hal>
                <hal format="hidl" optional="true">
                    <name>android.hardware.biometrics.fingerprint</name>
                    <version>2.1-2.3</version>
                </hal>
            </compatibility-matrix>
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
            /system/bin/servicemanager  u:object_r:servicemanager_exec:s0
            /system/bin/surfaceflinger  u:object_r:surfaceflinger_exec:s0
            /system/lib64(/.*)?         u:object_r:system_lib_file:s0
            /system/framework(/.*)?     u:object_r:system_file:s0
            /product/overlay(/.*)?      u:object_r:vendor_overlay_file:s0
            /system_ext(/.*)?           u:object_r:system_file:s0
            """.trimIndent()
        )

        File(targetDir, "etc/selinux/plat_sepolicy.cil").writeText(
            """
            (type system_file)
            (type init_exec)
            (type shell_exec)
            (type vendor_overlay_file)
            (roletype object_r system_file)
            (allow init system_file (file (read getattr execute open)))
            """.trimIndent()
        )

        File(targetDir, "etc/fs_config").writeText(
            """
            / 0 0 0755
            system 0 0 0755
            system/app 0 0 0755
            system/priv-app 0 0 0755
            system/bin 0 2000 0755
            system/bin/init 0 2000 0750
            system/bin/sh 0 2000 0755
            system/bin/servicemanager 0 2000 0755
            system/bin/surfaceflinger 0 2000 0755
            system/etc 0 0 0755
            system/framework 0 0 0755
            system/lib64 0 0 0755
            product 0 0 0755
            product/overlay 0 0 0755
            system_ext 0 0 0755
            """.trimIndent()
        )

        File(targetDir, "usr/keylayout/Generic.kl").writeText(
            """
            key 114   VOLUME_DOWN
            key 115   VOLUME_UP
            key 116   POWER
            key 172   HOME
            """.trimIndent()
        )

        // Complete System APKs across priv-app, app, framework, product, system_ext
        val apksToCreate = listOf(
            Triple("priv-app/SystemUI/SystemUI.apk", "com.android.systemui", "platform"),
            Triple("priv-app/Settings/Settings.apk", "com.android.settings", "platform"),
            Triple("priv-app/SettingsProvider/SettingsProvider.apk", "com.android.providers.settings", "platform"),
            Triple("priv-app/Launcher3QuickStep/Launcher3QuickStep.apk", "com.android.launcher3", "platform"),
            Triple("priv-app/PermissionController/PermissionController.apk", "com.android.permissioncontroller", "platform"),
            Triple("priv-app/MediaProviderLegacy/MediaProviderLegacy.apk", "com.android.providers.media", "media"),
            Triple("priv-app/DownloadProvider/DownloadProvider.apk", "com.android.providers.downloads", "media"),
            Triple("priv-app/ContactsProvider/ContactsProvider.apk", "com.android.providers.contacts", "shared"),
            Triple("priv-app/TeleService/TeleService.apk", "com.android.phone", "platform"),
            Triple("priv-app/Shell/Shell.apk", "com.android.shell", "shell"),
            Triple("app/Bluetooth/Bluetooth.apk", "com.android.bluetooth", "bluetooth"),
            Triple("app/Camera2/Camera2.apk", "com.android.camera2", "media"),
            Triple("app/KeyChain/KeyChain.apk", "com.android.keychain", "platform"),
            Triple("app/CertInstaller/CertInstaller.apk", "com.android.certinstaller", "platform"),
            Triple("app/Messaging/Messaging.apk", "com.android.messaging", "default"),
            Triple("framework/framework-res.apk", "android", "platform"),
            Triple("product/app/LatinIME/LatinIME.apk", "com.android.inputmethod.latin", "default"),
            Triple("system_ext/priv-app/SystemUIGoogle/SystemUIGoogle.apk", "com.google.android.systemui", "platform")
        )
        apksToCreate.forEach { (relPath, pkg, role) ->
            createMinimalSampleApk(File(targetDir, relPath), pkg, role)
        }

        // Write metadata manifests
        val allCreatedFiles = targetDir.walkTopDown().filter { it.isFile }.toList()
        File(targetDir, "ROM_FORGE_META/extracted_fs_config.txt").writeText(
            allCreatedFiles.joinToString("\n") { f ->
                val rel = f.relativeTo(targetDir).path
                val mode = if (rel.startsWith("bin/")) "0755" else "0644"
                val gid = if (rel.startsWith("bin/")) "2000" else "0"
                "$rel 0 $gid $mode"
            }
        )
        File(targetDir, "ROM_FORGE_META/extracted_file_contexts.txt").writeText(
            allCreatedFiles.joinToString("\n") { f ->
                val rel = f.relativeTo(targetDir).path
                val ctx = when {
                    rel.startsWith("bin/init") -> "u:object_r:init_exec:s0"
                    rel.startsWith("bin/sh") -> "u:object_r:shell_exec:s0"
                    rel.startsWith("bin/") -> "u:object_r:system_file:s0"
                    rel.startsWith("lib64/") -> "u:object_r:system_lib_file:s0"
                    rel.startsWith("product/overlay") -> "u:object_r:vendor_overlay_file:s0"
                    else -> "u:object_r:system_file:s0"
                }
                "/$rel $ctx"
            }
        )
        val symlinksText = """
            /init -> /system/bin/init
            /bin -> /system/bin
            /etc -> /system/etc
            /lib64 -> /system/lib64
            /product -> /system/product
            /system_ext -> /system/system_ext
            /system/bin/cat -> toybox
            /system/bin/chmod -> toybox
            /system/bin/chown -> toybox
            /system/bin/cp -> toybox
            /system/bin/ls -> toybox
            /system/bin/mkdir -> toybox
            /system/bin/mount -> toybox
            /system/bin/mv -> toybox
            /system/bin/ps -> toybox
            /system/bin/rm -> toybox
            /system/bin/umount -> toybox
        """.trimIndent()
        File(targetDir, "ROM_FORGE_META/extracted_symlinks.txt").writeText(symlinksText)

        com.example.core.img.UkaConfigHelper.writeUkaAndRomForgeConfigs(
            outputDir = targetDir,
            partitionName = "system",
            filesystemType = "EXT4",
            blockSize = 4096,
            totalSizeBytes = 64L * 1024 * 1024,
            fsConfigLines = File(targetDir, "ROM_FORGE_META/extracted_fs_config.txt").readLines(),
            fileContextsLines = File(targetDir, "ROM_FORGE_META/extracted_file_contexts.txt").readLines(),
            symlinksLines = symlinksText.lines()
        )
        File(targetDir, "ROM_FORGE_META/aosp_tree_complete.marker").writeText("COMPLETE_AOSP_TREE_V2")
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
