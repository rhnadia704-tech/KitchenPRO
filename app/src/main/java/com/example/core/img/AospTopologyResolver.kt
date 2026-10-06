package com.example.core.img

import java.io.File

/**
 * Autonomous AOSP Partition Topology & Symlink Resolver (`AospTopologyResolver`):
 *
 * Understands the difference between:
 * 1. **SAR (System-As-Root — Android 10/11/12/13/14/15 GSIs)**:
 *    - The root of the `.img` (`unpackedRoot/`) contains `system/`, `acct/`, `apex/`, `config/`,
 *      `data/`, `dev/`, `mnt/`, `odm/`, `oem/`, `proc/`, `sys/`, `vendor/`, and top-level symlinks:
 *      - `/product` -> `/system/product`
 *      - `/system_ext` -> `/system/system_ext`
 *      - `/bin` -> `/system/bin`
 *      - `/etc` -> `/system/etc`
 *      - `/lib64` -> `/system/lib64`
 *    - All real system files live inside `unpackedRoot/system/...`:
 *      - Overlays: `system/product/overlay/` (and `system/system_ext/overlay/`)
 *      - Init scripts: `system/etc/init/`
 *      - VINTF manifests: `system/etc/vintf/`
 *      - SELinux policies: `system/etc/selinux/`
 *      - Shared libraries: `system/lib64/`
 *      - Keylayouts: `system/usr/keylayout/`
 *      - Build properties: `system/build.prop` & `system/product/etc/build.prop`
 *    - **CRITICAL**: If a tool blindly writes to `unpackedRoot/product/overlay/` on a SAR image,
 *      it creates a real directory `/product` at the root that shadows or conflicts with the
 *      `/product -> /system/product` symlink, causing Android's `OverlayManagerService` to ignore
 *      the overlays at boot!
 *
 * 2. **Flat / Legacy Layout**:
 *    - `unpackedRoot/build.prop`, `unpackedRoot/priv-app/`, `unpackedRoot/etc/` are directly at the root,
 *      and `unpackedRoot/system/` does not contain a nested `build.prop`.
 *
 * This resolver inspects `unpackedRoot`, heals any accidental misplaced files in root `product/` or
 * `system_ext/` on SAR images by migrating them into `system/product/` and `system/system_ext/`,
 * restores the canonical `/product -> /system/product` and `/system_ext -> /system/system_ext` symlinks,
 * and returns the exact canonical paths for every partition component.
 */
data class AospTopologyReport(
    val unpackedRoot: File,
    val isSarLayout: Boolean,
    val layoutLabel: String,
    val systemBaseDir: File,        // unpackedRoot/system (SAR) or unpackedRoot (Flat)
    val systemPrefixRel: String,    // "system/" (SAR) or "" (Flat)
    val productDir: File,           // unpackedRoot/system/product (SAR) or unpackedRoot/product (Flat)
    val productOverlayDir: File,    // unpackedRoot/system/product/overlay (SAR) or unpackedRoot/product/overlay (Flat)
    val systemExtDir: File,         // unpackedRoot/system/system_ext (SAR) or unpackedRoot/system_ext (Flat)
    val etcDir: File,               // unpackedRoot/system/etc (SAR) or unpackedRoot/etc (Flat)
    val initRcDir: File,            // unpackedRoot/system/etc/init (SAR) or unpackedRoot/etc/init (Flat)
    val vintfDir: File,             // unpackedRoot/system/etc/vintf (SAR) or unpackedRoot/etc/vintf (Flat)
    val selinuxDir: File,           // unpackedRoot/system/etc/selinux (SAR) or unpackedRoot/etc/selinux (Flat)
    val permissionsDir: File,       // unpackedRoot/system/etc/permissions (SAR) or unpackedRoot/etc/permissions (Flat)
    val lib64Dir: File,             // unpackedRoot/system/lib64 (SAR) or unpackedRoot/lib64 (Flat)
    val keylayoutDir: File,         // unpackedRoot/system/usr/keylayout (SAR) or unpackedRoot/usr/keylayout (Flat)
    val mainBuildPropFile: File,    // unpackedRoot/system/build.prop (SAR) or unpackedRoot/build.prop (Flat)
    val symlinkMappings: Map<String, String>,
    val healedConflicts: List<String>
)

object AospTopologyResolver {

    /**
     * Detects whether `unpackedRoot` is a SAR (System-As-Root) image or a Flat image,
     * and optionally heals any misplaced root `product/` or `system_ext/` directories
     * that would break `/product -> /system/product` symlinks on a SAR image.
     */
    fun inspectAndResolve(
        unpackedRoot: File,
        autoHealSarConflicts: Boolean = true,
        onLog: ((String) -> Unit)? = null
    ): AospTopologyReport {
        val nestedSystemDir = File(unpackedRoot, "system")
        val hasNestedSystemContent = nestedSystemDir.isDirectory && (
                File(nestedSystemDir, "build.prop").exists() ||
                        File(nestedSystemDir, "priv-app").isDirectory ||
                        File(nestedSystemDir, "app").isDirectory ||
                        File(nestedSystemDir, "product").isDirectory ||
                        File(nestedSystemDir, "framework").isDirectory ||
                        File(nestedSystemDir, "etc").isDirectory
                )

        val symlinks = readExtractedSymlinks(unpackedRoot).toMutableMap()
        val hasSarSymlinks = symlinks["product"]?.contains("system/product") == true ||
                symlinks["bin"]?.contains("system/bin") == true ||
                File(unpackedRoot, "acct").isDirectory ||
                File(unpackedRoot, "oem").isDirectory

        val isSar = hasNestedSystemContent || (hasSarSymlinks && nestedSystemDir.isDirectory)
        val healedMessages = mutableListOf<String>()

        if (isSar) {
            nestedSystemDir.mkdirs()

            if (autoHealSarConflicts) {
                // Heal misplaced root-level directories that should live inside `system/` on SAR images
                val sarSubPartitionsToHeal = listOf("product", "system_ext", "etc", "lib64", "usr", "bin")
                for (subName in sarSubPartitionsToHeal) {
                    val rootLevelDir = File(unpackedRoot, subName)
                    val canonicalNestedDir = File(nestedSystemDir, subName)

                    // If a real directory exists at unpackedRoot/<subName> AND contains files, migrate them into unpackedRoot/system/<subName>
                    if (rootLevelDir.exists() && rootLevelDir.isDirectory) {
                        val filesInsideRootSub = rootLevelDir.walkTopDown().filter { it.isFile }.toList()
                        if (filesInsideRootSub.isNotEmpty()) {
                            canonicalNestedDir.mkdirs()
                            for (f in filesInsideRootSub) {
                                val rel = f.relativeTo(rootLevelDir).path
                                val dst = File(canonicalNestedDir, rel)
                                dst.parentFile?.mkdirs()
                                f.copyTo(dst, overwrite = true)
                            }
                            rootLevelDir.deleteRecursively()
                            val msg = "Migration SAR intelligente : ${filesInsideRootSub.size} fichier(s) déplacé(s) de /$subName/ vers /system/$subName/ (restauration du symlink /$subName -> /system/$subName)"
                            healedMessages.add(msg)
                            onLog?.invoke("[TOPOLOGY-HEAL] $msg")
                        } else if (subName in listOf("product", "system_ext", "bin", "etc", "lib64")) {
                            // Empty directory at root where a SAR symlink belongs: remove the empty dir so Ext4UserspaceBuilder writes the symlink!
                            rootLevelDir.deleteRecursively()
                        }
                    }
                }

                // Ensure canonical SAR symlinks are registered in extracted_symlinks.txt
                val canonicalSarSymlinks = mapOf(
                    "product" to "/system/product",
                    "system_ext" to "/system/system_ext",
                    "bin" to "/system/bin",
                    "etc" to "/system/etc",
                    "lib64" to "/system/lib64",
                    "init" to "/system/bin/init"
                )
                var symlinksUpdated = false
                for ((linkRel, target) in canonicalSarSymlinks) {
                    if (!symlinks.containsKey(linkRel) && !File(unpackedRoot, linkRel).exists()) {
                        symlinks[linkRel] = target
                        symlinksUpdated = true
                    }
                }
                if (symlinksUpdated || healedMessages.isNotEmpty()) {
                    saveExtractedSymlinks(unpackedRoot, symlinks)
                }
            }
        }

        val systemBase = if (isSar) nestedSystemDir else unpackedRoot
        val prefix = if (isSar) "system/" else ""

        val productDir = File(systemBase, "product")
        val productOverlayDir = File(productDir, "overlay")
        val systemExtDir = File(systemBase, "system_ext")
        val etcDir = File(systemBase, "etc")
        val initRcDir = File(etcDir, "init")
        val vintfDir = File(etcDir, "vintf")
        val selinuxDir = File(etcDir, "selinux")
        val permissionsDir = File(etcDir, "permissions")
        val lib64Dir = File(systemBase, "lib64")
        val keylayoutDir = File(systemBase, "usr/keylayout")
        val mainBuildProp = File(systemBase, "build.prop")

        val layoutLabel = if (isSar) {
            "System-As-Root (SAR Android 10-15 : /system/product/overlay & symlink /product -> /system/product)"
        } else {
            "Partition Plate / Directe (/product/overlay à la racine)"
        }

        return AospTopologyReport(
            unpackedRoot = unpackedRoot,
            isSarLayout = isSar,
            layoutLabel = layoutLabel,
            systemBaseDir = systemBase,
            systemPrefixRel = prefix,
            productDir = productDir,
            productOverlayDir = productOverlayDir,
            systemExtDir = systemExtDir,
            etcDir = etcDir,
            initRcDir = initRcDir,
            vintfDir = vintfDir,
            selinuxDir = selinuxDir,
            permissionsDir = permissionsDir,
            lib64Dir = lib64Dir,
            keylayoutDir = keylayoutDir,
            mainBuildPropFile = mainBuildProp,
            symlinkMappings = symlinks,
            healedConflicts = healedMessages
        )
    }

    /**
     * Resolves a logical system-relative path (e.g., `"product/overlay/TrebleHardwareOverlay.apk"`,
     * `"etc/init/init.tucana.fod.rc"`, `"lib64/libgf_hal.so"`) to its exact physical `File`
     * inside `unpackedRoot` according to whether the image is SAR (`system/...`) or Flat (`...`).
     */
    fun resolveSystemFile(unpackedRoot: File, logicalSystemSubPath: String): File {
        val topology = inspectAndResolve(unpackedRoot, autoHealSarConflicts = false)
        val cleanRel = logicalSystemSubPath.removePrefix("/").removePrefix("system/")
        return File(topology.systemBaseDir, cleanRel)
    }

    /**
     * Synchronizes both UKA `config/<partition>_fs_config` + `config/<partition>_file_contexts`
     * AND `system/etc/selinux/plat_file_contexts` + `system/etc/fs_config` whenever files
     * (like overlays, blobs, init.rc, keylayouts) are added or modified in `unpackedRoot`.
     */
    fun registerInjectedFilesInAllConfigs(
        unpackedRoot: File,
        injectedFiles: List<File>,
        onLog: ((String) -> Unit)? = null
    ) {
        val topology = inspectAndResolve(unpackedRoot, autoHealSarConflicts = false)
        val ukaConfigDir = File(unpackedRoot, "config").apply { mkdirs() }
        val metaDir = File(unpackedRoot, "ROM_FORGE_META").apply { mkdirs() }

        val ukaFsFile = File(ukaConfigDir, "system_fs_config")
        val ukaFcFile = File(ukaConfigDir, "system_file_contexts")
        val platFcFile = File(topology.selinuxDir, "plat_file_contexts")
        val metaFsFile = File(metaDir, "extracted_fs_config.txt")

        val ukaFsLines = if (ukaFsFile.exists()) ukaFsFile.readLines().toMutableList() else mutableListOf()
        val ukaFcLines = if (ukaFcFile.exists()) ukaFcFile.readLines().toMutableList() else mutableListOf()
        val platFcLines = if (platFcFile.exists()) platFcFile.readLines().toMutableList() else mutableListOf()
        val metaFsLines = if (metaFsFile.exists()) metaFsFile.readLines().toMutableList() else mutableListOf()

        for (file in injectedFiles) {
            if (!file.exists()) continue
            val relToUnpacked = file.relativeTo(unpackedRoot).invariantSeparatorsPath

            // Ensure parent directories are also registered
            val pathSegments = relToUnpacked.split("/")
            var curDirRel = ""
            for (i in 0 until pathSegments.lastIndex) {
                curDirRel = if (curDirRel.isEmpty()) pathSegments[i] else "$curDirRel/${pathSegments[i]}"
                val dirMode = if (curDirRel.endsWith("bin")) "0 2000 0755" else "0 0 0755"
                val ukaDirEntry = "system/$curDirRel $dirMode capabilities=0x0"
                val metaDirEntry = "$curDirRel $dirMode"
                if (ukaFsLines.none { it.startsWith("system/$curDirRel ") }) ukaFsLines.add(ukaDirEntry)
                if (metaFsLines.none { it.startsWith("$curDirRel ") }) metaFsLines.add(metaDirEntry)
            }

            val isBin = relToUnpacked.contains("/bin/") || relToUnpacked.startsWith("bin/")
            val uidGidMode = when {
                relToUnpacked.endsWith("bin/init") -> "0 2000 0750"
                isBin -> "0 2000 0755"
                else -> "0 0 0644"
            }

            val selinuxCtx = when {
                relToUnpacked.contains("overlay/") -> "u:object_r:vendor_overlay_file:s0"
                relToUnpacked.contains("lib64/hw/") -> "u:object_r:system_lib_file:s0"
                relToUnpacked.contains("lib64/") -> "u:object_r:system_lib_file:s0"
                relToUnpacked.endsWith(".rc") -> "u:object_r:system_file:s0"
                else -> "u:object_r:system_file:s0"
            }

            val ukaFsEntry = "system/$relToUnpacked $uidGidMode capabilities=0x0"
            val metaFsEntry = "$relToUnpacked $uidGidMode"
            if (ukaFsLines.none { it.startsWith("system/$relToUnpacked ") }) ukaFsLines.add(ukaFsEntry)
            if (metaFsLines.none { it.startsWith("$relToUnpacked ") }) metaFsLines.add(metaFsEntry)

            val escapedUkaPath = UkaConfigHelper.escapeFileContextPath("/system/$relToUnpacked")
            val escapedLogicalPath = UkaConfigHelper.escapeFileContextPath("/" + relToUnpacked.removePrefix("system/"))
            if (ukaFcLines.none { it.startsWith("$escapedUkaPath ") }) {
                ukaFcLines.add("$escapedUkaPath $selinuxCtx")
            }
            if (platFcLines.none { it.startsWith("$escapedLogicalPath ") }) {
                platFcLines.add("$escapedLogicalPath $selinuxCtx")
            }
            if (topology.isSarLayout && platFcLines.none { it.startsWith("$escapedUkaPath ") }) {
                platFcLines.add("$escapedUkaPath $selinuxCtx")
            }
        }

        ukaFsFile.writeText(ukaFsLines.distinct().joinToString("\n") + "\n")
        ukaFcFile.writeText(ukaFcLines.distinct().joinToString("\n") + "\n")
        metaFsFile.writeText(metaFsLines.distinct().joinToString("\n") + "\n")
        if (platFcFile.parentFile?.exists() == true) {
            platFcFile.writeText(platFcLines.distinct().joinToString("\n") + "\n")
        }

        onLog?.invoke(
            "[TOPOLOGY-SYNC] ${injectedFiles.size} fichier(s) enregistré(s) dans ${topology.systemPrefixRel}... + config/system_fs_config & system_file_contexts."
        )
    }

    private fun readExtractedSymlinks(unpackedRoot: File): Map<String, String> {
        val map = mutableMapOf<String, String>()
        val symFile = File(unpackedRoot, "ROM_FORGE_META/extracted_symlinks.txt")
        if (symFile.exists()) {
            symFile.readLines().forEach { raw ->
                val line = raw.trim()
                if (line.contains("->")) {
                    val left = line.substringBefore("->").trim().removePrefix("/").removePrefix("system/")
                    val right = line.substringAfter("->").trim()
                    if (left.isNotEmpty() && right.isNotEmpty()) {
                        map[left] = right
                    }
                }
            }
        }
        return map
    }

    private fun saveExtractedSymlinks(unpackedRoot: File, symlinks: Map<String, String>) {
        val metaDir = File(unpackedRoot, "ROM_FORGE_META").apply { mkdirs() }
        val symFile = File(metaDir, "extracted_symlinks.txt")
        val content = symlinks.entries.sortedBy { it.key }.joinToString("\n") { (k, v) ->
            "/$k -> $v"
        }
        symFile.writeText(content + "\n")
    }
}
