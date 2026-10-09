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
 *      - `/init` -> `/system/bin/init`
 *    - All real system files and nested symlinks (`/system/bin/sh -> toybox`, `/system/lib64/...`)
 *      live inside `unpackedRoot/system/...`.
 *
 * 2. **Flat / Legacy Layout**:
 *    - `unpackedRoot/build.prop`, `unpackedRoot/priv-app/`, `unpackedRoot/etc/` are directly at the root,
 *      and `unpackedRoot/system/` does not contain a nested `build.prop`.
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
     * that would break `/product -> /system/product` symlinks on a SAR image, while
     * strictly preserving all nested `/system/bin/...` and `/system/lib64/...` symlinks.
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

                // Heal any symlinks whose `system/` prefix was stripped by an earlier session on a SAR image
                // (e.g. `bin/cat -> toybox` when `bin` is a root symlink to `/system/bin` and `system/bin` is the real directory)
                var symlinksUpdated = false
                val migratedSymlinks = linkedMapOf<String, String>()
                val rootSarSymlinkNames = setOf("product", "system_ext", "bin", "etc", "lib64", "lib", "init", "odm", "vendor", "sdcard", "bugreports", "d")
                for ((linkRel, target) in symlinks) {
                    val firstSeg = linkRel.substringBefore("/")
                    val isSubPathUnderRootSymlink = linkRel.contains("/") &&
                            firstSeg in setOf("bin", "etc", "lib", "lib64", "product", "system_ext", "usr", "framework", "app", "priv-app") &&
                            !File(unpackedRoot, firstSeg).isDirectory &&
                            File(nestedSystemDir, firstSeg).isDirectory
                    if (isSubPathUnderRootSymlink) {
                        migratedSymlinks["system/$linkRel"] = target
                        symlinksUpdated = true
                    } else {
                        migratedSymlinks[linkRel] = target
                    }
                }
                if (symlinksUpdated) {
                    symlinks.clear()
                    symlinks.putAll(migratedSymlinks)
                }

                // Ensure canonical root-level SAR symlinks exist
                val canonicalSarSymlinks = mapOf(
                    "product" to "/system/product",
                    "system_ext" to "/system/system_ext",
                    "bin" to "/system/bin",
                    "etc" to "/system/etc",
                    "lib64" to "/system/lib64",
                    "init" to "/system/bin/init"
                )
                for ((linkRel, target) in canonicalSarSymlinks) {
                    if (!symlinks.containsKey(linkRel) && !File(unpackedRoot, linkRel).exists()) {
                        symlinks[linkRel] = target
                        symlinksUpdated = true
                    }
                }
                // Ensure `/config` directory exists at SAR root for `mount configfs none /config`
                File(unpackedRoot, "config").mkdirs()

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

    fun resolveSystemFile(unpackedRoot: File, logicalSystemSubPath: String): File {
        val topology = inspectAndResolve(unpackedRoot, autoHealSarConflicts = false)
        val cleanRel = logicalSystemSubPath.removePrefix("/").removePrefix("system/")
        return File(topology.systemBaseDir, cleanRel)
    }

    /**
     * Synchronizes both UKA `config/<partition>_fs_config` + `config/<partition>_file_contexts`
     * AND `system/etc/selinux/plat_file_contexts` + `ROM_FORGE_META/extracted_fs_config.txt` whenever files
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
                val dirMode = if (curDirRel.endsWith("bin") || curDirRel.endsWith("bin/hw")) "0 2000 0755" else "0 0 0755"
                val ukaDirEntry = "system/$curDirRel $dirMode capabilities=0x0"
                val metaDirEntry = "$curDirRel $dirMode capabilities=0x0"
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
            val metaFsEntry = "$relToUnpacked $uidGidMode capabilities=0x0"
            if (ukaFsLines.none { it.startsWith("system/$relToUnpacked ") }) ukaFsLines.add(ukaFsEntry)
            if (metaFsLines.none { it.startsWith("$relToUnpacked ") }) metaFsLines.add(metaFsEntry)

            val escapedUkaPath = UkaConfigHelper.escapeFileContextPath("/system/$relToUnpacked")
            val escapedDirectPath = UkaConfigHelper.escapeFileContextPath("/$relToUnpacked")
            val escapedLogicalPath = UkaConfigHelper.escapeFileContextPath("/" + relToUnpacked.removePrefix("system/"))
            if (ukaFcLines.none { it.startsWith("$escapedUkaPath ") }) {
                ukaFcLines.add("$escapedUkaPath $selinuxCtx")
            }
            if (escapedDirectPath != escapedUkaPath && ukaFcLines.none { it.startsWith("$escapedDirectPath ") }) {
                ukaFcLines.add("$escapedDirectPath $selinuxCtx")
            }
            if (platFcLines.none { it.startsWith("$escapedLogicalPath ") }) {
                platFcLines.add("$escapedLogicalPath $selinuxCtx")
            }
            if (topology.isSarLayout && platFcLines.none { it.startsWith("$escapedDirectPath ") }) {
                platFcLines.add("$escapedDirectPath $selinuxCtx")
            }
        }

        ukaFsFile.writeText(ukaFsLines.distinct().joinToString("\n") + "\n")
        ukaFcFile.writeText(ukaFcLines.distinct().joinToString("\n") + "\n")
        metaFsFile.writeText(metaFsLines.distinct().joinToString("\n") + "\n")
        // CRITICAL ANTI-BOOTLOOP FOR DSU SIDELOADER:
        // Never overwrite `platFcFile` (`/system/etc/selinux/plat_file_contexts`) if it already exists in the unpacked GSI!
        // Only write a fallback `plat_file_contexts` if none existed in the extracted image.
        if (!platFcFile.exists() && platFcFile.parentFile?.exists() == true) {
            platFcFile.writeText(platFcLines.distinct().joinToString("\n") + "\n")
        }

        onLog?.invoke(
            "[TOPOLOGY-SYNC] ${injectedFiles.size} fichier(s) enregistré(s) dans config/system_fs_config & system_file_contexts (plat_file_contexts d'origine 100% préservé)."
        )
    }

    /**
     * Reads all extracted symlinks while strictly preserving their exact relative path from `unpackedRoot`
     * (NEVER stripping `system/` from nested `/system/bin/...` or `/system/lib64/...` symlinks!).
     */
    private fun readExtractedSymlinks(unpackedRoot: File): Map<String, String> {
        val map = linkedMapOf<String, String>()
        // 1. Read from immutable baseline snapshot if present so original symlinks are 100% preserved
        val baseSnap = File(unpackedRoot, "ROM_FORGE_META/base_img_snapshot.txt")
        if (baseSnap.exists()) {
            baseSnap.useLines { lines ->
                lines.filter { it.startsWith("SYMLINK|") }.forEach { line ->
                    val p = line.split("|")
                    if (p.size >= 3) {
                        val left = p[1].trim().removePrefix("/")
                        val right = p[2].trim()
                        if (left.isNotEmpty() && right.isNotEmpty()) {
                            map[left] = right
                        }
                    }
                }
            }
        }
        // 2. Read from `ROM_FORGE_META/extracted_symlinks.txt`
        val symFile = File(unpackedRoot, "ROM_FORGE_META/extracted_symlinks.txt")
        if (symFile.exists()) {
            symFile.readLines().forEach { raw ->
                val line = raw.trim()
                if (line.contains("->")) {
                    val left = line.substringBefore("->").trim().removePrefix("/")
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
            "/${k.removePrefix("/")} -> $v"
        }
        symFile.writeText(content + "\n")
    }
}
