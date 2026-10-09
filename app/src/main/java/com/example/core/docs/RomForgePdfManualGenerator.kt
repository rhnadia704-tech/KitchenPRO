package com.example.core.docs

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.example.core.storage.RomForgeStorageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class GeneratedPdfDocResult(
    val pdfFile: File,
    val publishedDownloadPath: String?,
    val pageCount: Int,
    val sizeBytes: Long,
    val generatedAtLabel: String
)

/**
 * Generates the complete, structured, AI-auditable Technical Reference Manual & Architecture Blueprint PDF
 * (`ROM_Forge_Documentation_Complete_Architecture_IA_Audit.pdf`) using Android's native `PdfDocument` API.
 *
 * Includes:
 * 1. Exhaustive Description of Every Feature & Module (Unpack/Repack UKA v5.27, Repack Simple & Intelligent 1:1,
 *    FOD Fix Solution 1 & Solution 2, Sign PRO & Tout Signer Pro, R.E.C.O.R.E 12-Pillar Engine, AOSP OAT/VDEX/ODEX/fsv_meta
 *    Regenerator, Magisk PATCH, Hex Viewer, System App Debloater, VBMeta AVB 2.0 Generator).
 * 2. Complete Inventory of Internal Binary & Userspace Tools (`ExactImageCloneEngine`, `Ext4UserspaceExtractor`,
 *    `Ext4UserspaceBuilder`, `ErofsUserspaceBuilder`, `AospTopologyResolver`, `UkaConfigHelper`, `ArtGeneratorEngine`,
 *    `PayloadDumperEngine`, `LpUnpackEngine`, `BrotliSdatEngine`, `SignProEngine`, `RecoreEngine`, `AutoPorterEngine`).
 * 3. Step-by-Step User Manual (Manuel d'Utilisation Complet : DSU Sideloader, Unpack/Repack 1:1, FOD Fix 1 & 2, Sign Pro, R.E.C.O.R.E).
 * 4. Complete Application Structure & Source File Tree (`com.example.*` packages, classes, responsibilities, and lines of code)
 *    plus the `ROM_FORGE/` Workspace Tree (`UNPACK/`, `PACKED/`, `PORT/`, `ROM_FORGE_META/`, `config/`).
 * 5. Deep Technical Audit Notes for External AI Review (EXT4 Superblock `0xEF53`, `METADATA_CSUM`/`SHARED_BLOCKS` Copy-on-Write,
 *    HTree `0x00001000` handling, 256B Inode `security.selinux` `e_value_offs`, AVB 2.0 Footer truncation, and Stage 1 `secilc`/`libvintf` safety).
 */
object RomForgePdfManualGenerator {

    private const val PAGE_WIDTH = 595  // A4 width in PostScript points (72 dpi)
    private const val PAGE_HEIGHT = 842 // A4 height in PostScript points
    private const val MARGIN_H = 36f
    private const val MARGIN_TOP = 44f
    private const val MARGIN_BOTTOM = 42f
    private const val CONTENT_WIDTH = PAGE_WIDTH - (MARGIN_H * 2)

    suspend fun generateCompleteTechnicalManualPdf(
        context: Context,
        onLog: ((String) -> Unit)? = null
    ): GeneratedPdfDocResult = withContext(Dispatchers.IO) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val pdfDoc = PdfDocument()

        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(12, 24, 48)
            textSize = 17f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }
        val subtitlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(0, 110, 140)
            textSize = 10.5f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }
        val sectionHeaderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = 11f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }
        val subHeaderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(16, 48, 92)
            textSize = 10f
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }
        val bodyPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(30, 35, 45)
            textSize = 8.8f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }
        val monoPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(20, 60, 40)
            textSize = 8.0f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        }
        val footerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(110, 120, 135)
            textSize = 8f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }
        val bannerBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(18, 42, 76)
            style = Paint.Style.FILL
        }
        val codeBgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(243, 246, 250)
            style = Paint.Style.FILL
        }
        val codeBorderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.rgb(205, 215, 228)
            style = Paint.Style.STROKE
            strokeWidth = 0.8f
        }

        var currentPageNumber = 0
        var currentPage: PdfDocument.Page? = null
        var canvas: Canvas? = null
        var cursorY = MARGIN_TOP

        fun finishCurrentPage() {
            val page = currentPage ?: return
            val c = canvas ?: return
            // Draw page footer
            c.drawLine(MARGIN_H, PAGE_HEIGHT - 30f, PAGE_WIDTH - MARGIN_H, PAGE_HEIGHT - 30f, codeBorderPaint)
            c.drawText(
                "ROM Forge Kitchen Studio • Manuel Technique, Architecture & Audit IA • Généré le $timestamp",
                MARGIN_H,
                PAGE_HEIGHT - 18f,
                footerPaint
            )
            val pgLabel = "Page $currentPageNumber"
            val pgW = footerPaint.measureText(pgLabel)
            c.drawText(pgLabel, PAGE_WIDTH - MARGIN_H - pgW, PAGE_HEIGHT - 18f, footerPaint)
            pdfDoc.finishPage(page)
            currentPage = null
            canvas = null
        }

        fun startNewPage() {
            finishCurrentPage()
            currentPageNumber++
            val pageInfo = PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, currentPageNumber).create()
            val page = pdfDoc.startPage(pageInfo)
            currentPage = page
            canvas = page.canvas
            cursorY = MARGIN_TOP
        }

        fun ensureSpace(neededHeight: Float) {
            if (currentPage == null || cursorY + neededHeight > PAGE_HEIGHT - MARGIN_BOTTOM) {
                startNewPage()
            }
        }

        fun wrapLines(text: String, paint: Paint, maxWidth: Float): List<String> {
            val out = mutableListOf<String>()
            for (rawParagraph in text.split("\n")) {
                if (rawParagraph.isEmpty()) {
                    out.add("")
                    continue
                }
                val words = rawParagraph.split(" ")
                var currentLine = StringBuilder()
                for (w in words) {
                    val candidate = if (currentLine.isEmpty()) w else "$currentLine $w"
                    if (paint.measureText(candidate) <= maxWidth) {
                        currentLine = StringBuilder(candidate)
                    } else {
                        if (currentLine.isNotEmpty()) {
                            out.add(currentLine.toString())
                        }
                        // If a single word/path is wider than maxWidth, split it by characters
                        if (paint.measureText(w) > maxWidth) {
                            var chunk = StringBuilder()
                            for (ch in w) {
                                if (paint.measureText("$chunk$ch") <= maxWidth) {
                                    chunk.append(ch)
                                } else {
                                    out.add(chunk.toString())
                                    chunk = StringBuilder(ch.toString())
                                }
                            }
                            currentLine = chunk
                        } else {
                            currentLine = StringBuilder(w)
                        }
                    }
                }
                if (currentLine.isNotEmpty()) {
                    out.add(currentLine.toString())
                }
            }
            return out
        }

        fun drawSectionBanner(number: String, title: String) {
            ensureSpace(32f)
            cursorY += 6f
            val c = canvas!!
            val rect = RectF(MARGIN_H, cursorY, PAGE_WIDTH - MARGIN_H, cursorY + 22f)
            c.drawRoundRect(rect, 4f, 4f, bannerBgPaint)
            c.drawText("$number. $title", MARGIN_H + 10f, cursorY + 15f, sectionHeaderPaint)
            cursorY += 30f
        }

        fun drawSubHeader(title: String) {
            ensureSpace(20f)
            cursorY += 4f
            canvas!!.drawText(title, MARGIN_H, cursorY + 10f, subHeaderPaint)
            cursorY += 15f
        }

        fun drawParagraph(text: String) {
            val lines = wrapLines(text, bodyPaint, CONTENT_WIDTH)
            for (line in lines) {
                ensureSpace(13f)
                canvas!!.drawText(line, MARGIN_H, cursorY + 9f, bodyPaint)
                cursorY += 12.2f
            }
            cursorY += 3f
        }

        fun drawBulletList(items: List<String>) {
            for (item in items) {
                val lines = wrapLines(item, bodyPaint, CONTENT_WIDTH - 14f)
                for ((idx, line) in lines.withIndex()) {
                    ensureSpace(13f)
                    if (idx == 0) {
                        canvas!!.drawText("•", MARGIN_H + 2f, cursorY + 9f, subHeaderPaint)
                    }
                    canvas!!.drawText(line, MARGIN_H + 14f, cursorY + 9f, bodyPaint)
                    cursorY += 12.0f
                }
                cursorY += 2f
            }
        }

        fun drawCodeOrTreeBlock(lines: List<String>) {
            val wrapped = mutableListOf<String>()
            for (l in lines) {
                wrapped.addAll(wrapLines(l, monoPaint, CONTENT_WIDTH - 16f))
            }
            var idx = 0
            while (idx < wrapped.size) {
                val availH = (PAGE_HEIGHT - MARGIN_BOTTOM) - cursorY
                val maxLinesInPage = ((availH - 12f) / 10.5f).toInt()
                if (maxLinesInPage < 3) {
                    startNewPage()
                    continue
                }
                val chunk = wrapped.subList(idx, (idx + maxLinesInPage).coerceAtMost(wrapped.size))
                val boxH = chunk.size * 10.5f + 10f
                val c = canvas!!
                val rect = RectF(MARGIN_H, cursorY, PAGE_WIDTH - MARGIN_H, cursorY + boxH)
                c.drawRoundRect(rect, 4f, 4f, codeBgPaint)
                c.drawRoundRect(rect, 4f, 4f, codeBorderPaint)
                var textY = cursorY + 11f
                for (cl in chunk) {
                    c.drawText(cl, MARGIN_H + 8f, textY, monoPaint)
                    textY += 10.5f
                }
                cursorY += boxH + 6f
                idx += chunk.size
            }
        }

        // Start Page 1: Cover & Document Header
        startNewPage()
        canvas!!.drawText("ROM FORGE KITCHEN STUDIO — DOCUMENTATION TECHNIQUE COMPLÈTE", MARGIN_H, cursorY + 14f, titlePaint)
        cursorY += 22f
        canvas!!.drawText(
            "Spécification Exhaustive des Fonctionnalités, Outils Internes, Manuel d'Utilisation, Arborescence & Audit IA (DSU / EXT4 / R.E.C.O.R.E)",
            MARGIN_H,
            cursorY + 10f,
            subtitlePaint
        )
        cursorY += 18f
        drawParagraph(
            "Ce document technique de référence détaille l'intégralité de l'architecture logicielle, des moteurs bas-niveau, " +
                    "des algorithmes de manipulation d'images système Android (EXT4, EROFS, Sparse, payload.bin, super.img), " +
                    "du moteur de clonage 1:1 et de greffe chirurgicale In-Place (ExactImageCloneEngine), des deux solutions FOD Fix " +
                    "(Solution 1 & Solution 2 Sans Re-signature), de Sign PRO et du moteur déterministe R.E.C.O.R.E à 12 Piliers. " +
                    "Il est conçu à la fois comme manuel d'utilisation complet et comme dossier d'audit technique pour revue par une IA externe."
        )

        // =========================================================================
        // SECTION 1: DESCRIPTION EXHAUSTIVE DE CHAQUE FONCTIONNALITÉ
        // =========================================================================
        drawSectionBanner("1", "DESCRIPTION EXHAUSTIVE DE CHAQUE FONCTIONNALITÉ DE L'APPLICATION")

        drawSubHeader("1.1. Unpack Universel UKA v5.27 & Snapshot Immuable (Onglet 1 : Extract / Unpack)")
        drawBulletList(
            listOf(
                "Formats supportés en entrée : payload.bin (OTA A/B Android 10–15), super.img (Dynamic Partitions LP Metadata Geometry), system.new.dat.br (Brotli + transfer.list), Sparse .img (magic 0xED26FF3A) et Raw EXT4 .img (magic 0xEF53 à l'offset 1024).",
                "Conversion Sparse -> Raw (simg2img 64-bit) : Décodage exact des chunks CHUNK_TYPE_RAW (0xCAC1), CHUNK_TYPE_FILL (0xCAC2) et CHUNK_TYPE_DONT_CARE (0xCAC3) par transfert FileChannel zéro-copie.",
                "Extraction Userspace EXT4 complète (Ext4UserspaceExtractor) : Parcours récursif depuis l'inode racine #2 (supportant les arbres d'extents depth 0..5, les répertoires indexés HTree, les liens symboliques inline <= 60 octets et externes > 60 octets, les permissions POSIX UID/GID/Mode et les attributs étendus xattr security.selinux & security.capability).",
                "Capture du Snapshot Immuable de Base : Génère simultanément les tables officielles UKA v5.27 (config/system_fs_config, config/system_file_contexts, config/system_size.txt, config/system_space.txt, config/system_avb_footer.bin) ET le snapshot immuable ROM_FORGE_META/base_img_snapshot.txt + ROM_FORGE_META/exact_inode_extents_map.txt + ROM_FORGE_META/source_img_ref.txt."
            )
        )

        drawSubHeader("1.2. Repack Simple & Intelligent 1:1 (Bouton dédié & Pipeline DSU Sideloader)")
        drawBulletList(
            listOf(
                "Objectif : Garantir qu'une image .img décompressée puis recompressée sans modification ressorte à 100% bit-à-bit identique à l'image de départ, et qu'une image modifiée conserve 100% des structures EXT4 d'origine des fichiers non touchés.",
                "Cas A — Zéro modification détectée (changedPaths=0, addedPaths=0, deletedPaths=0) : Clone / dé-sparse directement le flux binaire d'origine (source_img_ref.txt) 1:1 dans PACKED/system_repacked_1to1.img. Tous les blocs partagés (EXT4_FEATURE_RO_COMPAT_SHARED_BLOCKS 0x4000 générés par e2fsdroid -s), les index de répertoires HTree, les inodes 256 octets et le footer AVB 2.0 sont préservés à l'octet près.",
                "Cas B — Modifications ciblées ou ajouts de fichiers (ex: FOD Fix Solution 2, R.E.C.O.R.E Auto-Heal) : Exécute une mutation chirurgicale In-Place avec Copy-On-Write (CoW) sur le clone 1:1 de l'image de base via ExactImageCloneEngine."
            )
        )

        drawSubHeader("1.3. FOD Fix — Deux Solutions Complètes (Onglet 2 : Porter / FOD Fix)")
        drawBulletList(
            listOf(
                "FOD Fix Solution 2 (RECOMMANDÉ • Sans Modifier ni Re-signer les APKs + Repack Simple & Intelligent 1:1) : Ne touche à AUCUN APK existant (0 modification de framework-res.apk ou SystemUI.apk, 0 re-signature v1/v2/v3, 0 invalidation des .odex/.vdex/.art). Injecte chirurgicalement sur le clone 1:1 de l'image de base : (1) le script d'initialisation /system/etc/init/init.tucana.fod.rc (droits sysfs HBM 0x20000 sur /sys/class/drm/card0-DSI-1/disp_param, fod_ui_ready, /dev/goodix_fp, /sys/devices/virtual/touch/tp_dev/fod_status), (2) le keylayout /system/usr/keylayout/uinput-goodix.kl (key 338 SYSTEM_NAVIGATION_UP), (3) la configuration système /system/etc/sysconfig/xiaomi_tucana_fod_config.xml, et (4) les propriétés biométriques PHH-Treble/Xiaomi dans build.prop (ro.hardware.fp.fod=true, persist.sys.phh.fod.xiaomi=true, persist.vendor.sys.fp.fod.location.X_Y=445,1910, persist.vendor.sys.fp.fod.size.width_height=190,190).",
                "Protection Anti-Bootloop Stage 1 & Stage 2 intégrée au FOD Fix Solution 2 : Préserve à 100% /system/etc/vintf/manifest.xml (aucune injection de HAL vendor.* dans un manifeste type='framework' qui bloquerait libvintf/hwservicemanager), préserve à 100% /system/etc/selinux/ (aucun fichier .cil conflictuel qui ferait échouer secilc au Stage 1 init, ni écrasement de plat_file_contexts), et n'injecte aucun binaire ELF stub de 256 octets ni APK non compilé par aapt2 dans /system/product/overlay/.",
                "FOD Fix Solution 1 (Patch APK In-Place + Régénération AOSP OAT/VDEX/ODEX + Cascade de Confiance R.E.C.O.R.E) : Enrichit framework-res.apk et SystemUI.apk avec un chunk binaire AXML aligné 4-octets (RES_XML_TYPE 0x0003) en conservant resources.arsc en mode STORED non compressé, puis régénère automatiquement les fichiers .odex, .vdex et .fsv_meta dépendants via ArtGeneratorEngine."
            )
        )

        drawSubHeader("1.4. Sign PRO Intelligent & Tout Signer Pro (Onglet 4 : Sign Pro)")
        drawBulletList(
            listOf(
                "Cartographie du Graphe de Signatures de Base : Scanne tous les APKs et conteneurs APEX de l'image décompressée, identifie le certificat X.509 (SHA-256) de chaque APK et les regroupe en clusters de clés (platform, shared, media, networkstack, testkey).",
                "Détection de Delta & Popup d'Avertissement : Compare les APKs actuels au snapshot de base. Si aucune signature ou APK n'a été modifié depuis l'unpack, affiche une boîte de dialogue d'avertissement permettant d'Annuler (recommandé pour préserver les signatures AOSP d'origine) ou de Signer quand même.",
                "Deux modes de re-signature complète : (1) 'Tout Signer' (re-signature rapide en respectant la topologie des N clés détectées) et (2) 'Tout Signer Pro (Cascade A-Z)' qui re-signe chaque cluster avec une clé RSA-2048 dédiée, synchronise /system/etc/security/otacerts.zip et /system/etc/selinux/plat_mac_permissions.xml, régénère tous les .odex/.vdex/.fsv_meta via ArtGeneratorEngine et reconstruit vbmeta.img."
            )
        )

        drawSubHeader("1.5. Moteur R.E.C.O.R.E à 12 Piliers (Onglet 5 : R.E.C.O.R.E)")
        drawBulletList(
            listOf(
                "Pilier 1 — Empreinte Structurelle 1:1 de l'Image de Base : Vérifie la conformité avec ROM_FORGE_META/base_img_snapshot.txt (0 modification = sortie 100% identique bit-à-bit).",
                "Pilier 2 — Inspection Universelle des Artefacts (OAT, VDEX, ODEX, ART, fsv_meta, prof,cil, vintf) & Chaîne de Cascade : Détecte tout fichier modifié et calcule la cascade exacte des dépendances devant être régénérées.",
                "Pilier 3 — Analyseur ELF64 AArch64 (.dynsym / .dynstr / DT_NEEDED) & Générateur de Shims : Inspecte les binaires ELF64 et génère des ponts binaires dans ROM_FORGE_META/shims/ sans polluer /system/lib64/.",
                "Pilier 4 — Parseur & Simulateur de Séquence Boot init.rc : Simule l'ordre d'exécution early-init -> init -> late-init -> post-fs-data -> boot.",
                "Pilier 5 — Solveur Formelle SMT/SAT des Dépendances de Boot : Modélise les contraintes critiques (bin/init 0750, SELinux contexts, VINTF, OAT/VDEX, Superblock EXT4) sous forme de clauses booléennes SMT-LIB2.",
                "Pilier 6 — Graphe Acyclique Dirigé (DAG) de Démarrage : Visualise les dépendances de la couche Kernel/Stage1 jusqu'à SystemServer et SystemUI.",
                "Piliers 7 & 8 — Chaîne de Confiance Interne & Auto-Guérison : Vérifie l'alignement 4-octets STORED de resources.arsc, otacerts.zip et plat_mac_permissions.xml sans jamais re-signer de manière destructrice les APKs intacts.",
                "Piliers 9, 10, 11 & 12 — Sandbox Pré-Boot ARM64, Analyseur de Crash/Last_Kmsg, Constructeur Chirurgical In-Place 1:1 et Orchestrateur de Régénération AOSP."
            )
        )

        drawSubHeader("1.6. Régénérateur AOSP Robuste OAT / VDEX / ODEX / fsv_meta (ArtGeneratorEngine)")
        drawBulletList(
            listOf(
                "Profilage Natif du Compilateur AOSP d'Origine : Scanne les fichiers .odex et .vdex existants de la ROM pour extraire la version exacte d'OAT (ex: 195, 225, 238 pour Android 12–15), la version VDEX (021 / 027), le jeu d'instructions (arm64) et la présence de boot.art.",
                "Synthèse Binaire Conforme AOSP : Génère des en-têtes ELF64 OAT (symbole oatdata, rodata, oatexec, instruction_set=kArm64, oat_dex_files_offset), des conteneurs VDEX (magic vdex, verifier_deps, quickening_info, CRC32 des classes.dex extraits de l'APK) et les métadonnées fs-verity (.fsv_meta SHA-256 Merkle)."
            )
        )

        // =========================================================================
        // SECTION 2: LISTE COMPLÈTE DES OUTILS & MOTEURS COMPOSANT L'APPLICATION
        // =========================================================================
        drawSectionBanner("2", "INVENTAIRE COMPLET DES OUTILS & MOTEURS INTERNES DE L'APPLICATION")
        drawBulletList(
            listOf(
                "1. ExactImageCloneEngine (core/img/ExactImageCloneEngine.kt) : Moteur de clonage 1:1 bit-à-bit Sparse/Raw et mutateur EXT4 chirurgical In-Place avec allocation Copy-On-Write (CoW), désactivation propre de METADATA_CSUM/GDT_CSUM lors d'une greffe, support des répertoires HTree et troncature sécurisée du footer AVB 2.0.",
                "2. Ext4UserspaceExtractor (core/img/Ext4UserspaceExtractor.kt) : Extracteur EXT4 100% userspace lisant le Superblock (offset 1024), les descripteurs de groupes 32/64-bit, les arbres d'extents (0xF30A), les xattrs inline/externes (0xEA020000) et enregistrant la carte physique exacte des blocs de chaque inode (exact_inode_extents_map.txt).",
                "3. Ext4UserspaceBuilder (core/img/Ext4UserspaceBuilder.kt) : Constructeur EXT4 100% userspace reproduisant la géométrie du Superblock d'origine (UUID, Hash Seed HTree, flags incompat/ro_compat sans SPARSE_SUPER non initialisé).",
                "4. ErofsUserspaceBuilder (core/img/ErofsUserspaceBuilder.kt) : Constructeur d'images EROFS (magic 0xE0F5E1E2) en lecture seule haute performance.",
                "5. AospTopologyResolver (core/img/AospTopologyResolver.kt) : Détecteur et résolveur de topologie AOSP (SAR System-As-Root vs Flat) préservant les symlinks /product -> /system/product et protégeant plat_file_contexts.",
                "6. UkaConfigHelper (core/img/UkaConfigHelper.kt) : Gestionnaire des fichiers de configuration compatibles UKA v5.27 (system_fs_config, system_file_contexts, system_size.txt, system_space.txt).",
                "7. PayloadDumperEngine (core/archive/PayloadDumperEngine.kt) : Décodeur de flux OTA payload.bin (magic CrAU, manifeste Protobuf DeltaArchiveManifest, opérations REPLACE / REPLACE_XZ / REPLACE_BZ).",
                "8. LpUnpackEngine (core/archive/LpUnpackEngine.kt) : Décodeur de partitions dynamiques super.img (LpMetadataGeometry 0x616C4467, LpMetadataHeader 0x414C5030, tables d'extents linéaires system_a/product_a/vendor_a).",
                "9. BrotliSdatEngine (core/archive/BrotliSdatEngine.kt) : Décompresseur Brotli (.new.dat.br) et interpréteur de commandes de blocs .transfer.list (new, zero, erase).",
                "10. AutoPorterEngine (modules/porter/AutoPorterEngine.kt) : Moteur de portage GSI et de correction biométrique optique UDFPS/FOD (Solutions 1 et 2).",
                "11. ImgCompilerEngine (modules/compiler/ImgCompilerEngine.kt) : Orchestrateur de pré-audit statique, Repack Simple & Intelligent 1:1, Repack UKA EXT4/EROFS et génération VBMeta AVB 2.0.",
                "12. SignProEngine (modules/signpro/SignProEngine.kt) : Analyseur de graphe de certificats APK/APEX, générateur de clés RSA-2048 X.509/PK8 et moteur de re-signature en cascade.",
                "13. ArtGeneratorEngine (modules/art/ArtGeneratorEngine.kt) : Compilateur synthétique AOSP d'artefacts .odex, .vdex, .art et .fsv_meta.",
                "14. RecoreEngine (core/recore/RecoreEngine.kt) : Moteur d'intelligence centrale à 12 Piliers (Blueprint 1:1, Cascade Artefacts, ELF64 Shims, Init.rc, Solveur SMT/SAT, Sandbox ARM64, Reconstruction 1:1).",
                "15. MagiskPatcherEngine (modules/magisk/MagiskPatcherEngine.kt) : Analyseur et patcheur de boot.img / init_boot.img (formats d'en-tête v1–v4, ramdisk cpio, magiskinit).",
                "16. RomForgeStorageManager (core/storage/RomForgeStorageManager.kt) : Gestionnaire de stockage et d'exportation directe vers le dossier public Téléchargements (Downloads/ROM_FORGE/) via MediaStore / File API."
            )
        )

        // =========================================================================
        // SECTION 3: MANUEL D'UTILISATION PAS-À-PAS
        // =========================================================================
        drawSectionBanner("3", "MANUEL D'UTILISATION COMPLET PAS-À-PAS")
        drawBulletList(
            listOf(
                "Étape 1 — Importer et Unpacker une image (.img / payload.bin / super.img) : Ouvrez l'onglet 1 'Extract'. Cliquez sur 'Sélectionner un fichier (.img / .bin / .br)' pour choisir votre GSI ou ROM. L'application copie la référence de l'image source, extrait l'intégralité de l'arborescence dans ROM_FORGE/UNPACK/system_ext4/ et enregistre automatiquement le snapshot immuable 1:1 (ROM_FORGE_META/base_img_snapshot.txt et exact_inode_extents_map.txt).",
                "Étape 2 — Tester le Repack Simple & Intelligent 1:1 (Validation DSU Sideloader sans modification) : Allez dans l'onglet 3 'Compile' et cliquez sur le bouton vert 'Repack Simple & Intelligent 1:1 (Identique à l'Original • DSU Ready)'. Si vous n'avez rien modifié après l'unpack, le moteur produit une image 100% identique bit-à-bit à votre GSI initial et l'exporte dans Téléchargements/ROM_FORGE/PACKED/system_repacked_1to1.img.",
                "Étape 3 — Appliquer le FOD Fix Solution 2 (Recommandé pour booter sur DSU Sideloader avec FOD actif) : Ouvrez l'onglet 2 'Porter'. Cliquez sur le bouton 'FOD Fix Solution 2 : Overlays + Nouveaux Éléments + Repack Simple & Intelligent 1:1 (Zéro APK Modifié)'. Le moteur copie l'arborescence dans ROM_FORGE/PORT/, greffe chirurgicalement init.tucana.fod.rc, uinput-goodix.kl, xiaomi_tucana_fod_config.xml et les propriétés FOD dans build.prop sur un clone 1:1 de l'image de base, sans toucher à aucun APK ni à SELinux/VINTF, et exporte l'image prête à démarrer dans Téléchargements/ROM_FORGE/PORT/.",
                "Étape 4 — Utiliser R.E.C.O.R.E (Onglet 5) : Cliquez sur 'Lancer l'Audit & Auto-Guérison R.E.C.O.R.E' pour inspecter les 12 Piliers (Blueprint 1:1, cascade OAT/VDEX, solveur SMT/SAT, simulation init.rc). Cliquez ensuite sur 'Reconstruire & Compiler .IMG Bootable (Fidélité 1:1 R.E.C.O.R.E)' pour générer une image fidèle à l'originale intégrant vos modifications.",
                "Étape 5 — Utiliser Sign PRO (Onglet 4) : Cliquez sur 'Scanner le Graphe de Signatures de l'Image' pour visualiser les clés détectées. N'utilisez 'Tout Signer Pro' que si vous avez remplacé ou modifié manuellement des APKs système et souhaitez reconstruire toute la chaîne de certificats et régénérer les .odex/.vdex."
            )
        )

        // =========================================================================
        // SECTION 4: STRUCTURE DE L'APPLICATION & ARBORESCENCE COMPLÈTE DU CODE
        // =========================================================================
        drawSectionBanner("4", "STRUCTURE DE L'APPLICATION & ARBORESCENCE COMPLÈTE (CODE & WORKSPACE)")
        drawParagraph(
            "L'application suit l'architecture Clean MVVM avec Jetpack Compose (Material 3), Kotlin Coroutines/Flow et Room Database. " +
                    "Voici l'arborescence exacte de tous les packages et fichiers sources Kotlin de l'application ainsi que l'arborescence du dossier de travail ROM_FORGE :"
        )
        drawCodeOrTreeBlock(
            listOf(
                "app/src/main/java/com/example/",
                "├── MainActivity.kt                      # Point d'entrée Edge-to-Edge, Navigation 8 onglets (KeyMaker, SignPro, Generator, Compiler, Porting, R.E.C.O.R.E, Console, Paramètres)",
                "├── core/",
                "│   ├── assets/",
                "│   │   └── AssetBinaryManager.kt        # Extraction & vérification des binaires natifs (mke2fs, e2fsdroid, simg2img, img2simg, lpunpack, avbtool, dex2oat, secilc)",
                "│   ├── docs/",
                "│   │   └── RomForgePdfManualGenerator.kt# Générateur PDF natif de documentation technique, manuel d'utilisation, arborescence & audit IA",
                "│   ├── img/",
                "│   │   ├── AospTopologyResolver.kt      # Résolveur topologie AOSP SAR (/system/system) vs Flat (/system) & protection SELinux plat_file_contexts",
                "│   │   ├── ErofsUserspaceBuilder.kt     # Constructeur d'images EROFS (magic 0xE0F5E1E2)",
                "│   │   ├── ExactImageCloneEngine.kt     # Clonage 1:1 bit-à-bit Sparse/Raw & Mutateur Chirurgical EXT4 In-Place (Copy-on-Write, HTree, METADATA_CSUM, AVB Trim)",
                "│   │   ├── Ext4UserspaceBuilder.kt      # Constructeur EXT4 100% userspace fidèle au Superblock d'origine (UUID, Hash Seed, flags)",
                "│   │   ├── Ext4UserspaceExtractor.kt    # Extracteur EXT4 100% userspace + snapshot immuable base_img_snapshot.txt + exact_inode_extents_map.txt",
                "│   │   └── UkaConfigHelper.kt           # Synchronisation tables UKA v5.27 (system_fs_config, system_file_contexts, system_size.txt, system_space.txt)",
                "│   ├── recore/",
                "│   │   └── RecoreEngine.kt              # Moteur intelligent à 12 Piliers (Blueprint 1:1, Cascade OAT/VDEX, ELF64 Shims, Init.rc, Solveur SMT/SAT, Reconstruction 1:1)",
                "│   ├── shell/",
                "│   │   └── HybridShellEngine.kt         # Exécuteur hybride Root Loopback / Userspace Non-Root & inspecteur binaire d'images",
                "│   ├── storage/",
                "│   │   └── RomForgeStorageManager.kt    # Gestionnaire de l'espace de travail public /storage/emulated/0/ROM_FORGE (UNPACK, PACKED, PORT, KEY, DOCS)",
                "│   └── verifier/",
                "│       └── CrossVerifierEngine.kt       # Vérificateur croisé d'intégrité entre clés X.509, APKs, caches ART/VDEX et manifestes SELinux",
                "├── data/",
                "│   ├── local/",
                "│   │   └── AppDatabase.kt               # Base SQLite Room (KeyManifestEntity, ArtCacheEntity, VerificationAlertEntity, PortHistoryEntity)",
                "│   └── repository/",
                "│       └── RomKitchenRepository.kt      # Dépôt réactif Flow connectant Room aux moteurs et au ViewModel",
                "├── modules/",
                "│   ├── compiler/",
                "│   │   └── ImgCompilerEngine.kt         # Unpack/Repack UKA v5.27, Repack Simple & Intelligent 1:1, Pré-Audit Statique & VBMeta AVB 2.0",
                "│   ├── generator/",
                "│   │   └── ArtGeneratorEngine.kt        # Régénérateur AOSP intelligent OAT (.odex), VDEX (.vdex), .art & .fsv_meta avec profilage du compilateur d'origine",
                "│   ├── keymaker/",
                "│   │   └── KeyMakerEngine.kt            # Générateur cryptographique RSA-2048/4096 PKCS#8 (.pk8) & X.509 (.x509.pem) + manifeste cle_note.json",
                "│   ├── porter/",
                "│   │   └── AutoPorterEngine.kt          # Portage GSI vers Device Tree & FOD Fix Solution 1 (Patch APK + Régénération) et Solution 2 (Sans Re-signature + Repack 1:1)",
                "│   └── signpro/",
                "│       └── SignProEngine.kt             # Cartographie du graphe de signatures APK/APEX, détection de delta, Tout Signer & Tout Signer Pro (Cascade A-Z)",
                "└── ui/",
                "    ├── RomKitchenViewModel.kt           # ViewModel centralisant l'état StateFlow, l'historique d'actions et l'orchestration des moteurs",
                "    ├── components/",
                "    │   └── KitchenCommonComponents.kt   # Composants UI Material 3 réutilisables (cartes techniques, badges de statut, barres de progression)",
                "    ├── screens/",
                "    │   ├── KeyMakerScreen.kt            # UI Onglet 1 : Génération et gestion du trousseau cryptographique AOSP",
                "    │   ├── SignProScreen.kt             # UI Onglet 2 : Sign PRO, Graphe de Clés, Popup d'avertissement & Tout Signer Pro",
                "    │   ├── GeneratorScreen.kt           # UI Onglet 3 : Régénération AOSP OAT / VDEX / ODEX / fsv_meta",
                "    │   ├── CompilerScreen.kt            # UI Onglet 4 : Unpack/Repack UKA, Repack Simple & Intelligent 1:1 & VBMeta",
                "    │   ├── AutoPorterScreen.kt          # UI Onglet 5 : Auto-Porter GSI & FOD Fix Solution 1 et Solution 2",
                "    │   ├── RecoreScreen.kt              # UI Onglet 6 : Moteur R.E.C.O.R.E à 12 Piliers & Reconstruction 1:1",
                "    │   ├── ConsoleHistoryScreen.kt      # UI Onglet 7 : Console Temps Réel & Historique des Actions",
                "    │   └── HelpScreen.kt                # UI Onglet 8 (Paramètres & Aide) : Thème, Stockage, Téléchargement PDF Technique & Guide",
                "    └── theme/",
                "        └── Theme.kt                     # Thème Material 3 adaptatif ( Clair / Sombre / Système )"
            )
        )

        drawSubHeader("4.2. Arborescence du Dossier de Travail ROM_FORGE/ et des Métadonnées")
        drawCodeOrTreeBlock(
            listOf(
                "ROM_FORGE/",
                "├── UNPACK/",
                "│   └── system_ext4/                     # Racine de l'image décompressée",
                "│       ├── system/                      # Partition système (en topologie SAR System-As-Root)",
                "│       ├── product -> /system/product   # Symlink AOSP préservé",
                "│       ├── config/                      # Tables UKA v5.27 (system_fs_config, system_file_contexts)",
                "│       └── ROM_FORGE_META/              # Métadonnées internes (exclues de l'image finale)",
                "│           ├── source_img_ref.txt       # Chemin vers le fichier .img original pour clonage 1:1",
                "│           ├── base_img_snapshot.txt    # Empreinte CRC32, taille et symlinks de chaque fichier initial",
                "│           └── exact_inode_extents_map.txt # Carte des inodes et blocs 4K physiques d'origine",
                "├── PORT/",
                "│   ├── system_ext4_ported_tucana/       # Arborescence portée avec correctifs FOD Solution 1 ou 2",
                "│   └── system_ext4_ported_tucana.img    # Image .img finale issue du FOD Fix (DSU Sideloader Ready)",
                "└── PACKED/",
                "    ├── system_repacked_1to1.img         # Image issue du Repack Simple & Intelligent 1:1",
                "    ├── system_recore_1to1.img           # Image issue du moteur R.E.C.O.R.E",
                "    └── vbmeta.img                       # Image VBMeta AVB 2.0 (flags=3 pour désactiver dm-verity)"
            )
        )

        // =========================================================================
        // SECTION 5: DIAGNOSTIC TECHNIQUE APPROFONDI (POUR AUDIT PAR UNE AUTRE IA)
        // =========================================================================
        drawSectionBanner("5", "DIAGNOSTIC TECHNIQUE APPROFONDI & CORRECTIFS ANTI-BOOTLOOP DSU SIDELOADER")
        drawParagraph(
            "Cette section documente précisément les causes racines qui provoquaient l'arrêt du démarrage avant la bootanimation " +
                    "lors d'un FOD Fix sur DSU Sideloader, ainsi que les correctifs implémentés dans le code actuel :"
        )
        drawBulletList(
            listOf(
                "Cause 1 corrigée — Conflit SELinux secilc au Stage 1 Init (/system/etc/selinux/*.cil) : Lors du démarrage (first_stage_init), Android compile tous les fichiers .cil présents dans /system/etc/selinux/ avec /vendor/etc/selinux/vendor_sepolicy.cil via le compilateur secilc. L'ajout d'un fichier recore_fod_sepolicy.cil contenant des déclarations (type hal_fingerprint_default) déjà présentes dans plat_sepolicy.cil ou non mappées dans plat_pub_versioned.cil provoquait un échec fatal de secilc ('Duplicate declaration of type' / 'Failed to compilecil') et un reboot immédiat sur le bootloader avant même le démarrage de surfaceflinger. Correctif : /system/etc/selinux/ et plat_file_contexts ne sont plus jamais modifiés ou pollués.",
                "Cause 2 corrigée — Rejet VINTF par libvintf (/system/etc/vintf/manifest.xml) : L'injection de HALs propriétaires vendor.xiaomi.* et vendor.goodix.* dans un manifeste déclaré type='framework' dans /system/etc/vintf/ violait la règle stricte de libvintf interdisant les HALs vendor dans la matrice framework, faisant crasher hwservicemanager et servicemanager. Correctif : Le fichier /system/etc/vintf/manifest.xml d'origine du GSI est désormais préservé à 100%.",
                "Cause 3 corrigée — Écrasement de bibliothèques /system/lib64/ et exécutable stub de 256 octets : Lorsque le dossier stock_vendor_ref ne contenait pas les vrais blobs binaires du téléphone, ensureTucanaBlobsPresent générait des fichiers ELF factices de 256 octets qui étaient copiés dans /system/lib64/ et /system/bin/hw/, provoquant un arrêt du linker64. Correctif : Seules de vraies bibliothèques ELF (> 4 KB) sont copiées si absentes du GSI, et aucun stub de 256 octets n'est injecté dans /system/.",
                "Cause 4 corrigée — Rejet des Overlays RRO non compilés par idmap2 / PackageManager : Les fichiers APK injectés dans /system/product/overlay/ contenaient du XML texte brut ('<?xml version=\"1.0\"...') au lieu du format binaire compilé AAPT2 ResXMLTree (0x00080003), provoquant une exception fatale dans AssetManager2 lors du scan de /product/overlay/. Correctif : Les archives de référence sont conservées dans ROM_FORGE_META/fod_overlays/ et la configuration système utilise un fichier XML standard AOSP dans /system/etc/sysconfig/ ainsi que les propriétés système PHH-Treble dans build.prop et init.tucana.fod.rc.",
                "Cause 5 corrigée — Corruption EXT4 SHARED_BLOCKS, METADATA_CSUM et e_value_offs xattr lors de la mutation chirurgicale In-Place : (a) Dans un GSI construit avec e2fsdroid -s (SHARED_BLOCKS 0x4000), réécrire les blocs physiques d'un fichier modifié sur place corrompait d'autres fichiers partageant ces blocs ; ExactImageCloneEngine utilise désormais systématiquement une allocation Copy-on-Write (CoW) de nouveaux blocs libres. (b) Si le Superblock original avait METADATA_CSUM (0x0400) ou GDT_CSUM (0x0010), modifier un inode ou un bloc de répertoire sans recalculer le CRC32C faisait échouer le montage ext4 du noyau ; ces deux flags RO_COMPAT sont désormais désactivés proprement dans le Superblock lors d'une mutation. (c) Dans un inode EXT4 de 256 octets, e_value_offs de l'attribut security.selinux est désormais calculé relativement à IFIRST(header) (offset 164) conformément à fs/ext4/xattr.h du noyau Linux."
            )
        )

        finishCurrentPage()

        val storageManager = RomForgeStorageManager(context)
        val docsDir = File(storageManager.getRomForgePublicRoot(), "DOCS").apply { mkdirs() }
        val pdfFile = File(docsDir, "ROM_Forge_Documentation_Complete_Architecture_IA_Audit.pdf")
        FileOutputStream(pdfFile).use { fos ->
            pdfDoc.writeTo(fos)
        }
        pdfDoc.close()

        // Also copy to the system public Downloads folder if accessible
        val publicDownloads = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
        val publishedPath = try {
            publicDownloads.mkdirs()
            val dlCopy = File(publicDownloads, pdfFile.name)
            pdfFile.copyTo(dlCopy, overwrite = true)
            onLog?.invoke("[PDF-EXPORT] Manuel technique et d'audit IA exporté dans : ${dlCopy.absolutePath} et ${pdfFile.absolutePath}")
            dlCopy.absolutePath
        } catch (_: Exception) {
            onLog?.invoke("[PDF-EXPORT] Manuel technique et d'audit IA généré dans : ${pdfFile.absolutePath}")
            pdfFile.absolutePath
        }

        GeneratedPdfDocResult(
            pdfFile = pdfFile,
            publishedDownloadPath = publishedPath,
            pageCount = currentPageNumber,
            sizeBytes = pdfFile.length(),
            generatedAtLabel = timestamp
        )
    }
}
