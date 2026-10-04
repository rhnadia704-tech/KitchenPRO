package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.KitchenTab

data class HelpGuideSection(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val steps: List<String>,
    val commands: List<Pair<String, String>>,
    val targetTab: KitchenTab? = null
)

@Composable
fun HelpScreen(
    romForgeRootPath: String,
    onNavigateToTab: (KitchenTab) -> Unit,
    onRunCommandInTerminal: (String) -> Unit
) {
    val context = LocalContext.current

    val sections = listOf(
        HelpGuideSection(
            title = "1. Organisation des Dossiers ROM_FORGE",
            subtitle = "Emplacement : $romForgeRootPath",
            icon = Icons.Default.Folder,
            steps = listOf(
                "• UNPACK/   : Contient tous vos fichiers .img décompilés (ex: UNPACK/system_ext4/).",
                "• PACKED/   : Contient les images recompilées (system.img, vbmeta.img) et les APKs individuels signés.",
                "• KEY/      : Contient vos 4 paires de clés RSA-2048 (.pk8 & .x509.pem) ainsi que manifest.json (Clé Note).",
                "• KEY/Data/ : Contient les rapports d'audit et de vérification des signatures en format .json et .txt.",
                "• PORT/     : Espace dédié au portage GSI (fichiers portés, overlays RRO, blobs FOD et image .img portée finale)."
            ),
            commands = listOf(
                "ls" to "Lister les dossiers principaux de ROM_FORGE",
                "ls unpack" to "Afficher les systèmes décompilés dans UNPACK"
            ),
            targetTab = KitchenTab.CONSOLE
        ),
        HelpGuideSection(
            title = "2. Key Maker — Chaîne de Confiance RSA-2048",
            subtitle = "Génération des clés AOSP & Clé Note (manifest.json)",
            icon = Icons.Default.Key,
            steps = listOf(
                "1. Renseignez votre Organisation (O), Common Name (CN) et Pays (C).",
                "2. Appuyez sur « Générer les 4 Paires RSA-2048 » pour créer platform, media, shared et testkey.",
                "3. Les clés privées PKCS#8 (.pk8), certificats X.509 (.x509.pem) et le fichier manifest.json sont enregistrés dans ROM_FORGE/KEY/."
            ),
            commands = listOf(
                "ls key" to "Vérifier les clés RSA-2048 et rapports présents dans KEY/"
            ),
            targetTab = KitchenTab.KEY_MAKER
        ),
        HelpGuideSection(
            title = "3. Sign Pro — Resignature & Vérification (KEY/Data)",
            subtitle = "Signature d'un système UNPACK, d'un APK unique, et rapport JSON/TXT",
            icon = Icons.Default.Bolt,
            steps = listOf(
                "1. Choisissez le système décompilé via la liste déroulante UNPACK (ex: Axion GSI ou system_ext4).",
                "2. Les applications critiques (SystemUI.apk, Settings.apk, framework-res.apk, priv-app) s'affichent en premier avec leur vrai rôle AOSP (Platform AOSP, Media AOSP, Shared AOSP, TestKey AOSP).",
                "3. Pour signer un seul APK : cliquez sur « Signer cet APK » sur la carte de l'application souhaitée.",
                "4. Pour tout resigner + injecter plat_mac_permissions.xml : cliquez sur « Tout Signer ».",
                "5. Cliquez sur « Vérifier (-> KEY/Data) » pour contrôler toutes les signatures et générer les rapports signatures_<nom>.json et .txt dans ROM_FORGE/KEY/Data/."
            ),
            commands = listOf(
                "verify-apks" to "Lancer l'audit de signature de tous les APKs et exporter JSON/TXT dans KEY/Data",
                "zipalign -v 4 SystemUI.apk SystemUI_aligned.apk" to "Vérifier l'alignement 4K de resources.arsc"
            ),
            targetTab = KitchenTab.SIGN_PRO
        ),
        HelpGuideSection(
            title = "4. Generator — Cache ART (.odex / .vdex) & fs-verity",
            subtitle = "Pré-compilation Ahead-Of-Time via dex2oat ARM64",
            icon = Icons.Default.Memory,
            steps = listOf(
                "1. Sélectionnez le système décompilé dans UNPACK.",
                "2. Choisissez le filtre de compilation (speed-profile ou speed) et activez fs-verity si nécessaire.",
                "3. Le cache MD5 intelligent ne recompile que les APKs modifiés pour accélérer le premier démarrage."
            ),
            commands = listOf(
                "dex2oat --dex-file=SystemUI.apk --oat-file=SystemUI.odex --instruction-set=arm64 --compiler-filter=speed-profile" to "Compiler manuellement un APK en ODEX/VDEX ARM64"
            ),
            targetTab = KitchenTab.GENERATOR
        ),
        HelpGuideSection(
            title = "5. Compilation — Décompilation & Reconstruction .IMG",
            subtitle = "Extraction vers UNPACK et compilation EXT4/EROFS non-corrompue vers PACKED",
            icon = Icons.Default.Build,
            steps = listOf(
                "1. Pour décompiler une image : cliquez sur « Choisir .IMG à Décompiler ». Tout son contenu est extrait dans ROM_FORGE/UNPACK/<nom_img>/.",
                "2. Avant de recompiler, lancez « Anti-Bootloop » pour vérifier plat_file_contexts et fs_config (mode 0750 sur init).",
                "3. Cliquez sur « Compiler .IMG & VBMeta » : une image EXT4 complète (Superblock 0xEF53, GDT, Inodes, Extents, Xattrs SELinux) + vbmeta.img sont créés dans ROM_FORGE/PACKED/."
            ),
            commands = listOf(
                "mke2fs -L system -M /system -t ext4 -b 4096 system_packed.img" to "Construire une partition EXT4 4K",
                "avbtool add_hashtree_footer --image system_packed.img --partition_name system --algorithm SHA256_RSA2048" to "Injecter le Hashtree dm-verity AVB 2.0",
                "avbtool make_vbmeta_image --output vbmeta.img --flags 3" to "Générer une image vbmeta.img"
            ),
            targetTab = KitchenTab.COMPILER
        ),
        HelpGuideSection(
            title = "6. Porting (GSI to System) — FOD / UDFPS & Xiaomi Tucana",
            subtitle = "Sonde matérielle Non-Root + LineageOS Xiaomi Tucana (SM6150) vers ROM_FORGE/PORT",
            icon = Icons.Default.AccountTree,
            steps = listOf(
                "1. Sélectionnez votre GSI décompilé depuis UNPACK.",
                "2. L'analyseur sonde votre téléphone actuel (même sans root via getprop) et applique l'architecture LineageOS Xiaomi Tucana (Goodix GF9518 + IXiaomiFingerprint 1.0 + IDisplayFeature HBM 0x20000).",
                "3. Cliquez sur « Porter GSI & FOD (-> PORT) » : tous les fichiers portés, overlays RRO (SystemUIUdfpsTucanaOverlay.apk, TrebleHardwareOverlay.apk), init.tucana.fod.rc ainsi que le fichier .img final sont générés dans ROM_FORGE/PORT/."
            ),
            commands = listOf(
                "getprop" to "Inspecter les propriétés matérielles et FOD de votre téléphone",
                "ls port" to "Vérifier les dossiers et images .img portés dans ROM_FORGE/PORT"
            ),
            targetTab = KitchenTab.AUTO_PORTER
        )
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.HelpOutline,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "GUIDE D'UTILISATION & COMMANDES AOSP",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Instructions pas-à-pas pour chaque module, structure UNPACK/PACKED/KEY/PORT et commandes exécutables dans le Terminal intégré.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        items(sections, key = { it.title }) { sec ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(
                                imageVector = sec.icon,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = sec.title,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Text(
                                    text = sec.subtitle,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.secondary
                                )
                            }
                        }

                        if (sec.targetTab != null) {
                            FilledTonalButton(
                                onClick = { onNavigateToTab(sec.targetTab) }
                            ) {
                                Text("Ouvrir", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }

                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        sec.steps.forEach { step ->
                            Text(
                                text = step,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }

                    if (sec.commands.isNotEmpty()) {
                        Text(
                            text = "Commandes Terminal associées :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )

                        sec.commands.forEach { (cmd, desc) ->
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 10.dp, vertical = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "$ $cmd",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                        Text(
                                            text = desc,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }

                                    Row {
                                        IconButton(
                                            onClick = {
                                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                                clipboard?.setPrimaryClip(ClipData.newPlainText("Command", cmd))
                                                Toast.makeText(context, "Commande copiée", Toast.LENGTH_SHORT).show()
                                            }
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.ContentCopy,
                                                contentDescription = "Copier la commande",
                                                modifier = Modifier.size(16.dp)
                                            )
                                        }

                                        IconButton(
                                            onClick = {
                                                onRunCommandInTerminal(cmd)
                                                onNavigateToTab(KitchenTab.CONSOLE)
                                            },
                                            modifier = Modifier.testTag("run_help_cmd_${cmd.take(8)}")
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.PlayArrow,
                                                contentDescription = "Exécuter dans la Console",
                                                tint = MaterialTheme.colorScheme.secondary,
                                                modifier = Modifier.size(18.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}
