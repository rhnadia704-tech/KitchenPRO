package com.example.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.KitchenUiState

@Composable
fun ExtractorScreen(
    uiState: KitchenUiState,
    onExecuteExtractMe: (Boolean) -> Unit,
    onNavigateToPorter: () -> Unit,
    onNavigateToCreation: () -> Unit
) {
    var combineWithTucanaBase by remember { mutableStateOf(true) }
    val dna = uiState.gastroDnaProfile

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // 1. Header Banner: EXTRACTOR + GASTROengine DeviceProfiler & ShellOrchestrator
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f)
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Download,
                        contentDescription = "EXTRACTOR",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "EXTRACTOR • Extraction ADN du Téléphone (-> EXTRACT/)",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Propulsé par GASTROengine (DeviceProfiler + ShellOrchestrator + FileExtractor + FsParser)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                Text(
                    text = "Ce module extrait tous les éléments de référence de votre téléphone (partitions, points de montage, services init, manifestes VINTF, HALs, blobs .so, keylayouts, permissions et symlinks) et les isole proprement dans le dossier ROM_FORGE/EXTRACT/.",
                    style = MaterialTheme.typography.bodySmall
                )

                Surface(
                    color = Color(0xFF10281E),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = "ShellOrchestrator Sandbox",
                            tint = Color(0xFF00E676),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Sécurité ShellOrchestrator : Lecture seule sur le système du téléphone. 100% des manipulations sont isolées dans l'espace de travail GASTRO (${uiState.romForgePublicPath}/EXTRACT/).",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFFB9F6CA),
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        // 2. Main Action Card: ExtractMe Button -> ROM_FORGE/EXTRACT/
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Option Base de Référence Parallèle (LineageOS 24.0 Tucana SM6150)",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Combine l'extraction réelle du téléphone avec les définitions FOD/HBM/VINTF de référence pour garantir 100% de complétude même sans Root.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = combineWithTucanaBase,
                        onCheckedChange = { combineWithTucanaBase = it },
                        modifier = Modifier.testTag("extractor_switch_combine_base")
                    )
                }

                Button(
                    onClick = { onExecuteExtractMe(combineWithTucanaBase) },
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                        .testTag("btn_extractor_extract_me")
                ) {
                    Icon(imageVector = Icons.Default.Download, contentDescription = "ExtractMe")
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "ExtractMe (Extraire Téléphone -> Dossier EXTRACT/)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onNavigateToPorter,
                        enabled = !uiState.isBusy,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("btn_extractor_go_porter")
                    ) {
                        Icon(imageVector = Icons.Default.AccountTree, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Aller vers PORTER")
                    }
                    OutlinedButton(
                        onClick = onNavigateToCreation,
                        enabled = !uiState.isBusy,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("btn_extractor_go_creation")
                    ) {
                        Icon(imageVector = Icons.Default.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Aller vers CREATION")
                    }
                }
            }
        }

        // 3. Status of ROM_FORGE/EXTRACT/ Folder & DeviceProfiler DNA
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.FolderSpecial,
                        contentDescription = "Dossier EXTRACT",
                        tint = if (uiState.isExtractReady) Color(0xFF00C853) else MaterialTheme.colorScheme.secondary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (uiState.isExtractReady) {
                            "Dossier EXTRACT Prêt (${uiState.extractedFilesCount} fichiers isolés)"
                        } else {
                            "Dossier EXTRACT en attente de ExtractMe"
                        },
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                Text(
                    text = "Chemin d'extraction : ${uiState.romForgePublicPath}/EXTRACT/",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary
                )

                if (dna != null) {
                    HorizontalDivider()
                    Text(
                        text = "ADN Matériel Extrait par DeviceProfiler (${dna.timestamp}) :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "• Appareil : ${dna.deviceBrand} ${dna.deviceModel} (${dna.deviceCodename})\n" +
                                "• Plateforme SoC : ${dna.boardPlatform} • Android ${dna.androidRelease} (SDK ${dna.sdkInt})\n" +
                                "• Noyau Kernel : ${dna.kernelVersion}\n" +
                                "• Accès Root (ShellOrchestrator RO) : ${if (dna.rootGranted) "OUI (uid=0)" else "Mode Live/Hybride"}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )

                    Text(
                        text = "Partitions & Points de Montage Capturés :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    dna.extractedPartitions.forEach { part ->
                        Text(
                            text = "  • $part",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Text(
                        text = "Topologie de Liens Symboliques (StructureAligner) :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    dna.symlinksMap.forEach { (k, v) ->
                        Text(
                            text = "  • $k -> $v",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }

                    Text(
                        text = "HALs & Services Init Détectés :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    dna.hardwareHalsDetected.forEach { hal ->
                        Text(
                            text = "  ✓ $hal",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        // 4. Overview of the 10 Rust Modules of GASTROengine
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Memory,
                        contentDescription = "GASTROengine Rust",
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Architecture Modulaire GASTROengine (10 Composants Rust + R.E.C.O.R.E)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                uiState.gastroSubsystems.forEach { sub ->
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = sub.title,
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Text(
                                    text = sub.status,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                            Text(
                                text = sub.description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = "${sub.rustModuleName} • ${sub.telemetryMetric}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.secondary
                            )
                        }
                    }
                }
            }
        }
    }
}
