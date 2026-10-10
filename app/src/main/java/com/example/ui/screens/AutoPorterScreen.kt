package com.example.ui.screens

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.data.local.PortHistoryEntity
import com.example.ui.KitchenUiState

private enum class PorterSubPage {
    MAIN_HUB,
    PORTER_PLAN_PAGE,
    FOD_ENGINE_PAGE
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AutoPorterScreen(
    uiState: KitchenUiState,
    portHistory: List<PortHistoryEntity>,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri) -> Unit,
    onExecutePortageToUnpackedGsi: () -> Unit,
    onRunPorterPlanAnalysis: () -> Unit,
    onRunFodCompleteScan: () -> Unit,
    onRunFodAiScan: () -> Unit,
    onApplyFodFix1Complete: () -> Unit,
    onApplyFodFix2Workaround: () -> Unit,
    onApplyFodFix3AiAndGastroEngine: () -> Unit,
    onNavigateToExtractor: () -> Unit,
    onNavigateToCreation: () -> Unit
) {
    var currentSubPage by rememberSaveable { mutableStateOf(PorterSubPage.MAIN_HUB) }

    if (currentSubPage != PorterSubPage.MAIN_HUB) {
        BackHandler {
            currentSubPage = PorterSubPage.MAIN_HUB
        }
    }

    when (currentSubPage) {
        PorterSubPage.MAIN_HUB -> PorterMainHubPage(
            uiState = uiState,
            portHistory = portHistory,
            onSelectDecompiledImg = onSelectDecompiledImg,
            onPickCustomSafTree = onPickCustomSafTree,
            onExecutePort = onExecutePortageToUnpackedGsi,
            onOpenPorterPlanPage = {
                onRunPorterPlanAnalysis()
                currentSubPage = PorterSubPage.PORTER_PLAN_PAGE
            },
            onOpenFodPage = {
                currentSubPage = PorterSubPage.FOD_ENGINE_PAGE
            },
            onNavigateToExtractor = onNavigateToExtractor,
            onNavigateToCreation = onNavigateToCreation
        )

        PorterSubPage.PORTER_PLAN_PAGE -> PorterPlanDedicatedPage(
            uiState = uiState,
            onBack = { currentSubPage = PorterSubPage.MAIN_HUB },
            onRefreshPorterPlan = onRunPorterPlanAnalysis,
            onNavigateToExtractor = onNavigateToExtractor,
            onExecutePort = onExecutePortageToUnpackedGsi
        )

        PorterSubPage.FOD_ENGINE_PAGE -> PorterFodDedicatedPage(
            uiState = uiState,
            onBack = { currentSubPage = PorterSubPage.MAIN_HUB },
            onRunScan = onRunFodCompleteScan,
            onRunAiScan = onRunFodAiScan,
            onApplyFodFix1 = onApplyFodFix1Complete,
            onApplyFodFix2 = onApplyFodFix2Workaround,
            onApplyFodFix3 = onApplyFodFix3AiAndGastroEngine,
            onNavigateToExtractor = onNavigateToExtractor,
            onNavigateToCreation = onNavigateToCreation
        )
    }
}

// ============================================================================
// 1. PORTER MAIN HUB PAGE (Dropdown + PORT + PORTERPLAN + FOD)
// ============================================================================
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PorterMainHubPage(
    uiState: KitchenUiState,
    portHistory: List<PortHistoryEntity>,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri) -> Unit,
    onExecutePort: () -> Unit,
    onOpenPorterPlanPage: () -> Unit,
    onOpenFodPage: () -> Unit,
    onNavigateToExtractor: () -> Unit,
    onNavigateToCreation: () -> Unit
) {
    var expandedDropdown by remember { mutableStateOf(false) }
    val safTreeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) onPickCustomSafTree(uri)
    }

    val portResult = uiState.portAnalysisResult

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header Card
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f)
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.AccountTree,
                        contentDescription = "PORTER",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "PORTER • Plateforme de Portage GSI",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "GASTROengine (Rust) • StructureAligner • VintfReconciler • R.E.C.O.R.E (Fond)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                Text(
                    text = "Choisissez l'OS unpacké cible, consultez l'architecture comparative dans PORTERPLAN, lancez le portage complet PORT (basé sur EXTRACTOR) ou ouvrez l'ingénierie FOD.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        // 1. Dropdown field to select which unpacked OS to port
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "1. Choisir l'OS Unpacké à Porter (UNPACK/)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.ExtraBold
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    ExposedDropdownMenuBox(
                        expanded = expandedDropdown,
                        onExpandedChange = { expandedDropdown = !expandedDropdown },
                        modifier = Modifier.weight(1f)
                    ) {
                        OutlinedTextField(
                            value = uiState.selectedDecompiledImgName,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Dossier OS Unpacké") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expandedDropdown) },
                            modifier = Modifier
                                .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                                .fillMaxWidth()
                                .testTag("porter_dropdown_unpacked_os")
                        )
                        ExposedDropdownMenu(
                            expanded = expandedDropdown,
                            onDismissRequest = { expandedDropdown = false }
                        ) {
                            uiState.availableDecompiledImgs.forEach { folder ->
                                DropdownMenuItem(
                                    text = { Text("UNPACK/$folder") },
                                    onClick = {
                                        onSelectDecompiledImg(folder)
                                        expandedDropdown = false
                                    }
                                )
                            }
                        }
                    }

                    OutlinedButton(
                        onClick = { safTreeLauncher.launch(null) },
                        modifier = Modifier.testTag("porter_btn_pick_saf")
                    ) {
                        Icon(imageVector = Icons.Default.FolderOpen, contentDescription = "Importer dossier")
                    }
                }

                Text(
                    text = "Cible active : ${uiState.selectedDecompiledImgFullPath}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // 2. EXTRACTOR Prerequisite Banner + PORT Button
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "2. Actions Principales de Portage (PORT / PORTERPLAN / FOD)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.ExtraBold
                )

                // Status of EXTRACTOR
                Surface(
                    color = if (uiState.isExtractReady) {
                        Color(0xFF0D2B1D)
                    } else {
                        MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.65f)
                    },
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(
                            modifier = Modifier.weight(1f),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = if (uiState.isExtractReady) Icons.Default.CheckCircle else Icons.Default.Warning,
                                contentDescription = null,
                                tint = if (uiState.isExtractReady) Color(0xFF00E676) else MaterialTheme.colorScheme.error
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = if (uiState.isExtractReady) {
                                        "EXTRACTOR Prêt : ${uiState.extractedFilesCount} fichiers dans ROM_FORGE/EXTRACT/"
                                    } else {
                                        "Prérequis PORT : Aucun extract trouvé dans ROM_FORGE/EXTRACT/"
                                    },
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = if (uiState.isExtractReady) Color(0xFFB9F6CA) else MaterialTheme.colorScheme.onErrorContainer
                                )
                                Text(
                                    text = if (uiState.isExtractReady) {
                                        "Le bouton PORT est déverrouillé et prêt à créer le portage complet."
                                    } else {
                                        "Exécutez d'abord ExtractMe dans EXTRACTOR pour activer le bouton PORT."
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (uiState.isExtractReady) Color(0xFFB9F6CA) else MaterialTheme.colorScheme.onErrorContainer
                                )
                            }
                        }
                        if (!uiState.isExtractReady) {
                            OutlinedButton(
                                onClick = onNavigateToExtractor,
                                modifier = Modifier.testTag("porter_btn_goto_extractor")
                            ) {
                                Icon(imageVector = Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("EXTRACTOR")
                            }
                        }
                    }
                }

                // Button 1: PORT (Requires an extract done by EXTRACTOR)
                Button(
                    onClick = onExecutePort,
                    enabled = !uiState.isBusy && uiState.isExtractReady,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                        .testTag("btn_porter_port")
                ) {
                    Icon(imageVector = Icons.Default.Memory, contentDescription = "PORT")
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "PORT (Créer le Portage Complet vers ${uiState.selectedDecompiledImgName})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                // Button 2: PORTERPLAN (Opens dedicated page)
                Button(
                    onClick = onOpenPorterPlanPage,
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp)
                        .testTag("btn_porter_porterplan")
                ) {
                    Icon(imageVector = Icons.Default.CompareArrows, contentDescription = "PORTERPLAN")
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "PORTERPLAN (Architecture & Comparatif GSI <-> Téléphone)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                // Button 3: FOD (Opens dedicated FOD page with SCAN, AISCAN, FOD Fix 1, 2, 3)
                Button(
                    onClick = onOpenFodPage,
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.tertiary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(54.dp)
                        .testTag("btn_porter_open_fod_page")
                ) {
                    Icon(imageVector = Icons.Default.Fingerprint, contentDescription = "FOD")
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "FOD (SCAN • AISCAN • FOD Fix 1, 2 & 3)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
            }
        }

        // 3. Summary of Last Port Result + Quick Link to CREATION
        if (portResult != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "État Actuel du Portage (${portResult.gsiTargetName})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        text = "• Appareil de référence : ${portResult.stockDeviceBrand} ${portResult.stockDeviceCodename} (${portResult.stockBoardPlatform})\n" +
                                "• Blobs & HALs analysés : ${portResult.proprietaryBlobs.size}\n" +
                                "• Capteur FOD : ${portResult.fodDiagnostics.sensorVendor} (X=${portResult.fodDiagnostics.fodCenterX}, Y=${portResult.fodDiagnostics.fodCenterY}, R=${portResult.fodDiagnostics.fodRadiusPx})\n" +
                                "• Dernier mode FOD appliqué : ${portResult.lastAppliedFodFixMode.ifBlank { "Aucun (Prêt)" }}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )

                    OutlinedButton(
                        onClick = onNavigateToCreation,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("porter_btn_goto_creation")
                    ) {
                        Icon(imageVector = Icons.Default.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Passer à CREATION (Make IMG / Make ROM .zip)")
                    }
                }
            }
        }

        if (portHistory.isNotEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = "Historique des Portages (${portHistory.size})",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.ExtraBold
                    )
                    portHistory.take(4).forEach { item ->
                        Text(
                            text = "• ${item.gsiTargetName} <- ${item.stockDeviceName} (${item.blobsTransplanted} blobs, ${item.fodStatus})",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }
    }
}

// ============================================================================
// 2. PORTERPLAN DEDICATED PAGE (Architecture & Comparative GSI <-> Phone)
// ============================================================================
@Composable
private fun PorterPlanDedicatedPage(
    uiState: KitchenUiState,
    onBack: () -> Unit,
    onRefreshPorterPlan: () -> Unit,
    onNavigateToExtractor: () -> Unit,
    onExecutePort: () -> Unit
) {
    val plan = uiState.gastroPorterPlanReport
    val mechReport = uiState.portAnalysisResult?.gsiMechanismReport

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Top Bar with Back Button
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag("porterplan_btn_back")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Retour vers PORTER"
                        )
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "PORTERPLAN • Architecture & Comparatif",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "GSI (${uiState.selectedDecompiledImgName}) <-> Téléphone (EXTRACT/) • GASTROengine",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    OutlinedButton(
                        onClick = onRefreshPorterPlan,
                        enabled = !uiState.isBusy,
                        modifier = Modifier.testTag("porterplan_btn_refresh")
                    ) {
                        Text("Actualiser")
                    }
                }
            }
        }

        if (plan != null) {
            // Summary of StructureAligner & VintfReconciler
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Synthèse GASTROengine (StructureAligner & VintfReconciler)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        text = "• ADN Téléphone : ${plan.hostDnaSummary}\n" +
                                "• État EXTRACT/ : ${if (plan.extractFolderReady) "PRÊT (${plan.extractFilesCount} fichiers)" else "EN ATTENTE D'EXTRACTOR"}\n" +
                                "• StructureAligner : ${plan.symlinkAlignmentSummary}\n" +
                                "• VintfReconciler : ${plan.vintfReconcileSummary}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            // Detailed Architecture Comparison: How it works in Host ROM vs Why it fails in GSI
            Text(
                text = "Architecture Comparative : Pourquoi les éléments fonctionnent dans votre ROM et pourquoi ils échouent dans le GSI",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.ExtraBold
            )

            plan.architectureComparisons.forEach { diff ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = diff.subsystem,
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = MaterialTheme.colorScheme.primary
                        )

                        Surface(
                            color = Color(0xFF0E2A1E),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "✓ Comment ça fonctionne dans la ROM du téléphone :",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF69F0AE)
                                )
                                Text(
                                    text = diff.howItWorksInHostRom,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color(0xFFE0F2F1)
                                )
                            }
                        }

                        Surface(
                            color = Color(0xFF331518),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "✗ Pourquoi ce n'est pas le cas dans le GSI :",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFFFF8A80)
                                )
                                Text(
                                    text = diff.whyItFailsInUnpackedGsi,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color(0xFFFFEBEE)
                                )
                            }
                        }

                        Text(
                            text = "Éléments à porter vers le GSI :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        diff.elementsToPortFromExtract.forEach { el ->
                            Text(
                                text = "  -> $el",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        Text(
                            text = "Action GASTROengine : ${diff.gastroEngineAlignmentAction}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.secondary,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            // Elements to port list
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Liste Complète des Éléments à Porter vers ${plan.gsiName}",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                    plan.missingBlobsAndConfigs.forEach { item ->
                        Text(
                            text = "• $item",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    HorizontalDivider()
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onNavigateToExtractor,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("EXTRACTOR")
                        }
                        Button(
                            onClick = onExecutePort,
                            enabled = !uiState.isBusy && uiState.isExtractReady,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Lancer PORT")
                        }
                    }
                }
            }
        }

        if (mechReport != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = "Comparatif Détaillé des Interfaces HAL (VintfReconciler)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                    mechReport.vendorHalDiffs.forEach { hal ->
                        Text(
                            text = "• ${hal.halName} (${hal.version} / ${hal.transport}) -> ${hal.statusLabel}\n  ${hal.differenceExplanation}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }
    }
}

// ============================================================================
// 3. FOD DEDICATED PAGE (SCAN, AISCAN, FOD Fix 1, FOD Fix 2, FOD Fix 3)
// ============================================================================
@Composable
private fun PorterFodDedicatedPage(
    uiState: KitchenUiState,
    onBack: () -> Unit,
    onRunScan: () -> Unit,
    onRunAiScan: () -> Unit,
    onApplyFodFix1: () -> Unit,
    onApplyFodFix2: () -> Unit,
    onApplyFodFix3: () -> Unit,
    onNavigateToExtractor: () -> Unit,
    onNavigateToCreation: () -> Unit
) {
    val portResult = uiState.portAnalysisResult
    val totalScan = portResult?.totalScanReport
    val fodStruct = portResult?.fodStructReport
    val aiScan = uiState.gastroAiScanReport
    val recore = uiState.recoreBrainReport

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header with Back button
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag("fod_page_btn_back")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Retour vers PORTER"
                        )
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "FOD • Diagnostic & Ingénierie UDFPS",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Cible : UNPACK/${uiState.selectedDecompiledImgName} • Appui GASTROengine & R.E.C.O.R.E",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        }

        // Section 1: SCAN & AISCAN Buttons
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "1. Analyse Complète du FOD (SCAN Matériel & AISCAN IA + GASTROengine)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.ExtraBold
                )

                Text(
                    text = "• SCAN : Vérifie les éléments extraits par EXTRACTOR et effectue des vérifications poussées sur le téléphone pour identifier ce qui manque concrètement au GSI et pourquoi son FOD ne marche pas.\n" +
                            "• AISCAN : S'appuie sur l'IA gratuite (Gemini / AI Studio avec mécanisme Anti-Quota) et sur GASTROengine pour établir le plan de portage FOD rigoureux.",
                    style = MaterialTheme.typography.bodySmall
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = onRunScan,
                        enabled = !uiState.isBusy,
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                        modifier = Modifier
                            .weight(1f)
                            .height(54.dp)
                            .testTag("btn_fod_scan")
                    ) {
                        Icon(imageVector = Icons.Default.Search, contentDescription = "SCAN")
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "SCAN",
                            fontWeight = FontWeight.ExtraBold
                        )
                    }

                    Button(
                        onClick = onRunAiScan,
                        enabled = !uiState.isBusy,
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                        modifier = Modifier
                            .weight(1f)
                            .height(54.dp)
                            .testTag("btn_fod_aiscan")
                    ) {
                        Icon(imageVector = Icons.Default.AutoAwesome, contentDescription = "AISCAN")
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "AISCAN",
                            fontWeight = FontWeight.ExtraBold
                        )
                    }
                }
            }
        }

        // Section 2: The 3 FOD Fix Buttons (FOD fix 1, FOD fix 2, FOD fix 3)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "2. Corrections FOD (FOD fix 1 • FOD fix 2 • FOD fix 3)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.ExtraBold
                )

                // FOD fix 1: Complete solution
                Button(
                    onClick = onApplyFodFix1,
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                        .testTag("btn_fod_fix_1")
                ) {
                    Icon(imageVector = Icons.Default.Fingerprint, contentDescription = "FOD fix 1")
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(horizontalAlignment = Alignment.Start) {
                        Text(
                            text = "FOD fix 1 (Solution Complète Stock-Grade)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Intégration complète RRO + HAL Blobs + Régénération OAT/VDEX/fsv_meta",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                // FOD fix 2: Workaround / Bidouillage zero-APK-touch
                Button(
                    onClick = onApplyFodFix2,
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                        .testTag("btn_fod_fix_2")
                ) {
                    Icon(imageVector = Icons.Default.Build, contentDescription = "FOD fix 2")
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(horizontalAlignment = Alignment.Start) {
                        Text(
                            text = "FOD fix 2 (Solution Bidouillage • Sans Modif APK)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Hooks Init RC + Keylayout + Props Phh-Treble sur l'OS unpacké sans repacker",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                // FOD fix 3: AI + GASTROengine + R.E.C.O.R.E
                Button(
                    onClick = onApplyFodFix3,
                    enabled = !uiState.isBusy,
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.tertiary),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(60.dp)
                        .testTag("btn_fod_fix_3")
                ) {
                    Icon(imageVector = Icons.Default.AutoAwesome, contentDescription = "FOD fix 3")
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(horizontalAlignment = Alignment.Start) {
                        Text(
                            text = "FOD fix 3 (Assisté par l'IA + GASTROengine + R.E.C.O.R.E)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "StructureAligner + Overlays RRO + VintfReconciler + Preuve Z3 Anti-Bootloop",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }

                if (!portResult?.lastAppliedFodFixMode.isNullOrBlank()) {
                    Surface(
                        color = Color(0xFF0E2A1E),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "✓ Dernier Fix FOD appliqué : ${portResult?.lastAppliedFodFixMode}\n" +
                                    "Moteur de fond R.E.C.O.R.E : Z3=${recore?.smtStatus ?: "SAT"} (Score Boot=${recore?.bootConfidenceScore ?: 100}/100)",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = Color(0xFF69F0AE),
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onNavigateToExtractor,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("EXTRACTOR")
                    }
                    OutlinedButton(
                        onClick = onNavigateToCreation,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("CREATION (Make IMG/ROM)")
                    }
                }
            }
        }

        // Section 3: AI SCAN Report (AiPortingAgent + Anti-Quota + GASTROengine)
        if (aiScan != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.AutoAwesome,
                            contentDescription = "AISCAN Report",
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "Rapport AISCAN (AiPortingAgent & GASTROengine)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Moteur : ${aiScan.engineModelUsed} • Anti-Quota : ${aiScan.antiQuotaState}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }

                    Text(
                        text = "Cause Racine Identifiée :\n${aiScan.rootCauseAnalysis}",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium
                    )

                    HorizontalDivider()
                    Text(
                        text = "Diagnostic Technique GASTROengine (Rust) :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    aiScan.gastroRustDiagnosis.forEach { diag ->
                        Text(
                            text = "  • $diag",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    HorizontalDivider()
                    Text(
                        text = "Plan de Portage Généré par l'IA & GASTROengine :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = aiScan.rawAiMarkdown,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }
            }
        }

        // Section 4: Complete Hardware & EXTRACT SCAN Report
        if (totalScan != null || fodStruct != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Résultat du SCAN Complet (GSI Unpacké <-> EXTRACT & Téléphone)",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )

                    if (fodStruct != null) {
                        Text(
                            text = "Pourquoi le FOD du GSI ne marche pas :\n${fodStruct.rootCauseWhyFodWontWork}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                        HorizontalDivider()
                        Text(
                            text = "Analyse des 5 Couches Matérielles & Logicielles FOD :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        fodStruct.layerNodes.forEach { layer ->
                            Text(
                                text = "• [Couche ${layer.layerOrder}] ${layer.layerName} (${if (layer.presentInGsi) "PRÉSENT" else "MANQUANT"})\n" +
                                        "  Raison échec : ${layer.whyItFailsOnVendor}\n" +
                                        "  Correctif : ${layer.actionPlanStep}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    if (totalScan != null) {
                        if (totalScan.systemToVendorBridgeSummary.isNotBlank()) {
                            Surface(
                                color = Color(0xFF0E2A1E),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = "Pont Dynamique /system <-> /vendor de votre téléphone :\n${totalScan.systemToVendorBridgeSummary}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = Color(0xFF69F0AE),
                                    modifier = Modifier.padding(10.dp)
                                )
                            }
                        }

                        if (totalScan.hostSystemLogicVerified.isNotEmpty()) {
                            HorizontalDivider()
                            Text(
                                text = "1. Vérification de la Partition SYSTÈME (/system, /product, /system_ext) de votre téléphone :",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.ExtraBold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            totalScan.hostSystemLogicVerified.forEach { sysLine ->
                                Text(
                                    text = "  ✓ [SYSTEM] $sysLine",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }

                        if (totalScan.hostVendorLogicVerified.isNotEmpty()) {
                            HorizontalDivider()
                            Text(
                                text = "2. Vérification de la Partition VENDOR (/vendor, /odm, /sys, /dev) de votre téléphone :",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.ExtraBold,
                                color = MaterialTheme.colorScheme.secondary
                            )
                            totalScan.hostVendorLogicVerified.forEach { venLine ->
                                Text(
                                    text = "  ✓ [VENDOR] $venLine",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }

                        HorizontalDivider()
                        Text(
                            text = "Éléments Manquants Concrètement au GSI (${totalScan.missingElementsToPort.size}) :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        totalScan.missingElementsToPort.forEach { miss ->
                            Text(
                                text = "  ✗ $miss",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }

                        HorizontalDivider()
                        Text(
                            text = "Tableau Comparatif (GSI <-> /system + /vendor du Téléphone) :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )
                        totalScan.comparativeItems.forEach { item ->
                            Text(
                                text = "• [${item.componentCategory}] ${item.elementName}\n  GSI=${item.unpackedOsStatus} | Téléphone=${item.hostOrBaseStatus}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }
        }
    }
}
