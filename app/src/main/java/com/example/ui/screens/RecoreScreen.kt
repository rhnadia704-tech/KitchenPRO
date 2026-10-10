package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.KitchenUiState
import com.example.ui.components.DecompiledImgTargetSelectorCard

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RecoreScreen(
    uiState: KitchenUiState,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri?) -> Unit,
    onRunRecoreDeepAnalysis: () -> Unit,
    onRunRecoreAutonomousReconstruction: () -> Unit,
    onRunRecoreRegenerateArtifacts: () -> Unit = {}
) {
    val context = LocalContext.current
    val report = uiState.recoreBrainReport
    var selectedSectionIndex by remember { mutableIntStateOf(0) }
    var showSmtFormulaModal by remember { mutableStateOf(false) }
    var showJsonPreview by remember { mutableStateOf(false) }

    val sectionTabs = listOf(
        "Vue Globale & Z3 SMT",
        "SCANNER (${report?.scannerMasterReport?.totalReportsCount ?: 16} Rapports)",
        "COMPARE (Diff & Chaînes)",
        "Partitions & DAG",
        "Symboles ELF & Shims",
        "Init.rc & Sandbox ARM64",
        "Confiance AVB & C-ABI"
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            ElevatedCard(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("recore_hero_card")
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
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.weight(1f)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(44.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(MaterialTheme.colorScheme.primaryContainer),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Psychology,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(28.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "R.E.C.O.R.E • REVERSE COHERENCE ENGINE",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Text(
                                    text = "Cerveau Rust C-ABI (librecore) : Cartographie multi-partition, Graphe DAG, Symboles ELF64, Sandbox ARM64, Solveur Z3 SMT & Self-Healing Shims",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        if (report != null) {
                            val isSat = report.smtStatus == "SAT"
                            Surface(
                                color = if (isSat) MaterialTheme.colorScheme.secondaryContainer
                                else MaterialTheme.colorScheme.errorContainer,
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Column(
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text(
                                        text = "Z3: ${report.smtStatus}",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = if (isSat) MaterialTheme.colorScheme.onSecondaryContainer
                                        else MaterialTheme.colorScheme.onErrorContainer
                                    )
                                    Text(
                                        text = "${report.bootConfidenceScore}/100",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isSat) MaterialTheme.colorScheme.onSecondaryContainer
                                        else MaterialTheme.colorScheme.onErrorContainer
                                    )
                                }
                            }
                        }
                    }

                    // Primary Action Buttons
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilledTonalButton(
                                onClick = onRunRecoreDeepAnalysis,
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("recore_scan_button")
                            ) {
                                Icon(imageVector = Icons.Default.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Analyser & Prouver (Z3)")
                            }

                            Button(
                                onClick = onRunRecoreAutonomousReconstruction,
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("recore_heal_button")
                            ) {
                                Icon(imageVector = Icons.Default.AutoFixHigh, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Reconstruire & Repack 1:1")
                            }
                        }

                        FilledTonalButton(
                            onClick = onRunRecoreRegenerateArtifacts,
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("recore_regenerate_artifacts_button")
                        ) {
                            Icon(imageVector = Icons.Default.Memory, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                if (report != null && report.staleArtifactsNeedingRegenCount > 0) {
                                    "Régénérer (${report.staleArtifactsNeedingRegenCount} Artefacts OAT/VDEX/ODEX/fsv_meta à synchroniser)"
                                } else {
                                    "Régénérer Tous les Artefacts AOSP (.odex, .vdex, .oat, .art, .fsv_meta)"
                                }
                            )
                        }
                    }

                    if (report != null) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Text("PARTITIONS", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                    Text("${report.partitions.size} analysées", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                                }
                            }
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Text("GRAPHE DAG", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                    Text("${report.dagNodes.size} nœuds / ${report.dagEdgesCount} arcs", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                                }
                            }
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Text("SHIMS ELF64", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
                                    Text("${report.generatedShims.size} ponts .so", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Target Unpacked Image Selector
        item {
            DecompiledImgTargetSelectorCard(
                title = "Image Décompilée Cible (UNPACK) pilotée par R.E.C.O.R.E :",
                availableFolders = uiState.availableDecompiledImgs,
                selectedFolderName = uiState.selectedDecompiledImgName,
                selectedFullPath = uiState.selectedDecompiledImgFullPath,
                onSelectFolder = onSelectDecompiledImg,
                onPickExternalSafTree = onPickCustomSafTree
            )
        }

        // Sub-navigation FilterChips for the 5 R.E.C.O.R.E Engineering Views
        item {
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                sectionTabs.forEachIndexed { index, title ->
                    FilterChip(
                        selected = selectedSectionIndex == index,
                        onClick = { selectedSectionIndex = index },
                        label = {
                            Text(
                                text = title,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = if (selectedSectionIndex == index) FontWeight.ExtraBold else FontWeight.Medium
                            )
                        },
                        modifier = Modifier.testTag("recore_subtab_$index")
                    )
                }
            }
        }

        if (report != null) {
            when (selectedSectionIndex) {
                // =========================================================================
                // TAB 0: OVERVIEW, SMT Z3 FORMAL SOLVER & INCREMENTAL FILE WATCHER
                // =========================================================================
                0 -> {
                    val bp = report.initialStructureBlueprint
                    if (bp != null) {
                        item {
                            ElevatedCard(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("recore_initial_blueprint_card")
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.AccountTree,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Column {
                                                Text(
                                                    text = "EMPREINTE STRUCTURE INITIALE & REPACK 1:1 R.E.C.O.R.E",
                                                    style = MaterialTheme.typography.titleSmall,
                                                    fontWeight = FontWeight.ExtraBold
                                                )
                                                Text(
                                                    text = bp.repackExecutionMode,
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.secondary,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                        }

                                        Surface(
                                            color = if (bp.is100PercentIdenticalToInitial) {
                                                MaterialTheme.colorScheme.secondaryContainer
                                            } else {
                                                MaterialTheme.colorScheme.tertiaryContainer
                                            },
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text(
                                                text = if (bp.is100PercentIdenticalToInitial) "100% IDENTIQUE" else "DELTA CHIRURGICAL",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = if (bp.is100PercentIdenticalToInitial) {
                                                    MaterialTheme.colorScheme.onSecondaryContainer
                                                } else {
                                                    MaterialTheme.colorScheme.onTertiaryContainer
                                                },
                                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                            )
                                        }
                                    }

                                    Surface(
                                        color = MaterialTheme.colorScheme.surfaceVariant,
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(3.dp)
                                        ) {
                                            Text(
                                                text = "• Image de Base   : ${bp.baseImageName} (${bp.baseFilesystemFormat}) • Layout : ${bp.baseArchitectureLayout}",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                            Text(
                                                text = "• Géométrie EXT4  : ${bp.baseTotalBlocks} blocs (${bp.baseBlockSize}B) • ${bp.baseTotalInodes} inodes • Mount='${bp.baseMountPoint}'",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                            Text(
                                                text = "• UUID & Extents  : ${bp.baseUuidHex} • ${bp.unmodifiedFilesCount} fichiers intacts • ${bp.totalRecordedExtentsCount} extents",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                            Text(
                                                text = "• Modifications   : ${bp.modifiedFilesPaths.size} modifié(s) | ${bp.addedFilesPaths.size} nouveau(x) fichier(s)/paramètre(s) | ${bp.deletedFilesPaths.size} supprimé(s)",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                fontWeight = FontWeight.Bold,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                            if (bp.lastCompiledOutputImgPath.isNotBlank()) {
                                                Text(
                                                    text = "• Image Générée   : ${bp.lastCompiledOutputImgPath}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontWeight = FontWeight.Bold,
                                                    color = MaterialTheme.colorScheme.secondary
                                                )
                                            }
                                        }
                                    }

                                    bp.chainedCoherenceMechanismsTriggered.forEach { stepLine ->
                                        Text(
                                            text = stepLine,
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }

                                    if (bp.addedFilesPaths.isNotEmpty() || bp.modifiedFilesPaths.isNotEmpty()) {
                                        val previewItems = (bp.modifiedFilesPaths.map { "[MODIFIÉ] $it" } +
                                                bp.addedFilesPaths.map { "[AJOUTÉ] $it" }).take(10)
                                        Text(
                                            text = "Éléments intégrés dans la structure initiale :\n" + previewItems.joinToString("\n"),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }

                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Default.VerifiedUser,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column {
                                            Text(
                                                text = "SOLVEUR DE CONTRAINTES SMT (VÉRIFICATION FORMELLE Z3)",
                                                style = MaterialTheme.typography.titleSmall,
                                                fontWeight = FontWeight.ExtraBold
                                            )
                                            Text(
                                                text = "${report.smtSolverResult.solverEngineName} • ${report.smtSolverResult.satisfiedConstraintsCount}/${report.smtSolverResult.totalConstraintsChecked} clauses satisfaites",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }

                                    FilledTonalButton(
                                        onClick = { showSmtFormulaModal = !showSmtFormulaModal }
                                    ) {
                                        Icon(imageVector = Icons.Default.Code, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(if (showSmtFormulaModal) "Masquer SMT-LIB2" else "SMT-LIB2")
                                    }
                                }

                                AnimatedVisibility(visible = showSmtFormulaModal) {
                                    Surface(
                                        color = MaterialTheme.colorScheme.surfaceVariant,
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Column(modifier = Modifier.padding(10.dp)) {
                                            Text(
                                                text = report.smtSolverResult.smtLib2ExportPreview,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                    }
                                }

                                report.smtSolverResult.clauses.forEach { clause ->
                                    OutlinedCard(
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                    Icon(
                                                        imageVector = if (clause.satisfied) Icons.Default.CheckCircle else Icons.Default.Warning,
                                                        contentDescription = null,
                                                        tint = if (clause.satisfied) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                                                        modifier = Modifier.size(16.dp)
                                                    )
                                                    Spacer(modifier = Modifier.width(6.dp))
                                                    Text(
                                                        text = "${clause.clauseId} (${clause.domainCategory})",
                                                        style = MaterialTheme.typography.labelMedium,
                                                        fontWeight = FontWeight.Bold,
                                                        fontFamily = FontFamily.Monospace
                                                    )
                                                }
                                                Text(
                                                    text = if (clause.satisfied) "SAT" else "UNSAT",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.ExtraBold,
                                                    color = if (clause.satisfied) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error
                                                )
                                            }
                                            Text(
                                                text = clause.formalAssertion,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                            Text(
                                                text = clause.counterExampleOrProof,
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                            if (!clause.satisfied) {
                                                Text(
                                                    text = "Correctif R.E.C.O.R.E : ${clause.autoFixRemediation}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.tertiary,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Incremental File Watcher Card
                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                val fw = report.fileWatcherDelta
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Visibility,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.secondary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "SURVEILLANCE TEMPS RÉEL & INDEXATION INCRÉMENTALE (FILE WATCHER)",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                Text(
                                    text = "• Statut Observer : ${if (fw.observerActive) "ACTIF (FileObserver Linux Inotify)" else "Standby"}\n" +
                                            "• Fichiers indexés : ${fw.totalIndexedFiles} fichiers dans ${report.targetImageName}\n" +
                                            "• Dernier Delta    : ${fw.lastDeltaTimestamp} (${fw.modifiedPathsDelta.size} fichiers modifiés -> ${fw.impactedDagNodesRecalculated} nœuds DAG recalculés)",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                                if (fw.modifiedPathsDelta.isNotEmpty()) {
                                    Text(
                                        text = "Branches delta recalculées : ${fw.modifiedPathsDelta.joinToString(", ")}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 1: MOTEUR SCANNER (16+ RAPPORTS EXHAUSTIFS D'ANALYSE DE L'IMG UNPACKÉ)
                // =========================================================================
                1 -> {
                    val scanner = report.scannerMasterReport
                    if (scanner != null) {
                        item {
                            ElevatedCard(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("recore_scanner_master_card")
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = "MOTEUR SCANNER • ${scanner.totalReportsCount} RAPPORTS EXHAUSTIFS",
                                                style = MaterialTheme.typography.titleSmall,
                                                fontWeight = FontWeight.ExtraBold
                                            )
                                            Text(
                                                text = "Cohérence, Interdépendance, Structure & Format de l'IMG Unpacké (${scanner.targetImageName})",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                        Surface(
                                            color = MaterialTheme.colorScheme.secondaryContainer,
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text(
                                                text = "${scanner.overallCoherencePercent}% COHÉRENT",
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = MaterialTheme.colorScheme.onSecondaryContainer
                                            )
                                        }
                                    }

                                    Text(
                                        text = "• Format de Base : ${scanner.baseFormatSummary}\n" +
                                            "• Topologie SAR  : ${scanner.sarTopologySummary}\n" +
                                            "• Détections     : SHARED_BLOCKS=${scanner.sharedBlocksDetected} | HTree DIR_INDEX=${scanner.htreeIndexedDirsDetected} | AVB Footer=${scanner.avbFooterDetected}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                            }
                        }

                        scanner.reports.forEach { rep ->
                            item {
                                OutlinedCard(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "${rep.reportTitle} [${rep.reportCode}]",
                                                style = MaterialTheme.typography.labelMedium,
                                                fontWeight = FontWeight.ExtraBold,
                                                modifier = Modifier.weight(1f)
                                            )
                                            Surface(
                                                color = MaterialTheme.colorScheme.primaryContainer,
                                                shape = RoundedCornerShape(6.dp)
                                            ) {
                                                Text(
                                                    text = "${rep.status} (${rep.coherenceScore}%)",
                                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.Bold,
                                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                                )
                                            }
                                        }
                                        Text(
                                            text = rep.keyMetricsSummary,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                        rep.findings.forEach { f ->
                                            Text(
                                                text = "• $f",
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                        Text(
                                            text = "Stratégie R.E.C.O.R.E : ${rep.recoreRecommendation}",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.SemiBold,
                                            color = MaterialTheme.colorScheme.secondary
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 2: MOTEUR COMPARE (ÉLÉMENTS NOUVEAUX/MODIFIÉS & CHAÎNES DE FIXATION)
                // =========================================================================
                2 -> {
                    val compare = report.compareEngineReport
                    if (compare != null) {
                        item {
                            ElevatedCard(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("recore_compare_engine_card")
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = "MOTEUR COMPARE • ÉLÉMENTS NOUVEAUX & CHAÎNES DE FIXATION",
                                                style = MaterialTheme.typography.titleSmall,
                                                fontWeight = FontWeight.ExtraBold
                                            )
                                            Text(
                                                text = "Identification chirurgicale des éléments ajoutés/modifiés et communication inter-moteurs",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                        Surface(
                                            color = if (compare.is100PercentIdenticalToBase) {
                                                MaterialTheme.colorScheme.secondaryContainer
                                            } else {
                                                MaterialTheme.colorScheme.tertiaryContainer
                                            },
                                            shape = RoundedCornerShape(8.dp)
                                        ) {
                                            Text(
                                                text = if (compare.is100PercentIdenticalToBase) "100% IDENTIQUE" else "+${compare.addedElementsCount} / ~${compare.modifiedElementsCount}",
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.ExtraBold
                                            )
                                        }
                                    }

                                    Text(
                                        text = "• Fichiers intacts : ${compare.unmodifiedFilesCount} | Nouveaux : ${compare.addedElementsCount} | Modifiés : ${compare.modifiedElementsCount} | Supprimés : ${compare.deletedElementsCount}\n" +
                                            "• Protocole Inter-Moteurs : ${compare.recoreInterEngineProtocolSummary}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace
                                    )

                                    HorizontalDivider()

                                    Text(
                                        text = "Stratégies et Chaînes de Fixation déclenchées par R.E.C.O.R.E :",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold
                                    )
                                    compare.chainedFixStrategies.forEach { st ->
                                        Text(
                                            text = "✓ $st",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                }
                            }
                        }

                        compare.elements.forEach { el ->
                            item {
                                OutlinedCard(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp),
                                        verticalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "[${el.changeKind} • ${el.elementCategory}] ${el.relativePath}",
                                                style = MaterialTheme.typography.labelMedium,
                                                fontWeight = FontWeight.Bold,
                                                fontFamily = FontFamily.Monospace,
                                                modifier = Modifier.weight(1f)
                                            )
                                            Text(
                                                text = el.bootRiskLevel,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = MaterialTheme.colorScheme.secondary
                                            )
                                        }
                                        Text(
                                            text = "Taille : ${el.sizeBytes}B (Base=${el.baseSizeBytes}B) • Chaîne requise=${el.requiresChainedFix}",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace
                                        )
                                        el.requiredFixChain.forEach { step ->
                                            Text(
                                                text = "  -> $step",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                        Text(
                                            text = "Action R.E.C.O.R.E : ${el.recoreActionApplied}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 3: MULTI-PARTITION MAPPING & MULTI-LAYER DEPENDENCY GRAPH (DAG)
                // =========================================================================
                3 -> {
                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Layers,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "CARTOGRAPHIE MULTI-PARTITION (SYSTEM, VENDOR, PRODUCT, SYSTEM_EXT, APEX, BOOT, ODM)",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.ExtraBold
                                    )
                                }

                                report.partitions.forEach { part ->
                                    OutlinedCard(
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Text(
                                                    text = "${part.partitionName.uppercase()} (${part.canonicalMountPoint})",
                                                    style = MaterialTheme.typography.labelMedium,
                                                    fontWeight = FontWeight.ExtraBold
                                                )
                                                Text(
                                                    text = part.detectedTopology,
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = if (part.healthy) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                                                    fontWeight = FontWeight.Bold
                                                )
                                            }
                                            Text(
                                                text = "Chemin réel UNPACK : ${part.physicalPathInUnpack} | ${part.filesCount} fichiers | ${part.elfBinariesCount} ELF | ${part.apksAndApexCount} APK/APEX",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                            Text(
                                                text = part.symlinkStatus,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Hub,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.secondary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = "GRAPHE DE DÉPENDANCES MULTI-COUCHES (DAG)",
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                        Text(
                                            text = "${report.dagNodes.size} nœuds et ${report.dagEdgesCount} interdépendances logiques (Fichiers <-> ELF <-> Init <-> HAL <-> SELinux)",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }

                                report.dagNodes.forEach { node ->
                                    OutlinedCard(
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Text(
                                                    text = "[${node.layer}] ${node.label}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace,
                                                    modifier = Modifier.weight(1f)
                                                )
                                                Text(
                                                    text = node.status,
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.ExtraBold,
                                                    color = if (node.status == "MISSING_DEP") MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary
                                                )
                                            }
                                            if (node.dependsOnNodeIds.isNotEmpty()) {
                                                Text(
                                                    text = "Dépend de -> ${node.dependsOnNodeIds.joinToString(", ")}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.primary,
                                                    fontFamily = FontFamily.Monospace
                                                )
                                            }
                                            Text(
                                                text = node.detail,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 4: ELF64 SYMBOLS (DT_NEEDED) & AUTOMATIC BINARY SHIM GENERATOR
                // =========================================================================
                4 -> {
                    if (report.generatedShims.isNotEmpty()) {
                        item {
                            ElevatedCard(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.elevatedCardColors(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                                )
                            ) {
                                Column(
                                    modifier = Modifier.padding(16.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Text(
                                        text = "SELF-HEALING BINAIRE : PONTS SHIM ELF64 ACTIFS (${report.generatedShims.size})",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    report.generatedShims.forEach { shim ->
                                        Text(
                                            text = "✓ ${shim.installedRelativePath} (${shim.elfSizeBytes} octets | ${shim.selinuxContext})\n" +
                                                    "  Cible : ${shim.targetProprietaryBlob}\n" +
                                                    "  Symboles C/C++ ré-exportés : ${shim.bridgedMissingSymbols.joinToString(", ")}",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSecondaryContainer
                                        )
                                    }
                                }
                            }
                        }
                    }

                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Memory,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "INSPECTION & RÉSOLUTION DES SYMBOLES ELF (.SO & EXÉCUTABLES)",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.ExtraBold
                                    )
                                }

                                report.elfAudits.forEach { elf ->
                                    OutlinedCard(
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Text(
                                                    text = elf.binaryRelativePath,
                                                    style = MaterialTheme.typography.labelMedium,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace,
                                                    modifier = Modifier.weight(1f)
                                                )
                                                Text(
                                                    text = if (elf.shimGenerated) "SHIM ACTIF"
                                                    else if (elf.missingLibraries.isEmpty() && elf.unresolvedSymbols.isEmpty()) "OK"
                                                    else "SYMBOLE MANQUANT",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.ExtraBold,
                                                    color = if (elf.missingLibraries.isEmpty() && elf.unresolvedSymbols.isEmpty()) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error
                                                )
                                            }
                                            Text(
                                                text = "DT_NEEDED : ${elf.dtNeededLibs.joinToString(", ")}",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                            Text(
                                                text = "Exports C/C++ : ${elf.exportedSymbolsSample.joinToString(", ")}",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                            if (elf.unresolvedSymbols.isNotEmpty()) {
                                                Text(
                                                    text = "Non résolus : ${elf.unresolvedSymbols.joinToString(", ")}",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontFamily = FontFamily.Monospace,
                                                    color = MaterialTheme.colorScheme.error
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 5: INIT.RC BOOT SEQUENCE SIMULATION & PRE-BOOT ARM64 SANDBOX
                // =========================================================================
                5 -> {
                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                val sb = report.sandboxTrace
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.DeveloperBoard,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = "SANDBOX PRÉ-BOOT ARM64 (INIT & LINKER64)",
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                        Text(
                                            text = "${sb.sandboxArch} • Verdict : ${sb.sandboxVerdict}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.secondary,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }

                                Surface(
                                    color = MaterialTheme.colorScheme.surfaceVariant,
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(
                                        modifier = Modifier.padding(12.dp),
                                        verticalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        sb.simulatedSteps.forEach { line ->
                                            Text(
                                                text = line,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.PlayArrow,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.secondary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "PARSING & SIMULATION DES SCRIPTS INIT.RC (${report.initSimulationSteps.size} ÉTAPES)",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.ExtraBold
                                    )
                                }

                                report.initSimulationSteps.forEach { step ->
                                    OutlinedCard(
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(10.dp),
                                            verticalArrangement = Arrangement.spacedBy(4.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Text(
                                                    text = "#${step.stageOrder} [${step.triggerName}]",
                                                    style = MaterialTheme.typography.labelMedium,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace
                                                )
                                                Text(
                                                    text = step.simulatedStatus,
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = FontWeight.ExtraBold,
                                                    color = if (step.simulatedStatus == "PASS") MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error
                                                )
                                            }
                                            Text(
                                                text = "Fichier : ${step.sourceRcFile} | Domaine : ${step.selinuxDomain}",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                color = MaterialTheme.colorScheme.primary
                                            )
                                            Text(
                                                text = step.diagnosticNote,
                                                style = MaterialTheme.typography.bodySmall
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // =========================================================================
                // TAB 6: INTERNAL TRUST CHAIN (AVB 2.0 / APK / APEX) & HEADLESS C-ABI FFI
                // =========================================================================
                6 -> {
                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                val tc = report.trustChain
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Security,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "SYSTÈME DE CONFIANCE INTERNE (AVB 2.0, DM-VERITY, VBMETA, X.509 & APKS)",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.ExtraBold
                                    )
                                }

                                Text(
                                    text = "• AVB & VBMeta       : ${tc.avbVersion} (VBMeta valide=${tc.vbmetaStructValid})\n" +
                                            "• Mode dm-verity     : ${tc.dmVerityMode}\n" +
                                            "• Tags build.prop    : ${tc.buildTagsMode}\n" +
                                            "• Magasin otacerts   : ${if (tc.otaCertsSynced) "Synchronisé (otacerts.zip)" else "À synchroniser"}\n" +
                                            "• SELinux MAC XML    : ${if (tc.macPermissionsSynced) "Synchronisé (plat_mac_permissions.xml)" else "À synchroniser"}\n" +
                                            "• Signatures APK/JAR : ${tc.alignedAndSignedApks}/${tc.totalApksAudited} APKs signés & alignés 4K | ${tc.apexContainersAudited} APEX",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )

                                if (tc.realignmentActionsApplied.isNotEmpty()) {
                                    HorizontalDivider()
                                    Text(
                                        text = "Ré-alignements de confiance appliqués par R.E.C.O.R.E :",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.secondary
                                    )
                                    tc.realignmentActionsApplied.forEach { act ->
                                        Text(
                                            text = "✓ $act",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                }
                            }
                        }
                    }

                    item {
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                val cabi = report.cAbiDescriptor
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "ARCHITECTURE HEADLESS C-ABI / FFI & EXPORT PROTOBUF / JSON",
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                        Text(
                                            text = "${cabi.libraryName} • ${cabi.abiVersion}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                    }

                                    FilledTonalButton(
                                        onClick = {
                                            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                            cm.setPrimaryClip(ClipData.newPlainText("RECORE_JSON", report.structuredJsonPreview))
                                            Toast.makeText(context, "Rapport JSON R.E.C.O.R.E copié", Toast.LENGTH_SHORT).show()
                                        }
                                    ) {
                                        Icon(imageVector = Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Copier JSON")
                                    }
                                }

                                Text(
                                    text = "• Export JSON     : ${cabi.jsonReportPath}\n" +
                                            "• Export Protobuf : ${cabi.protobufReportPath} (${cabi.protobufWireSizeBytes} octets wire-format)\n" +
                                            "• CLI Headless    : ${cabi.headlessCliCommand}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )

                                Surface(
                                    color = MaterialTheme.colorScheme.surfaceVariant,
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(
                                        modifier = Modifier.padding(10.dp),
                                        verticalArrangement = Arrangement.spacedBy(3.dp)
                                    ) {
                                        Text(
                                            text = "Table des Symboles C-ABI Exportés (librecore.h) :",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.primary
                                        )
                                        cabi.exportedSymbols.forEach { fn ->
                                            Text(
                                                text = fn,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                    }
                                }

                                FilledTonalButton(
                                    onClick = { showJsonPreview = !showJsonPreview },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(if (showJsonPreview) "Masquer l'aperçu JSON structuré" else "Afficher le rapport JSON structuré R.E.C.O.R.E")
                                }

                                AnimatedVisibility(visible = showJsonPreview) {
                                    Surface(
                                        color = MaterialTheme.colorScheme.surfaceVariant,
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(
                                            text = report.structuredJsonPreview,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            modifier = Modifier.padding(10.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(18.dp)) }
    }
}
