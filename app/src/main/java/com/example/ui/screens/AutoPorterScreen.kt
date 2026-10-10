package com.example.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.DeveloperBoard
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.data.local.PortHistoryEntity
import com.example.modules.porter.FodLayerNode
import com.example.modules.porter.FodStructScanReport
import com.example.modules.porter.FodTotalComparativeScanReport
import com.example.modules.porter.GsiMechanismAndVendorReport
import com.example.modules.porter.ProprietaryBlobItem
import com.example.ui.KitchenUiState

@Composable
fun AutoPorterScreen(
    uiState: KitchenUiState,
    portHistory: List<PortHistoryEntity>,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri?) -> Unit,
    onExecuteExtractMe: (combineWithUseBase: Boolean) -> Unit,
    onExecuteUseBaseLineageTucana: (keepExtractMeParallel: Boolean) -> Unit,
    onExecutePortageToUnpackedGsi: () -> Unit,
    onInspectGsiMechanism: () -> Unit,
    onScanFodStruct: () -> Unit,
    onRunFodTotalComparativeScan: () -> Unit,
    onApplyFodFixUnpackOnlyZeroApk: () -> Unit,
    onFixFodCoherentStock: () -> Unit,
    onFixFodOverlayOnlyZeroSign: () -> Unit,
    onNavigateToCompiler: () -> Unit = {},
    onNavigateToRecore: () -> Unit = {}
) {
    val portResult = uiState.portAnalysisResult
    val isBusy = uiState.isBusy
    var selectedTab by remember { mutableIntStateOf(0) }
    var dropdownExpanded by remember { mutableStateOf(false) }
    var useExtractMeActive by remember { mutableStateOf(true) }
    var useBaseTucanaActive by remember { mutableStateOf(true) }

    val customTreeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) onPickCustomSafTree(uri)
    }

    val tabs = listOf(
        "FOD & TOTAL SCAN (${portResult?.totalScanReport?.comparativeItems?.size ?: portResult?.fodStructReport?.layerNodes?.size ?: 0})",
        "Mécanisme GSI/Vendor (${portResult?.gsiMechanismReport?.vendorHalDiffs?.size ?: 0})",
        "Blobs (${portResult?.proprietaryBlobs?.size ?: 0})",
        "Device Tree .mk & Historique (${portHistory.size})"
    )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 1. HEADER & DROPDOWN LIST OF UNPACKED FOLDERS
        item {
            ElevatedCard(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.elevatedCardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.AccountTree,
                            contentDescription = "PORTER Hub",
                            modifier = Modifier.size(30.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "PORTER Refonte Totale • ExtractMe + USE Base + FOD Suite",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Text(
                                text = "Portage Système/Vendor vers GSI Unpacké • Zéro risque de bootloop (idmap2 / secilc / libvintf Safe)",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.85f)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = "1. Champ avec Liste Déroulante des Dossiers Unpackés (ROM_FORGE/UNPACK) :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Spacer(modifier = Modifier.height(6.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Box(modifier = Modifier.weight(1f)) {
                            OutlinedCard(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable(enabled = !isBusy) { dropdownExpanded = true }
                                    .testTag("porter_unpacked_dropdown"),
                                colors = CardDefaults.outlinedCardColors(
                                    containerColor = MaterialTheme.colorScheme.surface
                                )
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.FolderOpen,
                                            contentDescription = "Dossier Unpacké",
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(20.dp)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column {
                                            Text(
                                                text = uiState.selectedDecompiledImgName.ifBlank { "Sélectionner un dossier unpacké..." },
                                                style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                text = uiState.selectedDecompiledImgFullPath,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontFamily = FontFamily.Monospace,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                    Icon(
                                        imageVector = Icons.Default.ArrowDropDown,
                                        contentDescription = "Ouvrir la liste déroulante"
                                    )
                                }
                            }

                            DropdownMenu(
                                expanded = dropdownExpanded,
                                onDismissRequest = { dropdownExpanded = false },
                                modifier = Modifier.fillMaxWidth(0.85f)
                            ) {
                                if (uiState.availableDecompiledImgs.isEmpty()) {
                                    DropdownMenuItem(
                                        text = { Text("Aucun dossier unpacké trouvé (Décompilez d'abord un .img)") },
                                        onClick = { dropdownExpanded = false }
                                    )
                                } else {
                                    uiState.availableDecompiledImgs.forEach { folderName ->
                                        DropdownMenuItem(
                                            text = {
                                                Column {
                                                    Text(
                                                        text = "UNPACK/$folderName",
                                                        fontWeight = FontWeight.Bold
                                                    )
                                                    Text(
                                                        text = "${uiState.romForgePublicPath}/UNPACK/$folderName",
                                                        style = MaterialTheme.typography.labelSmall,
                                                        fontFamily = FontFamily.Monospace
                                                    )
                                                }
                                            },
                                            onClick = {
                                                onSelectDecompiledImg(folderName)
                                                dropdownExpanded = false
                                            }
                                        )
                                    }
                                }
                            }
                        }

                        OutlinedButton(
                            onClick = { customTreeLauncher.launch(null) },
                            enabled = !isBusy,
                            modifier = Modifier.testTag("porter_saf_folder_btn")
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = "SAF", modifier = Modifier.size(18.dp))
                        }
                    }
                }
            }
        }

        // 2. EXTRACTME (ROOT) + EN PARALLÈLE USE BASE (LINEAGEOS 24.0 XIAOMI TUCANA) + BOUTON PORTAGE
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "2. Extraction Composants System/Vendor & Base LineageOS 24.0 Tucana",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                    Text(
                        text = "• ExtractMe (Root) : Extrait les HALs, blobs et composants de /system et /vendor de la ROM actuelle sur laquelle l'application est installée.\n" +
                            "• USE Base (Sans Root ou En Parallèle) : Utilise les éléments intégrés de LineageOS android_device_xiaomi_tucana & branche lineage-24.0 (SM6150 / Goodix GF9518 / HBM 0x20000). Utilisable sans root ou en parallèle avec ExtractMe pour un résultat optimal.\n" +
                            "• PORTAGE : Porte tous les éléments de la ROM actuelle vers le dossier d'image unpacké en prenant comme fondement ExtractMe, USE Base ou les deux combinés.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.9f)
                    )

                    // Parallel buttons: ExtractMe & USE Base
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                useExtractMeActive = true
                                onExecuteExtractMe(useBaseTucanaActive)
                            },
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("porter_extract_me_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.tertiary
                            )
                        ) {
                            Icon(Icons.Default.Terminal, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("ExtractMe (Root)", fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = {
                                useBaseTucanaActive = true
                                onExecuteUseBaseLineageTucana(useExtractMeActive)
                            },
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("porter_use_base_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.secondary
                            )
                        ) {
                            Icon(Icons.Default.DeveloperBoard, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("USE Base (Tucana)", fontWeight = FontWeight.Bold)
                        }
                    }

                    // Active source toggles for combined usage
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Fondement actif :",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        FilterChip(
                            selected = useExtractMeActive,
                            onClick = { useExtractMeActive = !useExtractMeActive },
                            label = { Text("ExtractMe (Host System/Vendor)") },
                            modifier = Modifier.testTag("toggle_use_extractme")
                        )
                        FilterChip(
                            selected = useBaseTucanaActive,
                            onClick = { useBaseTucanaActive = !useBaseTucanaActive },
                            label = { Text("USE Base (LineageOS 24.0 Tucana)") },
                            modifier = Modifier.testTag("toggle_use_base")
                        )
                    }

                    // Display active source summary if available
                    portResult?.sourceExtractionSummary?.let { ext ->
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(10.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = "Mode Source Actif : ${ext.activeSourceModeLabel}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = "Root: ${if (ext.rootProbedSuccess) "Confirmé (uid=0)" else "Lecture Live Directe"} • System Hôte: ${ext.extractedHostSystemFilesCount} • Vendor Hôte: ${ext.extractedHostVendorFilesCount} • Base Tucana (lineage-24.0): ${ext.useBaseTucanaElementsCount} composants",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                                ext.extractedElementsPreview.take(4).forEach { line ->
                                    Text(
                                        text = "• $line",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }

                    // PORTAGE button
                    Button(
                        onClick = onExecutePortageToUnpackedGsi,
                        enabled = !isBusy,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("porter_portage_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary
                        )
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "PORTAGE (Porter tous les éléments vers ${uiState.selectedDecompiledImgName})",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        // 3. PARTIE FOD : Scan FOD + TOTAL SCAN + FOD Fix (Sans Repack, Sans Toucher APK) + En Parallèle FOD Fix PRO (Stock ROM Totale)
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.72f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Fingerprint,
                            contentDescription = "FOD Suite",
                            tint = MaterialTheme.colorScheme.onTertiaryContainer,
                            modifier = Modifier.size(26.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "3. Partie FOD (Scan FOD • TOTAL SCAN • FOD Fix • FOD Fix PRO)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onTertiaryContainer
                            )
                            Text(
                                text = "Analyse comparative OS Unpacké <-> Système Hôte et correction FOD sans risque de bootloop",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.85f)
                            )
                        }
                    }

                    // Row 1: Scan FOD & TOTAL SCAN
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onScanFodStruct,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("fod_scan_struct_button")
                        ) {
                            Icon(Icons.Default.Science, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Scan FOD (OS Unpacké)", fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = onRunFodTotalComparativeScan,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("fod_total_scan_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.secondary
                            )
                        ) {
                            Icon(Icons.Default.CompareArrows, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("TOTAL SCAN (Comparatif)", fontWeight = FontWeight.Bold)
                        }
                    }

                    HorizontalDivider(color = MaterialTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.2f))

                    Text(
                        text = "• FOD Fix (Sans Repack • Sans modifier les APKs internes) : Applique les fixes et corrections FOD au GSI unpacké sans le repacker et sans modifier les APKs internes (0 risque de bootloop).\n" +
                            "• En parallèle : FOD Fix PRO (Implémentation Stock ROM Totale) : Fixe le FOD comme si le FOD de l'img unpacké était implémenté comme une vraie Stock ROM (refonte totale du FOD dans l'img unpacké).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.9f)
                    )

                    // Row 2: FOD Fix (Unpack-only, zero APK touch) & FOD Fix PRO (Stock ROM Total Implementation)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onApplyFodFixUnpackOnlyZeroApk,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("fod_fix_unpack_only_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Icon(Icons.Default.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("FOD Fix (Sans APK / Sans Repack)", fontWeight = FontWeight.Bold)
                        }

                        Button(
                            onClick = onFixFodCoherentStock,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("fod_fix_pro_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.tertiary
                            )
                        ) {
                            Icon(Icons.Default.Verified, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("FOD Fix PRO (Stock ROM)", fontWeight = FontWeight.Bold)
                        }
                    }

                    // Secondary buttons: Inspect Mechanism & Navigate to R.E.C.O.R.E / Compilator
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = onInspectGsiMechanism,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("porter_inspect_mech_button")
                        ) {
                            Icon(Icons.Default.Layers, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Inspecter GSI <-> Vendor")
                        }

                        OutlinedButton(
                            onClick = onNavigateToRecore,
                            enabled = !isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("porter_goto_recore_button")
                        ) {
                            Icon(Icons.Default.Memory, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Ouvrir R.E.C.O.R.E ->")
                        }
                    }

                    if (!portResult?.lastAppliedFodFixMode.isNullOrBlank()) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "Dernière Opération FOD Appliquée : ${portResult?.lastAppliedFodFixMode}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF2E7D32)
                                )
                                Text(
                                    text = "Sortie Dossier : ${portResult?.portOutputDirectoryPath}\nStatut Image : ${portResult?.portedSystemImgPath}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }
        }

        // 4. DIAGNOSTIC TABS & DETAILED REPORTS
        if (portResult != null) {
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    tabs.forEachIndexed { index, title ->
                        FilterChip(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            label = { Text(title) },
                            modifier = Modifier.testTag("porter_tab_$index")
                        )
                    }
                }
            }

            when (selectedTab) {
                0 -> {
                    // Show TOTAL SCAN Comparative Report if available
                    portResult.totalScanReport?.let { totalScan ->
                        item {
                            FodTotalComparativeScanCard(totalScan)
                        }
                    }
                    // Show FODstruct Report
                    portResult.fodStructReport?.let { fodStruct ->
                        item {
                            FodStructOverviewCard(fodStruct)
                        }
                        items(fodStruct.layerNodes) { layer ->
                            FodLayerNodeCard(layer)
                        }
                    }
                }

                1 -> {
                    portResult.gsiMechanismReport?.let { mech ->
                        item {
                            GsiMechanismReportCard(mech)
                        }
                    }
                }

                2 -> {
                    items(portResult.proprietaryBlobs) { blob ->
                        ProprietaryBlobItemCard(blob)
                    }
                }

                3 -> {
                    item {
                        DeviceTreeMakefileAndHistoryCard(
                            makefileContent = portResult.lineageDeviceMkContent,
                            portHistory = portHistory
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun FodTotalComparativeScanCard(report: FodTotalComparativeScanReport) {
    val readyCount = report.comparativeItems.count { it.readyInUnpacked }
    val totalCount = report.comparativeItems.size.coerceAtLeast(1)
    val readyPct = (readyCount * 100) / totalCount

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "TOTAL SCAN Comparatif (OS Unpacké <-> Système Hôte + Base Tucana)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = if (readyPct == 100) Color(0xFF2E7D32) else MaterialTheme.colorScheme.primary
                ) {
                    Text(
                        text = "$readyPct% Prêt ($readyCount/$totalCount)",
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
            }

            Text(
                text = "• OS Unpacké : ${report.unpackedOsName}\n" +
                    "• Système Hôte : ${report.hostSystemDeviceSummary}\n" +
                    "• Référence Base : ${report.baseReferenceSummary}\n" +
                    "• Liaison Moteurs : ${report.coherenceWithScannerAndCompare}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )

            HorizontalDivider()

            Text(
                text = "Éléments comparés (OS Unpacké vs Système Hôte / Base Tucana) :",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )

            report.comparativeItems.forEach { item ->
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "[${item.componentCategory}] ${item.elementName}",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                text = item.unpackedOsStatus,
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                color = if (item.readyInUnpacked) Color(0xFF2E7D32) else MaterialTheme.colorScheme.error
                            )
                        }
                        Text(
                            text = "Source Hôte/Base : ${item.hostOrBaseStatus}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Action de Portage : ${item.portActionRequired}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            HorizontalDivider()

            Text(
                text = "Éléments Manquants à Porter :",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            report.missingElementsToPort.forEach { missing ->
                Text(
                    text = "• $missing",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            HorizontalDivider()

            Text(
                text = "Stratégie de Portage FOD Recommandée :",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            report.fodPortingStrategySteps.forEach { step ->
                Text(
                    text = step,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
            }
        }
    }
}

@Composable
private fun FodStructOverviewCard(report: FodStructScanReport) {
    val activeLayers = report.layerNodes.count { it.presentInGsi }
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Scan FOD (OS Unpacké : ${report.scannedGsiName})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "Architecture : ${report.fodArchitectureType} • Topologie : ${report.topologyLabel}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = if (activeLayers == report.layerNodes.size) Color(0xFF2E7D32) else MaterialTheme.colorScheme.primary
                ) {
                    Text(
                        text = "$activeLayers/${report.layerNodes.size} Couches",
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Text(
                text = "Diagnostic : ${report.rootCauseWhyFodWontWork}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (report.stockGradeFixApplied && report.stockGradeFixSummary.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = "Résumé du Fix FOD Appliqué :",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF2E7D32)
                )
                report.stockGradeFixSummary.forEach { line ->
                    Text(
                        text = "✓ $line",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}

@Composable
private fun FodLayerNodeCard(layer: FodLayerNode) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Icon(
                        imageVector = if (layer.presentInGsi) Icons.Default.CheckCircle else Icons.Default.Warning,
                        contentDescription = null,
                        tint = if (layer.presentInGsi) Color(0xFF2E7D32) else MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "Couche ${layer.layerOrder} : ${layer.layerName}",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = layer.componentPath,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = if (layer.presentInGsi) Color(0xFF2E7D32).copy(alpha = 0.15f)
                    else MaterialTheme.colorScheme.errorContainer
                ) {
                    Text(
                        text = if (layer.presentInGsi) "PRÉSENT" else "À CORRIGER",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (layer.presentInGsi) Color(0xFF2E7D32) else MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
            Text(
                text = "État : ${layer.currentArchitectureDetail}",
                style = MaterialTheme.typography.bodySmall
            )
            Text(
                text = "Action : ${layer.actionPlanStep}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
private fun GsiMechanismReportCard(report: GsiMechanismAndVendorReport) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = "Mécanisme GSI (${report.gsiName}) • Android ${report.gsiAndroidRelease} (SDK ${report.gsiSdkLevel})",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = "Architecture Treble : ${report.trebleArchitecture} • VNDK : ${report.gsiVndkVersion}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            HorizontalDivider()
            Text(
                text = "Interfaces HAL Comparées (${report.vendorHalDiffs.size}) :",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold
            )
            report.vendorHalDiffs.forEach { diff ->
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            text = "${diff.halName} @${diff.version} (${diff.transport}) — ${diff.statusLabel}",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                        Text(
                            text = diff.differenceExplanation,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ProprietaryBlobItemCard(blob: ProprietaryBlobItem) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Icon(
                        imageVector = Icons.Default.Storage,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = blob.relativePath,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer
                ) {
                    Text(
                        text = blob.subsystem,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
            Text(
                text = "Arch : ${blob.elfArch} • DT_NEEDED : ${blob.dtNeededLibs.joinToString(", ")}",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun DeviceTreeMakefileAndHistoryCard(
    makefileContent: String,
    portHistory: List<PortHistoryEntity>
) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Tune,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Configuration LineageOS device_tucana.mk & Historique de Portage",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                    .padding(10.dp)
            ) {
                Text(
                    text = makefileContent,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace
                )
            }
            if (portHistory.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = "Historique des Portages (${portHistory.size}) :",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                portHistory.take(5).forEach { entry ->
                    Text(
                        text = "• ${entry.stockDeviceName} -> ${entry.gsiTargetName} | Blobs=${entry.blobsTransplanted} | FOD=${entry.fodStatus}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
    }
}
