package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.modules.signpro.ApkSignTarget
import com.example.modules.signpro.SignatureVerificationEntry
import com.example.ui.KitchenUiState
import com.example.ui.SignProInputMode
import com.example.ui.components.DecompiledImgTargetSelectorCard

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SignProScreen(
    uiState: KitchenUiState,
    onSelectSignMode: (SignProInputMode) -> Unit,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri?) -> Unit,
    onPickSingleApkUri: (Uri?) -> Unit,
    onSelectSingleApkRole: (String) -> Unit,
    onSignSingleApk: () -> Unit,
    onSignIndividualApkInUnpack: (ApkSignTarget) -> Unit,
    onVerifyApkSignatures: (ApkSignTarget?) -> Unit,
    onDiscoverMultiKeysAndDeps: () -> Unit = {},
    onSignAllApksOnly: () -> Unit = {},
    onSignAllInMemory: (Boolean) -> Unit
) {
    val context = LocalContext.current
    var showMacXmlPreview by remember { mutableStateOf(false) }
    var showFullVerificationDetails by remember { mutableStateOf(true) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategoryFilter by remember { mutableStateOf("CORE_APPS") }
    var expandedApkDetailsPath by remember { mutableStateOf<String?>(null) }

    val verifiedEntriesByPath = remember(uiState.lastSignatureReport) {
        uiState.lastSignatureReport?.entries?.associateBy { it.relativePath }.orEmpty()
    }

    val filteredApks by remember(uiState.scannedApks, searchQuery, selectedCategoryFilter) {
        derivedStateOf {
            uiState.scannedApks.filter { apk ->
                val matchesSearch = searchQuery.isBlank() ||
                        apk.name.contains(searchQuery, ignoreCase = true) ||
                        apk.relativePath.contains(searchQuery, ignoreCase = true) ||
                        apk.detectedRole.contains(searchQuery, ignoreCase = true)

                val matchesCategory = when (selectedCategoryFilter) {
                    "CORE_APPS" -> apk.partitionCategory != "overlay"
                    "PRIV_APP" -> apk.partitionCategory == "priv-app" || apk.partitionCategory == "framework"
                    "OVERLAYS" -> apk.partitionCategory == "overlay"
                    else -> true // ALL
                }
                matchesSearch && matchesCategory
            }
        }
    }

    val singleApkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        onPickSingleApkUri(uri)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Bolt,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "MODULE 2 • SIGN PRO & INSPECTEUR DE CLÉS APK",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Resignez un ou tous les APKs avec synchronisation XML intelligente (0 Bootloop), et inspectez la clé publique entière (HEX, PEM, SHA-256/SHA-1/MD5) de chaque APK",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        SignProInputMode.entries.forEach { mode ->
                            FilterChip(
                                selected = uiState.signProMode == mode,
                                onClick = { onSelectSignMode(mode) },
                                label = { Text(mode.label, style = MaterialTheme.typography.labelSmall) },
                                modifier = Modifier.testTag("sign_mode_${mode.name}")
                            )
                        }
                    }
                }
            }
        }

        if (uiState.signProMode == SignProInputMode.DECOMPILED_IMG_FOLDER) {
            // 1. Dropdown Selector for UNPACK systems
            item {
                DecompiledImgTargetSelectorCard(
                    title = "1. Choisir le Système Décompilé dans UNPACK :",
                    availableFolders = uiState.availableDecompiledImgs,
                    selectedFolderName = uiState.selectedDecompiledImgName,
                    selectedFullPath = uiState.selectedDecompiledImgFullPath,
                    onSelectFolder = onSelectDecompiledImg,
                    onPickExternalSafTree = onPickCustomSafTree
                )
            }

            // 2. Batch Sign + Complete Signature & Full Key Verification Report (KEY/Data)
            item {
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "2. Cartographie Multi-Clés, Sign All (APKs) vs Sign All Pro (OS + OAT/VDEX/fsv_meta)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = onSignAllApksOnly,
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("sign_all_apks_only_button")
                            ) {
                                Icon(imageVector = Icons.Default.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Sign All (APKs)")
                            }

                            Button(
                                onClick = { onSignAllInMemory(true) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1.2f)
                                    .testTag("sign_all_in_memory_button")
                            ) {
                                Icon(imageVector = Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Sign All Pro (+OAT/VDEX)")
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilledTonalButton(
                                onClick = onDiscoverMultiKeysAndDeps,
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("discover_multi_keys_button")
                            ) {
                                Icon(imageVector = Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Cartographier Clés")
                            }

                            FilledTonalButton(
                                onClick = {
                                    showFullVerificationDetails = true
                                    onVerifyApkSignatures(null)
                                },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("verify_all_signatures_button")
                            ) {
                                Icon(imageVector = Icons.Default.VerifiedUser, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Vérifier Tout")
                            }

                            FilledTonalButton(
                                onClick = { showMacXmlPreview = !showMacXmlPreview },
                                modifier = Modifier.testTag("toggle_mac_xml_button")
                            ) {
                                Icon(imageVector = Icons.Default.Policy, contentDescription = null, modifier = Modifier.size(18.dp))
                            }
                        }

                        uiState.signProDiscoveryReport?.let { disc ->
                            Surface(
                                color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.65f),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Text(
                                        text = "Cartographie Multi-Clés & Interdépendances : ${disc.totalDistinctKeysDiscovered} Clé(s) détectée(s) et enregistrée(s) sur ${disc.totalApksScanned} APKs",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = MaterialTheme.colorScheme.onTertiaryContainer
                                    )
                                    Text(
                                        text = "Registre enregistré : ${disc.registeredRegistryPath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onTertiaryContainer
                                    )
                                    disc.discoveredCertGroups.forEach { cg ->
                                        Text(
                                            text = "• [${cg.certClusterId}] Rôle='${cg.assignedRoleName}' (${cg.signedApksCount} APKs • SHA256=${cg.originalSha256Short}) | Domaine=${cg.seinfoDomain}\n  APKs co-signés : ${cg.signedApkNames.take(6).joinToString(", ")}${if (cg.signedApkNames.size > 6) "..." else ""}",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onTertiaryContainer
                                        )
                                    }
                                }
                            }
                        }

                        uiState.lastBatchSignResult?.let { res ->
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Text(
                                        text = "${res.signedSuccess}/${res.totalApks} APKs signés en ${res.elapsedMs}ms (${res.totalBytesProcessed / 1024} KB) + Chaîne de Confiance OS R.E.C.O.R.E Synchronisée",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    Text(
                                        text = "Système mis à jour : ${res.outputDirectoryPath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    res.recoreSignReport?.let { recoreRep ->
                                        HorizontalDivider(
                                            color = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.2f)
                                        )
                                        Text(
                                            text = "Audit Pré-Signature R.E.C.O.R.E (${recoreRep.preSignRisksDetected} risques interceptés • ${recoreRep.sharedUidGroupsCount} clusters sharedUserId) :",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.onSecondaryContainer
                                        )
                                        recoreRep.risksAndAlerts.forEach { risk ->
                                            Text(
                                                text = "• [${risk.component}] ${risk.riskDescription}\n  -> Solution Source-Build : ${risk.sourceTreeEquivalentFix}",
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.onSecondaryContainer
                                            )
                                        }
                                        recoreRep.realignmentStepsApplied.forEach { step ->
                                            Text(
                                                text = "✓ $step",
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.SemiBold,
                                                color = MaterialTheme.colorScheme.onSecondaryContainer
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        // Complete Cryptographic Key & Signature Inspector Panel
                        uiState.lastSignatureReport?.let { rep ->
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
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
                                                imageVector = Icons.Default.Key,
                                                contentDescription = null,
                                                tint = MaterialTheme.colorScheme.primary,
                                                modifier = Modifier.size(18.dp)
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Column {
                                                Text(
                                                    text = if (rep.isSingleApkAudit && rep.entries.size == 1)
                                                        "Clé & Signature Complète : ${rep.entries.first().apkName}"
                                                    else
                                                        "Audit Complet des Clés & Signatures (${rep.validCount}/${rep.totalVerified} APKs)",
                                                    style = MaterialTheme.typography.titleSmall,
                                                    fontWeight = FontWeight.ExtraBold
                                                )
                                                Text(
                                                    text = "Exporté dans KEY/Data : JSON & TXT complets",
                                                    style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.primary
                                                )
                                            }
                                        }

                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            IconButton(
                                                onClick = {
                                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                                    clipboard?.setPrimaryClip(ClipData.newPlainText("Rapport Signatures APK", rep.fullTxtContent))
                                                    Toast.makeText(context, "Rapport complet des clés copié !", Toast.LENGTH_SHORT).show()
                                                },
                                                modifier = Modifier.size(34.dp)
                                            ) {
                                                Icon(
                                                    imageVector = Icons.Default.ContentCopy,
                                                    contentDescription = "Copier toutes les clés",
                                                    modifier = Modifier.size(18.dp)
                                                )
                                            }

                                            IconButton(
                                                onClick = { showFullVerificationDetails = !showFullVerificationDetails },
                                                modifier = Modifier.size(34.dp)
                                            ) {
                                                Icon(
                                                    imageVector = if (showFullVerificationDetails) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                                    contentDescription = "Afficher/Masquer les détails"
                                                )
                                            }
                                        }
                                    }

                                    Text(
                                        text = "• JSON : ${rep.jsonReportPath}\n• TXT  : ${rep.txtReportPath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace
                                    )

                                    AnimatedVisibility(visible = showFullVerificationDetails) {
                                        Column(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .heightIn(max = 460.dp)
                                                .verticalScroll(rememberScrollState()),
                                            verticalArrangement = Arrangement.spacedBy(10.dp)
                                        ) {
                                            rep.entries.forEachIndexed { idx, entry ->
                                                FullApkKeyAndSignatureDetailCard(
                                                    index = idx + 1,
                                                    entry = entry,
                                                    context = context
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

            item {
                AnimatedVisibility(visible = showMacXmlPreview) {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant
                        )
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 320.dp)
                                .verticalScroll(rememberScrollState())
                                .padding(14.dp)
                        ) {
                            Text(
                                text = "${uiState.selectedDecompiledImgFullPath}/etc/selinux/plat_mac_permissions.xml",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            SelectionContainer {
                                Text(
                                    text = uiState.macPermissionsPreview,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }

            // 3. Search & Category Filter so SystemUI.apk, Settings.apk, priv-app are front and center
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = { Text("Rechercher un APK (ex: SystemUI, Settings, framework)...") },
                        leadingIcon = { Icon(imageVector = Icons.Default.Search, contentDescription = null) },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("signpro_apk_search_input")
                    )

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        val coreCount = uiState.scannedApks.count { it.partitionCategory != "overlay" }
                        val privCount = uiState.scannedApks.count { it.partitionCategory == "priv-app" || it.partitionCategory == "framework" }
                        val overlayCount = uiState.scannedApks.count { it.partitionCategory == "overlay" }

                        val filters = listOf(
                            "CORE_APPS" to "Apps Système ($coreCount)",
                            "PRIV_APP" to "Priv-App & Framework ($privCount)",
                            "ALL" to "Tous (${uiState.scannedApks.size})",
                            "OVERLAYS" to "Overlays RRO ($overlayCount)"
                        )
                        filters.forEach { (code, label) ->
                            FilterChip(
                                selected = selectedCategoryFilter == code,
                                onClick = { selectedCategoryFilter = code },
                                label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                                modifier = Modifier.testTag("apk_filter_chip_$code")
                            )
                        }
                    }
                }
            }

            items(filteredApks, key = { it.relativePath }) { apk ->
                val verifiedEntry = verifiedEntriesByPath[apk.relativePath]
                val isExpanded = expandedApkDetailsPath == apk.relativePath

                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("apk_item_${apk.name}")
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
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
                                    imageVector = Icons.Default.Android,
                                    contentDescription = null,
                                    tint = if (apk.isSignedWithCustomKey) MaterialTheme.colorScheme.secondary
                                    else MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = apk.name,
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "UNPACK/${uiState.selectedDecompiledImgName}/${apk.relativePath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Text(
                                        text = "Rôle SELinux : ${apk.detectedRole} • Partition : ${apk.partitionCategory} • ${apk.sizeBytes / 1024} KB • SHA256: ${apk.certSha256Short}",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }

                            val badgeContainerColor = when {
                                apk.isSignedWithCustomKey -> MaterialTheme.colorScheme.secondaryContainer
                                apk.detectedRole == "platform" -> MaterialTheme.colorScheme.primaryContainer
                                apk.detectedRole == "media" || apk.detectedRole == "shared" -> MaterialTheme.colorScheme.surfaceVariant
                                else -> MaterialTheme.colorScheme.tertiaryContainer
                            }
                            val badgeTextColor = when {
                                apk.isSignedWithCustomKey -> MaterialTheme.colorScheme.onSecondaryContainer
                                apk.detectedRole == "platform" -> MaterialTheme.colorScheme.onPrimaryContainer
                                apk.detectedRole == "media" || apk.detectedRole == "shared" -> MaterialTheme.colorScheme.onSurfaceVariant
                                else -> MaterialTheme.colorScheme.onTertiaryContainer
                            }

                            Surface(
                                color = badgeContainerColor,
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    if (apk.isSignedWithCustomKey) {
                                        Icon(
                                            imageVector = Icons.Default.CheckCircle,
                                            contentDescription = null,
                                            tint = badgeTextColor,
                                            modifier = Modifier.size(14.dp)
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                    }
                                    Text(
                                        text = apk.currentCertificateLabel,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = badgeTextColor
                                    )
                                }
                            }
                        }

                        // Per-APK Direct Actions: Sign ONLY this APK or Verify & Show Full Key of ONLY this APK
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            FilledTonalButton(
                                onClick = { onSignIndividualApkInUnpack(apk) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("sign_single_unpack_apk_${apk.name}")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Security,
                                    contentDescription = null,
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Signer (${apk.detectedRole})", style = MaterialTheme.typography.labelSmall)
                            }

                            OutlinedButton(
                                onClick = {
                                    expandedApkDetailsPath = if (isExpanded && verifiedEntry != null) null else apk.relativePath
                                    showFullVerificationDetails = true
                                    onVerifyApkSignatures(apk)
                                },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("verify_single_unpack_apk_${apk.name}")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Key,
                                    contentDescription = null,
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = if (isExpanded && verifiedEntry != null) "Masquer Clé" else "Voir Clé & Infos",
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }

                        // Inline Full Key & Signature Details directly inside the APK card when verified!
                        AnimatedVisibility(visible = isExpanded && verifiedEntry != null) {
                            verifiedEntry?.let { entry ->
                                FullApkKeyAndSignatureDetailCard(
                                    index = 1,
                                    entry = entry,
                                    context = context
                                )
                            }
                        }
                    }
                }
            }
        } else {
            // Standalone Single APK Resigning Card
            item {
                val roles = listOf("platform", "media", "shared", "testkey")
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            text = "Resignature d'un Fichier APK Individuel (.apk)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = "Sélectionnez un fichier .apk externe pour le resigner uniquement avec votre clé AOSP vers /storage/emulated/0/ROM_FORGE/PACKED/signed_apks/.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            FilledTonalButton(
                                onClick = { singleApkPicker.launch(arrayOf("application/vnd.android.package-archive", "*/*")) },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("pick_single_apk_button")
                            ) {
                                Icon(imageVector = Icons.Default.FileOpen, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Choisir un .APK")
                            }

                            FilledTonalButton(
                                onClick = { onPickSingleApkUri(null) },
                                modifier = Modifier.testTag("use_sample_single_apk_button")
                            ) {
                                Text("APK Démo")
                            }
                        }

                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "APK Cible : ${uiState.selectedSingleApkName}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                if (uiState.selectedSingleApkPath.isNotEmpty()) {
                                    Text(
                                        text = uiState.selectedSingleApkPath,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }

                        Text(
                            text = "Clé AOSP à utiliser pour la signature :",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold
                        )

                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            roles.forEach { role ->
                                FilterChip(
                                    selected = uiState.selectedSingleApkRole == role,
                                    onClick = { onSelectSingleApkRole(role) },
                                    label = { Text(role) },
                                    modifier = Modifier.testTag("single_apk_role_$role")
                                )
                            }
                        }

                        Button(
                            onClick = onSignSingleApk,
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("sign_single_apk_execute_button")
                        ) {
                            Icon(imageVector = Icons.Default.Security, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Signer uniquement cet APK (-> PACKED/signed_apks)")
                        }

                        if (uiState.lastSingleSignedApkOutPath.isNotEmpty()) {
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = "APK Signé Disponible :",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    Text(
                                        text = uiState.lastSingleSignedApkOutPath,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
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

/**
 * Displays the COMPLETE cryptographic key, digital signature, SHA-256 / SHA-1 / MD5 fingerprints,
 * PEM certificate block, package metadata, SELinux `seinfo` domain, and ZIP alignment details for an APK.
 */
@Composable
private fun FullApkKeyAndSignatureDetailCard(
    index: Int,
    entry: SignatureVerificationEntry,
    context: Context
) {
    var showPemCertificate by remember { mutableStateOf(false) }

    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        SelectionContainer {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "[#$index] ${entry.apkName} (${entry.packageName})",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Chemin : ${entry.relativePath} • ${entry.sizeBytes} octets (${entry.zipEntriesCount} entrées ZIP)",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    AssistChip(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val fullDump = buildString {
                                appendLine("APK: ${entry.apkName} (${entry.packageName})")
                                appendLine("Path: ${entry.absolutePath}")
                                appendLine("Role: ${entry.assignedRole} | SELinux: ${entry.seinfoDomain}")
                                appendLine("SharedUserId: ${entry.sharedUserId}")
                                appendLine("Issuer: ${entry.certificateIssuer}")
                                appendLine("SHA-256: ${entry.sha256DigestFull}")
                                appendLine("SHA-1: ${entry.sha1DigestFull}")
                                appendLine("MD5: ${entry.md5DigestFull}")
                                appendLine("Public Key HEX (<signer signature>): ${entry.fullPublicKeyHex}")
                                appendLine("Signature HEX (CERT.RSA): ${entry.fullCertSignatureHex}")
                                appendLine(entry.fullCertificateBase64Pem)
                            }
                            clipboard?.setPrimaryClip(ClipData.newPlainText("Clé APK ${entry.apkName}", fullDump))
                            Toast.makeText(context, "Clé entière de ${entry.apkName} copiée !", Toast.LENGTH_SHORT).show()
                        },
                        label = { Text("Copier Clé", style = MaterialTheme.typography.labelSmall) },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.ContentCopy,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    )
                }

                HorizontalDivider()

                // Complete Metadata Table
                Text(
                    text = "• Package & UID      : ${entry.packageName} | ${entry.sharedUserId}\n" +
                            "• Partition & Rôle   : ${entry.partition} | Rôle Clé=${entry.assignedRole}\n" +
                            "• Domaine SELinux    : ${entry.seinfoDomain}\n" +
                            "• Émetteur X.509 DN  : ${entry.certificateIssuer}\n" +
                            "• Algorithme & Clé   : ${entry.signatureAlgorithm} (${entry.keySizeBits} bits)\n" +
                            "• En-tête MANIFEST   : ${entry.manifestMfHeaderSummary}\n" +
                            "• Vérification APK   : Statut=${entry.status} | V1_JAR=${entry.v1JarVerified} | V2/V3=${entry.v2v3BlockPresent} | ARSC_STORED_4K=${entry.arscPageAligned}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 16.sp
                )

                // Complete Cryptographic Fingerprints (SHA-256, SHA-1, MD5)
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            text = "EMPREINTES COMPLÈTES DU CERTIFICAT :",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "SHA-256 : ${entry.sha256DigestFull}\n" +
                                    "SHA-1   : ${entry.sha1DigestFull}\n" +
                                    "MD5     : ${entry.md5DigestFull}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.5.sp,
                            lineHeight = 15.sp
                        )
                    }
                }

                // Full Public Key HEX Block (used in plat_mac_permissions.xml <signer signature="...">)
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.35f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            text = "CLÉ PUBLIQUE ENTIÈRE HEX (<signer signature=\"...\"> SELinux) :",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = MaterialTheme.colorScheme.secondary
                        )
                        Text(
                            text = entry.fullPublicKeyHex,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            lineHeight = 14.sp
                        )
                    }
                }

                // Full Digital Signature HEX Block (META-INF/CERT.RSA)
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(8.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(
                            text = "SIGNATURE NUMÉRIQUE ENTIÈRE HEX (META-INF/CERT.RSA) :",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                        Text(
                            text = entry.fullCertSignatureHex,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            lineHeight = 14.sp
                        )
                    }
                }

                // Toggleable Full X.509 PEM Base64 Certificate
                AssistChip(
                    onClick = { showPemCertificate = !showPemCertificate },
                    label = {
                        Text(
                            text = if (showPemCertificate) "Masquer le Certificat X.509 PEM (Base64)"
                            else "Afficher le Certificat X.509 PEM (Base64) Complet",
                            style = MaterialTheme.typography.labelSmall
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Description,
                            contentDescription = null,
                            modifier = Modifier.size(15.dp)
                        )
                    }
                )

                if (showPemCertificate) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = entry.fullCertificateBase64Pem,
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            lineHeight = 14.sp,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
            }
        }
    }
}
