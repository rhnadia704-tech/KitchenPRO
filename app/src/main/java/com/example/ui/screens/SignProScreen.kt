package com.example.ui.screens

import android.net.Uri
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.modules.signpro.ApkSignTarget
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
    onSignAllInMemory: (Boolean) -> Unit
) {
    var showMacXmlPreview by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategoryFilter by remember { mutableStateOf("CORE_APPS") }

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
                                text = "MODULE 2 • SIGN PRO & AUDIT DE CONFIANCE",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Resignez tous les APKs d'un système UNPACK, signez un APK précis sur place, ou exportez les rapports JSON/TXT dans KEY/Data",
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

            // 2. Batch Sign + Signature Verification Report (KEY/Data)
            item {
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "2. Signature Globale & Audit des Signatures (-> KEY/Data)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { onSignAllInMemory(true) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("sign_all_in_memory_button")
                            ) {
                                Icon(imageVector = Icons.Default.Security, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Tout Signer (${uiState.scannedApks.size})")
                            }

                            FilledTonalButton(
                                onClick = { onVerifyApkSignatures(null) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("verify_all_signatures_button")
                            ) {
                                Icon(imageVector = Icons.Default.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Vérifier (-> KEY/Data)")
                            }

                            FilledTonalButton(
                                onClick = { showMacXmlPreview = !showMacXmlPreview },
                                modifier = Modifier.testTag("toggle_mac_xml_button")
                            ) {
                                Icon(imageVector = Icons.Default.Policy, contentDescription = null, modifier = Modifier.size(18.dp))
                            }
                        }

                        uiState.lastBatchSignResult?.let { res ->
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = "${res.signedSuccess}/${res.totalApks} APKs signés en ${res.elapsedMs}ms (${res.totalBytesProcessed / 1024} KB)",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    Text(
                                        text = "Système mis à jour : ${res.outputDirectoryPath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                }
                            }
                        }

                        uiState.lastSignatureReport?.let { rep ->
                            Surface(
                                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.75f),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Default.Description,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "Rapport de Vérification généré dans KEY/Data (${rep.validCount}/${rep.totalVerified} valides)",
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.onPrimaryContainer
                                        )
                                    }
                                    Text(
                                        text = "JSON : ${rep.jsonReportPath}\nTXT  : ${rep.txtReportPath}",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.onPrimaryContainer
                                    )
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
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text(
                                text = "${uiState.selectedDecompiledImgFullPath}/etc/selinux/plat_mac_permissions.xml",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = uiState.macPermissionsPreview,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
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
                                        text = "Rôle SELinux : ${apk.detectedRole} • Partition : ${apk.partitionCategory} • ${apk.sizeBytes / 1024} KB",
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

                        // Per-APK Direct Actions: Sign ONLY this APK or Verify ONLY this APK (-> KEY/Data)
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
                                Text("Signer cet APK (${apk.detectedRole})", style = MaterialTheme.typography.labelSmall)
                            }

                            OutlinedButton(
                                onClick = { onVerifyApkSignatures(apk) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier.testTag("verify_single_unpack_apk_${apk.name}")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.VerifiedUser,
                                    contentDescription = null,
                                    modifier = Modifier.size(15.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Vérifier", style = MaterialTheme.typography.labelSmall)
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
