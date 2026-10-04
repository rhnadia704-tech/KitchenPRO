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
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Policy
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
    onSignAllInMemory: (Boolean) -> Unit
) {
    var showMacXmlPreview by remember { mutableStateOf(false) }

    val singleApkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        onPickSingleApkUri(uri)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            // Mode Switcher Card: Decompiled .IMG vs Standalone .APK
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
                                text = "MODULE 2 • SIGN PRO (IMG DÉCOMPILÉ OU APK INDIVIDUEL)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Choisissez entre signer tous les APKs d'un .img décompilé ou resigner un fichier .apk unique dans ROM_FORGE",
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
            // 1. Decompiled IMG Folder Target Selector
            item {
                DecompiledImgTargetSelectorCard(
                    title = "1. Sélectionner l'IMG Décompilé contenant les APKs :",
                    availableFolders = uiState.availableDecompiledImgs,
                    selectedFolderName = uiState.selectedDecompiledImgName,
                    selectedFullPath = uiState.selectedDecompiledImgFullPath,
                    onSelectFolder = onSelectDecompiledImg,
                    onPickExternalSafTree = onPickCustomSafTree
                )
            }

            // 2. Batch Sign Action Card
            item {
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text(
                            text = "2. Resignature Massive In-Memory & Injection SELinux",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Button(
                                onClick = { onSignAllInMemory(true) },
                                enabled = !uiState.isBusy,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("sign_all_in_memory_button")
                            ) {
                                Icon(imageVector = Icons.Default.Security, contentDescription = null)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Resigner l'IMG (${uiState.scannedApks.size} APKs)")
                            }

                            FilledTonalButton(
                                onClick = { showMacXmlPreview = !showMacXmlPreview },
                                modifier = Modifier.testTag("toggle_mac_xml_button")
                            ) {
                                Icon(imageVector = Icons.Default.Policy, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("XML")
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
                                        text = "${res.signedSuccess}/${res.totalApks} APKs signés en ${res.elapsedMs}ms (${res.totalBytesProcessed / 1024} KB I/O)",
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer
                                    )
                                    Text(
                                        text = "Sortie : ${res.outputDirectoryPath}",
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

            // plat_mac_permissions.xml live viewer
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

            item {
                Text(
                    text = "APKs trouvés dans '${uiState.selectedDecompiledImgName}' (${uiState.scannedApks.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
            }

            items(uiState.scannedApks, key = { it.relativePath }) { apk ->
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("apk_item_${apk.name}")
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
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
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = apk.name,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "${uiState.selectedDecompiledImgName}/${apk.relativePath}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "Rôle SELinux : ${apk.detectedRole} • STORED ARSC 4K",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }

                        Surface(
                            color = if (apk.isSignedWithCustomKey) MaterialTheme.colorScheme.secondaryContainer
                            else MaterialTheme.colorScheme.tertiaryContainer,
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
                                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                }
                                Text(
                                    text = if (apk.isSignedWithCustomKey) "Signé RSA-2048" else "TestKey AOSP",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = if (apk.isSignedWithCustomKey) MaterialTheme.colorScheme.onSecondaryContainer
                                    else MaterialTheme.colorScheme.onTertiaryContainer
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
                            text = "Sélectionnez n'importe quel fichier .apk de votre téléphone pour supprimer son META-INF et le resigner avec votre clé AOSP dans /storage/emulated/0/ROM_FORGE/signed_apks/.",
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
                            Text("Resigner cet APK vers ROM_FORGE/signed_apks")
                        }

                        if (uiState.lastSingleSignedApkOutPath.isNotEmpty()) {
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = "APK Resigné Disponible sans Root :",
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
