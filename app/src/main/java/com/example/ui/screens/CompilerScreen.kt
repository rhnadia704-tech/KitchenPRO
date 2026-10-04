package com.example.ui.screens

import android.net.Uri
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.modules.compiler.FilesystemFormat
import com.example.ui.KitchenUiState

@Composable
fun CompilerScreen(
    uiState: KitchenUiState,
    onUpdateOptions: (FilesystemFormat, Boolean, Boolean) -> Unit,
    onRunPreFlightAudit: (Boolean) -> Unit,
    onCompileImages: () -> Unit,
    onImportImgUri: (Uri?) -> Unit
) {
    val safImgPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        onImportImgUri(uri)
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            // Hybrid IMG Mount / SAF Unpack Card
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Storage,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "EXTRACTEUR & MONTEUR HYBRIDE (.IMG)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Supporte EXT4 (0xEF53), EROFS (0xE0F5E1E2), Sparse (0xED26FF3A) en mode Root Loop ou Non-Root SAF",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FilledTonalButton(
                            onClick = { safImgPicker.launch(arrayOf("*/*")) },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("saf_import_img_button")
                        ) {
                            Icon(imageVector = Icons.Default.FolderOpen, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Charger .img (SAF)")
                        }

                        Button(
                            onClick = { onImportImgUri(null) },
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("inspect_workspace_img_button")
                        ) {
                            Icon(imageVector = Icons.Default.Storage, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Monter / Décompresser")
                        }
                    }

                    uiState.lastMountedImgReport?.let { rep ->
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = "Image Active : ${rep.fileName} [${rep.format}]",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = "Magic : ${rep.magicHex} • Fichiers : ${rep.extractedFilesCount} • Point : ${rep.mountPointUsed}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }
            }
        }

        // Orchestrateur de Compilation EXT4 / EROFS + AVB 2.0
        item {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Build,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.secondary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "MODULE 4 • ORCHESTRATEUR DE COMPILATION & AVB 2.0",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Reconstruction system.img (mke2fs / mkfs.erofs) + arbre dm-verity & génération vbmeta.img",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FilesystemFormat.entries.forEach { fmt ->
                            FilterChip(
                                selected = uiState.selectedFsFormat == fmt,
                                onClick = {
                                    onUpdateOptions(
                                        fmt,
                                        uiState.enableDmVerity,
                                        uiState.disableVerityFlagsInVbmeta
                                    )
                                },
                                label = { Text(fmt.name) },
                                modifier = Modifier.testTag("fs_format_chip_${fmt.name}")
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Injecter le Hashtree Footer dm-verity (avbtool)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Signe l'arbre SHA-256 avec la clé RSA-2048 platform",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.enableDmVerity,
                            onCheckedChange = {
                                onUpdateOptions(
                                    uiState.selectedFsFormat,
                                    it,
                                    uiState.disableVerityFlagsInVbmeta
                                )
                            },
                            modifier = Modifier.testTag("dmverity_switch")
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        FilledTonalButton(
                            onClick = { onRunPreFlightAudit(true) },
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("anti_bootloop_repair_button")
                        ) {
                            Icon(imageVector = Icons.Default.HealthAndSafety, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Anti-Bootloop")
                        }

                        Button(
                            onClick = onCompileImages,
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("compile_system_img_button")
                        ) {
                            Icon(imageVector = Icons.Default.Build, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Compiler .IMG & VBMeta")
                        }
                    }

                    uiState.lastCompilationOutput?.let { out ->
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = "Compilation Réussie (${out.format.name} en ${out.elapsedMs}ms)",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                                Text(
                                    text = "system.img : ${out.systemImgSizeBytes / 1024} KB (${out.format.magicHex})\nvbmeta.img : ${out.vbmetaImgSizeBytes} octets (AVB0)\nRoot Digest : ${out.dmVerityRootDigest.take(28)}...",
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

        // Pre-Flight Static Analysis Checklist
        item {
            Text(
                text = "Contrôles Statiques Anti-Bootloop (SELinux & fs_config)",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
        }

        items(uiState.preFlightItems, key = { it.checkName }) { item ->
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (item.passed) Icons.Default.CheckCircle else Icons.Default.Warning,
                        contentDescription = null,
                        tint = if (item.passed) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "[${item.category}] ${item.checkName}",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = item.detail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}
