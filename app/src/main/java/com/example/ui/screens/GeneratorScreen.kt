package com.example.ui.screens

import android.net.Uri
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cached
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import com.example.data.local.ArtCacheEntity
import com.example.ui.KitchenUiState
import com.example.ui.components.DecompiledImgTargetSelectorCard

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun GeneratorScreen(
    uiState: KitchenUiState,
    artCacheEntries: List<ArtCacheEntity>,
    onSelectDecompiledImg: (String) -> Unit,
    onPickCustomSafTree: (Uri?) -> Unit,
    onUpdateOptions: (String, String, Boolean) -> Unit,
    onRunDex2oat: (Boolean) -> Unit,
    onClearMd5Cache: () -> Unit
) {
    val filters = listOf("speed-profile", "speed", "everything", "verify")

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(6.dp))
            // Step 1: Select which Decompiled IMG to generate ART (.odex/.vdex) & fs-verity for
            DecompiledImgTargetSelectorCard(
                title = "1. Sélectionner l'IMG Décompilé cible pour le Generator :",
                availableFolders = uiState.availableDecompiledImgs,
                selectedFolderName = uiState.selectedDecompiledImgName,
                selectedFullPath = uiState.selectedDecompiledImgFullPath,
                onSelectFolder = onSelectDecompiledImg,
                onPickExternalSafTree = onPickCustomSafTree
            )
        }

        item {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Memory,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = "MODULE 3 • GENERATOR (ART CACHE & FS-VERITY)",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Génère .odex, .vdex, .fsv_meta et otacerts.zip dans '${uiState.selectedDecompiledImgName}'",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Text(
                        text = "Filtre de compilation ART (dex2oat --compiler-filter) :",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold
                    )

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        filters.forEach { filter ->
                            FilterChip(
                                selected = uiState.selectedCompilerFilter == filter,
                                onClick = {
                                    onUpdateOptions(
                                        filter,
                                        uiState.selectedInstructionSet,
                                        uiState.enableFsVerity
                                    )
                                },
                                label = { Text(filter) },
                                modifier = Modifier.testTag("filter_chip_$filter")
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
                                text = "Générer les métadonnées fs-verity (.fsv_meta)",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = "Arbre de Merkle SHA-256 par blocs de 4096 octets + synchronisation otacerts.zip",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = uiState.enableFsVerity,
                            onCheckedChange = {
                                onUpdateOptions(
                                    uiState.selectedCompilerFilter,
                                    uiState.selectedInstructionSet,
                                    it
                                )
                            },
                            modifier = Modifier.testTag("fsverity_switch")
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { onRunDex2oat(false) },
                            enabled = !uiState.isBusy,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("run_dex2oat_button")
                        ) {
                            Icon(imageVector = Icons.Default.PlayArrow, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Générer dans ${uiState.selectedDecompiledImgName}")
                        }

                        FilledTonalButton(
                            onClick = { onRunDex2oat(true) },
                            enabled = !uiState.isBusy,
                            modifier = Modifier.testTag("force_dex2oat_button")
                        ) {
                            Icon(imageVector = Icons.Default.Cached, contentDescription = null)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Forcer")
                        }
                    }

                    uiState.lastArtReport?.let { rep ->
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = "Bilan R.E.C.O.R.E ART (${rep.targetDecompiledFolder}) : ${rep.compiledCount} APKs (.odex/.vdex/.art) | ${rep.bootArtImagesCount} Boot Images ART | ${rep.fsVerityGeneratedCount} .fsv_meta",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                                Text(
                                    text = "• Bootclasspath : ${rep.bootArtImagesCount} .art, ${rep.bootOatImagesCount} .oat, ${rep.bootVdexImagesCount} .vdex, ${rep.profilesGeneratedCount} profils .prof\n" +
                                            "• Zygote64      : preloaded-classes & dirty-image-objects synchronisés\n" +
                                            "• Sortie        : ${rep.targetAbsolutePath}",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                                rep.recoreCoherenceNotes.forEach { note ->
                                    Text(
                                        text = "✓ $note",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onPrimaryContainer
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // MD5 Cache Table Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Table de Cache MD5 ART (${artCacheEntries.size} entrées)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                if (artCacheEntries.isNotEmpty()) {
                    FilledTonalButton(
                        onClick = onClearMd5Cache,
                        modifier = Modifier.testTag("clear_md5_cache_button")
                    ) {
                        Icon(imageVector = Icons.Default.DeleteSweep, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Vider Cache")
                    }
                }
            }
        }

        if (artCacheEntries.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                    )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Aucun artefact .odex / .vdex en cache MD5",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = "Sélectionnez votre IMG décompilé ci-dessus et lancez 'Générer' pour compiler les fichiers oat/arm64/*.odex et *.vdex.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(artCacheEntries, key = { it.apkRelativePath }) { item ->
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = item.apkRelativePath,
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold
                            )
                            Surface(
                                color = MaterialTheme.colorScheme.secondaryContainer,
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    text = "${item.instructionSet} • ${item.compilerFilter}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "MD5 : ${item.md5Hash}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "ODEX : ${item.odexPath}\nVDEX : ${item.vdexPath}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        item.fsvMetaPath?.let { fsv ->
                            Text(
                                text = "FS-Verity : $fsv",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.secondary
                            )
                        }
                    }
                }
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}
