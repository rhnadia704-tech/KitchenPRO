package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ClearAll
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.PortHistoryEntity
import com.example.ui.KitchenTab
import com.example.ui.KitchenUiState

@Composable
fun ConsoleHistoryScreen(
    uiState: KitchenUiState,
    portHistory: List<PortHistoryEntity>,
    onClearLogs: () -> Unit,
    onExecuteCommand: (String) -> Unit,
    onSaveLogsToTxt: () -> Unit,
    onSelectDecompiledImgAndNavigate: (String, KitchenTab) -> Unit
) {
    val context = LocalContext.current
    // 0 = Log Entier & Terminal Interactif, 1 = Historique & Progression des Actions
    var selectedSubTab by remember { mutableIntStateOf(0) }
    var selectedLevelFilter by remember { mutableStateOf("ALL") }
    var searchQuery by remember { mutableStateOf("") }
    var showSearchBar by remember { mutableStateOf(false) }
    var commandInput by remember { mutableStateOf("") }
    var autoScroll by remember { mutableStateOf(true) }

    val filteredLogs by remember(uiState.terminalLogs, selectedLevelFilter, searchQuery) {
        derivedStateOf {
            uiState.terminalLogs.filter { entry ->
                val matchesLevel = selectedLevelFilter == "ALL" || entry.level == selectedLevelFilter
                val matchesQuery = searchQuery.isBlank() ||
                        entry.message.contains(searchQuery, ignoreCase = true) ||
                        entry.timestamp.contains(searchQuery, ignoreCase = true)
                matchesLevel && matchesQuery
            }
        }
    }

    val listState = rememberLazyListState()

    LaunchedEffect(filteredLogs.size, autoScroll) {
        if (autoScroll && filteredLogs.isNotEmpty() && selectedSubTab == 0) {
            listState.scrollToItem(filteredLogs.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp, vertical = 4.dp)
    ) {
        // Live Action Progress Card (always visible at top of Console)
        Surface(
            color = if (uiState.isBusy) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.65f)
            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 6.dp)
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Timeline,
                            contentDescription = null,
                            tint = if (uiState.isBusy) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (uiState.isBusy) "PROGRESSION EN COURS : ${uiState.activeTaskTitle}"
                            else "PROGRESSION DES ACTIONS : Prêt (${uiState.actionHistory.size} actions enregistrées)",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.ExtraBold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = if (uiState.isBusy) "${(uiState.activeTaskProgress * 100).toInt().coerceIn(10, 95)}%" else "100%",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.ExtraBold,
                        color = if (uiState.isBusy) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary
                    )
                }

                if (uiState.isBusy) {
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp))
                    )
                } else {
                    LinearProgressIndicator(
                        progress = { 1f },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(3.dp)
                            .clip(RoundedCornerShape(2.dp)),
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
            }
        }

        // Top Toolbar: Sub-Tab Selector + Search Toggle + Copy + Save TXT + Clear
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                FilterChip(
                    selected = selectedSubTab == 0,
                    onClick = { selectedSubTab = 0 },
                    label = {
                        Text(
                            text = "Log Entier & Commandes (${uiState.terminalLogs.size})",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Terminal,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("subtab_console_logs")
                )

                FilterChip(
                    selected = selectedSubTab == 1,
                    onClick = { selectedSubTab = 1 },
                    label = {
                        Text(
                            text = "Historique (${uiState.actionHistory.size})",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1
                        )
                    },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.History,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("subtab_history_imgs")
                )
            }

            if (selectedSubTab == 0) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(
                        onClick = { showSearchBar = !showSearchBar },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = "Rechercher dans les logs",
                            tint = if (showSearchBar || searchQuery.isNotEmpty()) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(19.dp)
                        )
                    }

                    IconButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            val allText = filteredLogs.joinToString("\n") { "${it.timestamp} ${it.message}" }
                            clipboard?.setPrimaryClip(ClipData.newPlainText("ROM Forge Logs", allText))
                            Toast.makeText(context, "Logs copiés dans le presse-papiers", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier
                            .size(36.dp)
                            .testTag("copy_logs_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = "Copier les logs",
                            modifier = Modifier.size(19.dp)
                        )
                    }

                    IconButton(
                        onClick = {
                            onSaveLogsToTxt()
                            Toast.makeText(context, "Journal enregistré en .txt dans KEY/Data", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier
                            .size(36.dp)
                            .testTag("save_logs_txt_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.Save,
                            contentDescription = "Enregistrer en format .txt",
                            modifier = Modifier.size(19.dp)
                        )
                    }

                    IconButton(
                        onClick = onClearLogs,
                        modifier = Modifier
                            .size(36.dp)
                            .testTag("clear_terminal_button")
                    ) {
                        Icon(
                            imageVector = Icons.Default.ClearAll,
                            contentDescription = "Effacer les logs",
                            modifier = Modifier.size(19.dp)
                        )
                    }
                }
            }
        }

        if (selectedSubTab == 0) {
            AnimatedVisibility(visible = showSearchBar) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Filtrer les logs (EXT4, APK, FOD)...", fontSize = 12.sp) },
                    leadingIcon = { Icon(imageVector = Icons.Default.Search, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .testTag("console_search_input")
                )
            }

            if (uiState.lastSavedLogFilePath.isNotEmpty()) {
                Text(
                    text = "Export TXT : ${uiState.lastSavedLogFilePath}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.secondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val levels = listOf(
                    "ALL" to "Tous",
                    "SUCCESS" to "Succès",
                    "INFO" to "Infos",
                    "WARN" to "Alertes",
                    "ERROR" to "Erreurs"
                )
                levels.forEach { (code, label) ->
                    FilterChip(
                        selected = selectedLevelFilter == code,
                        onClick = { selectedLevelFilter = code },
                        label = { Text(label, style = MaterialTheme.typography.labelSmall) },
                        modifier = Modifier.testTag("log_filter_$code")
                    )
                }

                FilterChip(
                    selected = autoScroll,
                    onClick = { autoScroll = !autoScroll },
                    label = { Text("Auto-Scroll", style = MaterialTheme.typography.labelSmall) }
                )

                val quickCmds = listOf("ls", "ls unpack", "ls packed", "ls key", "ls port", "getprop", "verify-apks", "help")
                quickCmds.forEach { qCmd ->
                    AssistChip(
                        onClick = { onExecuteCommand(qCmd) },
                        label = {
                            Text(
                                text = "$ $qCmd",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            // Full-Height Terminal Console Viewport
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .heightIn(min = 240.dp),
                color = Color(0xFF090D16),
                shape = RoundedCornerShape(14.dp)
            ) {
                if (filteredLogs.isEmpty()) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "Terminal prêt. Saisissez une commande ci-dessous (ex: help, ls unpack, avbtool --version).",
                            color = Color(0xFF64748B),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(16.dp)
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(5.dp)
                    ) {
                        items(filteredLogs, key = { it.id }) { entry ->
                            val lineColor = when {
                                entry.message.startsWith("$ ") -> Color(0xFF00E5FF)
                                entry.level == "ERROR" -> Color(0xFFF87171)
                                entry.level == "WARN" -> Color(0xFFFBBF24)
                                entry.level == "SUCCESS" -> Color(0xFF34D399)
                                else -> Color(0xFF93C5FD)
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.Top
                            ) {
                                Box(
                                    modifier = Modifier
                                        .padding(top = 6.dp)
                                        .size(6.dp)
                                        .clip(CircleShape)
                                        .background(lineColor)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "${entry.timestamp} ${entry.message}",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    lineHeight = 17.sp,
                                    color = lineColor
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Interactive Terminal Command Input Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = commandInput,
                    onValueChange = { commandInput = it },
                    placeholder = {
                        Text(
                            text = "$ Taper une commande (help, ls unpack, getprop...)",
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(
                        onSend = {
                            if (commandInput.isNotBlank()) {
                                onExecuteCommand(commandInput)
                                commandInput = ""
                            }
                        }
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("terminal_command_input")
                )

                FilledTonalButton(
                    onClick = {
                        if (commandInput.isNotBlank()) {
                            onExecuteCommand(commandInput)
                            commandInput = ""
                        }
                    },
                    modifier = Modifier
                        .height(52.dp)
                        .testTag("terminal_send_command_button")
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.Send,
                        contentDescription = "Exécuter la commande"
                    )
                }
            }
        } else {
            // Sub-tab 1: Action History, Progress of Each Action, and Organized ROM_FORGE Workspaces
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    Text(
                        text = "Historique & Progression de Chaque Action (${uiState.actionHistory.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                if (uiState.actionHistory.isEmpty()) {
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Text(
                                    text = "Aucune action manuelle exécutée dans cette session pour le moment.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                } else {
                    items(uiState.actionHistory, key = { it.id }) { act ->
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Default.CheckCircle,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.secondary,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = "${act.moduleLabel} • ${act.actionTitle}",
                                            style = MaterialTheme.typography.labelMedium,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                    }
                                    Text(
                                        text = "${act.finishedAt} (${act.progressPercent}%)",
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                                Text(
                                    text = "Cible : ${act.targetName} | ${act.summaryDetail}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                LinearProgressIndicator(
                                    progress = { act.progressPercent / 100f },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(3.dp)
                                        .clip(RoundedCornerShape(2.dp)),
                                    color = MaterialTheme.colorScheme.secondary
                                )
                            }
                        }
                    }
                }

                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.35f)
                        )
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Arborescence Organisée ROM_FORGE",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "• UNPACK : ${uiState.romForgePublicPath}/UNPACK/<nom_img>\n" +
                                        "• PACKED : ${uiState.romForgePublicPath}/PACKED/ (Images .img compilées)\n" +
                                        "• KEY    : ${uiState.romForgePublicPath}/KEY/ & KEY/Data/ (Clés & Rapports JSON/TXT)\n" +
                                        "• PORT   : ${uiState.romForgePublicPath}/PORT/ (Espace de portage GSI & FOD)",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }

                item {
                    Text(
                        text = "Systèmes .img Décompilés dans ROM_FORGE/UNPACK (${uiState.availableDecompiledImgs.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                }

                items(uiState.availableDecompiledImgs, key = { it }) { folderName ->
                    val isActive = folderName == uiState.selectedDecompiledImgName
                    ElevatedCard(
                        modifier = Modifier.fillMaxWidth()
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
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Folder,
                                        contentDescription = null,
                                        tint = if (isActive) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Column {
                                        Text(
                                            text = folderName,
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.ExtraBold,
                                            fontFamily = FontFamily.Monospace
                                        )
                                        Text(
                                            text = "${uiState.romForgePublicPath}/UNPACK/$folderName",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }

                                if (isActive) {
                                    Surface(
                                        color = MaterialTheme.colorScheme.secondaryContainer,
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Text(
                                            text = "ACTIF",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                        )
                                    }
                                }
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                FilledTonalButton(
                                    onClick = { onSelectDecompiledImgAndNavigate(folderName, KitchenTab.SIGN_PRO) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(imageVector = Icons.Default.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Sign Pro", style = MaterialTheme.typography.labelSmall)
                                }

                                FilledTonalButton(
                                    onClick = { onSelectDecompiledImgAndNavigate(folderName, KitchenTab.AUTO_PORTER) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(imageVector = Icons.Default.Memory, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Porting", style = MaterialTheme.typography.labelSmall)
                                }

                                FilledTonalButton(
                                    onClick = { onSelectDecompiledImgAndNavigate(folderName, KitchenTab.COMPILER) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(imageVector = Icons.Default.Build, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Compilator", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }

                if (portHistory.isNotEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Historique des Portages GSI -> ROM_FORGE/PORT (${portHistory.size})",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    items(portHistory, key = { it.id }) { history ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
                            )
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = "${history.stockDeviceName} -> ${history.gsiTargetName}",
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "${history.blobsTransplanted} Blobs • ${history.sepolicyRulesMerged} règles CIL • FOD: ${history.fodStatus}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                item {
                    Spacer(modifier = Modifier.height(24.dp))
                }
            }
        }
    }
}
