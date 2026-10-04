package com.example.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.ClearAll
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.data.local.PortHistoryEntity
import com.example.ui.KitchenTab
import com.example.ui.KitchenUiState

@OptIn(ExperimentalLayoutApi::class)
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
    var selectedSubTab by remember { mutableIntStateOf(0) } // 0 = Terminal & Logs Live, 1 = Dossiers UNPACK / PORT & Historique
    var selectedLevelFilter by remember { mutableStateOf("ALL") }
    var searchQuery by remember { mutableStateOf("") }
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
            .padding(horizontal = 16.dp)
    ) {
        TabRow(
            selectedTabIndex = selectedSubTab,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
        ) {
            Tab(
                selected = selectedSubTab == 0,
                onClick = { selectedSubTab = 0 },
                text = { Text("Terminal & Logs Live (${uiState.terminalLogs.size})") },
                icon = { Icon(imageVector = Icons.Default.Terminal, contentDescription = null) },
                modifier = Modifier.testTag("subtab_console_logs")
            )
            Tab(
                selected = selectedSubTab == 1,
                onClick = { selectedSubTab = 1 },
                text = { Text("Espaces UNPACK & PORT (${uiState.availableDecompiledImgs.size})") },
                icon = { Icon(imageVector = Icons.Default.History, contentDescription = null) },
                modifier = Modifier.testTag("subtab_history_imgs")
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (selectedSubTab == 0) {
            // Search, Copy & Save as .TXT Bar
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Filtrer les logs (EXT4, APK, FOD)...") },
                    leadingIcon = { Icon(imageVector = Icons.Default.Search, contentDescription = null) },
                    singleLine = true,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("console_search_input")
                )

                IconButton(
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        val allText = filteredLogs.joinToString("\n") { "${it.timestamp} ${it.message}" }
                        clipboard?.setPrimaryClip(ClipData.newPlainText("ROM Forge Logs", allText))
                        Toast.makeText(context, "Logs copiés dans le presse-papiers", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.testTag("copy_logs_button")
                ) {
                    Icon(imageVector = Icons.Default.ContentCopy, contentDescription = "Copier les logs")
                }

                IconButton(
                    onClick = {
                        onSaveLogsToTxt()
                        Toast.makeText(context, "Journal enregistré en .txt dans KEY/Data", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.testTag("save_logs_txt_button")
                ) {
                    Icon(imageVector = Icons.Default.Save, contentDescription = "Enregistrer en format .txt")
                }

                IconButton(
                    onClick = onClearLogs,
                    modifier = Modifier.testTag("clear_terminal_button")
                ) {
                    Icon(imageVector = Icons.Default.ClearAll, contentDescription = "Effacer les logs")
                }
            }

            if (uiState.lastSavedLogFilePath.isNotEmpty()) {
                Text(
                    text = "Dernier export TXT : ${uiState.lastSavedLogFilePath}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.padding(top = 2.dp)
                )
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Level Filters + Quick Shell Shortcuts
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
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

                val quickCmds = listOf("ls", "ls unpack", "ls packed", "ls key", "ls port", "getprop", "verify-apks")
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

            Spacer(modifier = Modifier.height(6.dp))

            // Full-Height Smooth Terminal Log View
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
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
                            .padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
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
                                        .padding(top = 5.dp)
                                        .size(6.dp)
                                        .clip(CircleShape)
                                        .background(lineColor)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "${entry.timestamp} ${entry.message}",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.5.sp,
                                    lineHeight = 16.sp,
                                    color = lineColor
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Interactive Terminal Command Input Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = commandInput,
                    onValueChange = { commandInput = it },
                    placeholder = {
                        Text(
                            text = "Commande shell (ex: ls unpack, getprop ro.board.platform, avbtool, help)...",
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace
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
                    modifier = Modifier.testTag("terminal_send_command_button")
                ) {
                    Icon(imageVector = Icons.AutoMirrored.Filled.Send, contentDescription = "Exécuter")
                }
            }
        } else {
            // Sub-Tab 2: Structured Workspace Overview (UNPACK, PACKED, KEY, PORT)
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = "Architecture des Dossiers ROM_FORGE",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.ExtraBold,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = "• UNPACK/   : Systèmes .img décompilés prêts à modifier\n" +
                                        "• PACKED/   : Images system.img & vbmeta.img recompilées\n" +
                                        "• KEY/      : Clés RSA-2048 (.pk8/.x509.pem) & manifest.json\n" +
                                        "• KEY/Data/ : Rapports JSON & TXT des signatures vérifiées\n" +
                                        "• PORT/     : Espace de portage GSI + Blobs FOD + Image portée finale",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }

                item {
                    Text(
                        text = "Systèmes Décompilés dans ROM_FORGE/UNPACK (${uiState.availableDecompiledImgs.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Bold
                    )
                }

                items(uiState.availableDecompiledImgs, key = { it }) { folderName ->
                    val isSelected = folderName == uiState.selectedDecompiledImgName
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(14.dp),
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
                                        tint = if (isSelected) MaterialTheme.colorScheme.secondary
                                        else MaterialTheme.colorScheme.primary
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = "UNPACK / $folderName",
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                        Text(
                                            text = "${uiState.romForgePublicPath}/UNPACK/$folderName",
                                            style = MaterialTheme.typography.labelSmall,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }

                                if (isSelected) {
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
                                    onClick = { onSelectDecompiledImgAndNavigate(folderName, KitchenTab.GENERATOR) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(imageVector = Icons.Default.Memory, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Generator", style = MaterialTheme.typography.labelSmall)
                                }

                                FilledTonalButton(
                                    onClick = { onSelectDecompiledImgAndNavigate(folderName, KitchenTab.COMPILER) },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(imageVector = Icons.Default.Build, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Compiler", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }

                if (portHistory.isNotEmpty()) {
                    item {
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "Historique des Portages GSI dans ROM_FORGE/PORT (${portHistory.size})",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    items(portHistory, key = { it.id }) { hist ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                            )
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = "${hist.stockDeviceName} -> ${hist.gsiTargetName}",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "${hist.blobsTransplanted} Blobs • ${hist.sepolicyRulesMerged} règles CIL • FOD: ${hist.fodStatus}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }
}
