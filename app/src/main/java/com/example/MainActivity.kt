package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.FolderSpecial
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.KitchenTab
import com.example.ui.RomKitchenViewModel
import com.example.ui.components.TopSystemStatusBar
import com.example.ui.screens.AutoPorterScreen
import com.example.ui.screens.CompilerScreen
import com.example.ui.screens.ConsoleHistoryScreen
import com.example.ui.screens.GeneratorScreen
import com.example.ui.screens.HelpScreen
import com.example.ui.screens.KeyMakerScreen
import com.example.ui.screens.SignProScreen
import com.example.ui.theme.MyApplicationTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                RomForgeKitchenApp()
            }
        }
    }
}

@Composable
fun RomForgeKitchenApp(viewModel: RomKitchenViewModel = viewModel()) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val keys by viewModel.keysFlow.collectAsStateWithLifecycle()
    val artCache by viewModel.artCacheFlow.collectAsStateWithLifecycle()
    val alerts by viewModel.alertsFlow.collectAsStateWithLifecycle()
    val portHistory by viewModel.portHistoryFlow.collectAsStateWithLifecycle()

    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val coroutineScope = rememberCoroutineScope()

    if (uiState.currentTab != KitchenTab.KEY_MAKER) {
        BackHandler {
            if (drawerState.isOpen) {
                coroutineScope.launch { drawerState.close() }
            } else if (uiState.currentTab == KitchenTab.CONSOLE) {
                viewModel.toggleConsoleTab()
            } else {
                viewModel.selectTab(KitchenTab.KEY_MAKER)
            }
        }
    }

    val coreModuleTabs = listOf(
        KitchenTab.KEY_MAKER,
        KitchenTab.SIGN_PRO,
        KitchenTab.GENERATOR,
        KitchenTab.COMPILER,
        KitchenTab.AUTO_PORTER
    )

    val toolsAndSupportTabs = listOf(
        KitchenTab.CONSOLE,
        KitchenTab.HELP
    )

    // 2-pane bottom bar: Active Module View <-> Live Terminal Console View, while all features live in the Sidebar Drawer
    val isConsolePaneActive = uiState.currentTab == KitchenTab.CONSOLE
    val activeWorkspaceTab = if (isConsolePaneActive) uiState.previousTabBeforeConsole else uiState.currentTab

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet(
                modifier = Modifier
                    .fillMaxHeight()
                    .width(305.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                ) {
                    // Sidebar Header
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                            .statusBarsPadding()
                            .padding(18.dp)
                    ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(MaterialTheme.colorScheme.primaryContainer),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Memory,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "ROM FORGE v2.5",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "AOSP Reverse-Compiler Kitchen",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                text = "Dossiers Structurés ROM_FORGE :",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.secondary
                            )
                            Text(
                                text = "• UNPACK/ (${uiState.availableDecompiledImgs.size} systèmes)\n" +
                                        "• PACKED/ (Images .img & vbmeta)\n" +
                                        "• KEY/ & KEY/Data/ (Clés & Audits)\n" +
                                        "• PORT/ (GSI & FOD Xiaomi Tucana)",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "MODULES D'INGÉNIERIE AOSP",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.ExtraBold,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)
                )

                coreModuleTabs.forEach { tab ->
                    NavigationDrawerItem(
                        label = {
                            Column {
                                Text(
                                    text = tab.label,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = tab.subtitle(),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        },
                        icon = {
                            Icon(imageVector = tab.icon(), contentDescription = tab.label)
                        },
                        selected = uiState.currentTab == tab,
                        onClick = {
                            viewModel.selectTab(tab)
                            coroutineScope.launch { drawerState.close() }
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_${tab.route}")
                    )
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp, horizontal = 16.dp))

                Text(
                    text = "TERMINAL & DOCUMENTATION",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.ExtraBold,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)
                )

                toolsAndSupportTabs.forEach { tab ->
                    NavigationDrawerItem(
                        label = {
                            Column {
                                Text(
                                    text = tab.label,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = tab.subtitle(),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        },
                        icon = {
                            Icon(imageVector = tab.icon(), contentDescription = tab.label)
                        },
                        selected = uiState.currentTab == tab,
                        onClick = {
                            viewModel.selectTab(tab)
                            coroutineScope.launch { drawerState.close() }
                        },
                        modifier = Modifier
                            .padding(NavigationDrawerItemDefaults.ItemPadding)
                            .testTag("drawer_item_${tab.route}")
                    )
                }

                    Spacer(modifier = Modifier.height(24.dp))
                }
            }
        }
    ) {
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val isWideScreen = maxWidth >= 600.dp

            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing,
                topBar = {
                    TopSystemStatusBar(
                        executionMode = uiState.executionMode,
                        isRootAvailable = uiState.isRootAvailable,
                        isBusy = uiState.isBusy,
                        activeTaskTitle = uiState.activeTaskTitle,
                        romForgePublicPath = uiState.romForgePublicPath,
                        hasAllFilesAccess = uiState.hasAllFilesAccess,
                        availableDecompiledImgs = uiState.availableDecompiledImgs,
                        selectedDecompiledImgName = uiState.selectedDecompiledImgName,
                        binaries = uiState.extractedBinaries,
                        verificationSummary = uiState.verificationSummary,
                        alerts = alerts,
                        logsCount = uiState.terminalLogs.size,
                        latestLogEntry = uiState.terminalLogs.lastOrNull(),
                        isConsoleTabSelected = isConsolePaneActive,
                        onOpenDrawer = { coroutineScope.launch { drawerState.open() } },
                        onToggleConsoleTab = viewModel::toggleConsoleTab,
                        onToggleMode = viewModel::toggleExecutionMode,
                        onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                        onRunVerifier = viewModel::runIntelligentCrossVerifier,
                        onFixAllCoherence = viewModel::fixAllCoherenceAndBootloopRisksForUnpackedImg,
                        onRefreshStorage = viewModel::refreshStorageStatusAndFolders
                    )
                },
                bottomBar = {
                    if (!isWideScreen) {
                        // Clean 2-Pane Navigation Bar + Sidebar Drawer Trigger
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.surface
                        ) {
                            // Pane 1: Active Engineering Module (opens Sidebar Drawer on re-tap or switches back from Console)
                            NavigationBarItem(
                                selected = !isConsolePaneActive,
                                onClick = {
                                    if (isConsolePaneActive) {
                                        viewModel.selectTab(activeWorkspaceTab)
                                    } else {
                                        coroutineScope.launch { drawerState.open() }
                                    }
                                },
                                icon = {
                                    Icon(
                                        imageVector = activeWorkspaceTab.icon(),
                                        contentDescription = activeWorkspaceTab.label
                                    )
                                },
                                label = {
                                    Text(
                                        text = "Volet 1 : ${activeWorkspaceTab.shortLabel()}",
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        fontWeight = FontWeight.Bold
                                    )
                                },
                                modifier = Modifier.testTag("nav_pane_workspace")
                            )

                            // Pane 2: Live Terminal & Console / Workspaces
                            NavigationBarItem(
                                selected = isConsolePaneActive,
                                onClick = { viewModel.selectTab(KitchenTab.CONSOLE) },
                                icon = {
                                    Icon(
                                        imageVector = Icons.Default.Terminal,
                                        contentDescription = "Volet 2 : Console & Terminal"
                                    )
                                },
                                label = {
                                    Text(
                                        text = "Volet 2 : Console (${uiState.terminalLogs.size})",
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        fontWeight = FontWeight.Bold
                                    )
                                },
                                modifier = Modifier.testTag("nav_tab_console")
                            )
                        }
                    }
                }
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    if (isWideScreen) {
                        NavigationRail(
                            modifier = Modifier.fillMaxHeight()
                        ) {
                            KitchenTab.entries.forEach { tab ->
                                NavigationRailItem(
                                    selected = uiState.currentTab == tab,
                                    onClick = { viewModel.selectTab(tab) },
                                    icon = {
                                        Icon(
                                            imageVector = tab.icon(),
                                            contentDescription = tab.label
                                        )
                                    },
                                    label = { Text(tab.shortLabel()) },
                                    modifier = Modifier.testTag("nav_rail_${tab.route}")
                                )
                            }
                        }
                    }

                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                    ) {
                        // Quick Module Selector Strip at top of Workspace Pane so all modules are 1-tap accessible in addition to the Sidebar Drawer
                        if (!isWideScreen) {
                            Surface(
                                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    KitchenTab.entries.forEach { tab ->
                                        val selected = uiState.currentTab == tab
                                        Surface(
                                            onClick = { viewModel.selectTab(tab) },
                                            color = if (selected) MaterialTheme.colorScheme.primaryContainer
                                            else MaterialTheme.colorScheme.surface.copy(alpha = 0f),
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier
                                                .weight(1f)
                                                .testTag("nav_tab_${tab.route}")
                                        ) {
                                            Column(
                                                modifier = Modifier.padding(vertical = 5.dp, horizontal = 2.dp),
                                                horizontalAlignment = Alignment.CenterHorizontally
                                            ) {
                                                Icon(
                                                    imageVector = tab.icon(),
                                                    contentDescription = tab.label,
                                                    tint = if (selected) MaterialTheme.colorScheme.primary
                                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                                    modifier = Modifier.size(16.dp)
                                                )
                                                Text(
                                                    text = tab.shortLabel(),
                                                    style = MaterialTheme.typography.labelSmall,
                                                    fontWeight = if (selected) FontWeight.ExtraBold else FontWeight.Medium,
                                                    color = if (selected) MaterialTheme.colorScheme.primary
                                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth()
                        ) {
                            when (uiState.currentTab) {
                                KitchenTab.KEY_MAKER -> KeyMakerScreen(
                                    uiState = uiState,
                                    keys = keys,
                                    onUpdateParams = viewModel::updateKeyParameters,
                                    onGenerateKeys = viewModel::generateAospKeySuite
                                )

                                KitchenTab.SIGN_PRO -> SignProScreen(
                                    uiState = uiState,
                                    onSelectSignMode = viewModel::setSignProInputMode,
                                    onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                                    onPickCustomSafTree = viewModel::selectCustomDecompiledDirectoryUri,
                                    onPickSingleApkUri = viewModel::pickSingleApkToSign,
                                    onSelectSingleApkRole = viewModel::setSingleApkRole,
                                    onSignSingleApk = viewModel::signSingleSelectedApk,
                                    onSignIndividualApkInUnpack = viewModel::signSingleApkInDecompiledSystem,
                                    onVerifyApkSignatures = viewModel::verifyApkSignaturesAndExportReports,
                                    onSignAllInMemory = viewModel::signAllSystemApksInMemory
                                )

                                KitchenTab.GENERATOR -> GeneratorScreen(
                                    uiState = uiState,
                                    artCacheEntries = artCache,
                                    onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                                    onPickCustomSafTree = viewModel::selectCustomDecompiledDirectoryUri,
                                    onUpdateOptions = viewModel::updateGeneratorOptions,
                                    onRunDex2oat = viewModel::runArtDex2oatGenerator,
                                    onClearMd5Cache = viewModel::clearMd5ArtCache
                                )

                                KitchenTab.COMPILER -> CompilerScreen(
                                    uiState = uiState,
                                    onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                                    onPickCustomSafTree = viewModel::selectCustomDecompiledDirectoryUri,
                                    onUpdateOptions = viewModel::updateCompilerOptions,
                                    onRunPreFlightAudit = viewModel::runPreFlightAudit,
                                    onCompileImages = viewModel::compileFullSystemAndVbmeta,
                                    onImportImgUri = viewModel::importAndInspectExternalImg
                                )

                                KitchenTab.AUTO_PORTER -> AutoPorterScreen(
                                    uiState = uiState,
                                    portHistory = portHistory,
                                    onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                                    onPickCustomSafTree = viewModel::selectCustomDecompiledDirectoryUri,
                                    onExecuteFullAutoPort = viewModel::executeGsiToSystemAutoPort
                                )

                                KitchenTab.CONSOLE -> ConsoleHistoryScreen(
                                    uiState = uiState,
                                    portHistory = portHistory,
                                    onClearLogs = viewModel::clearLogs,
                                    onExecuteCommand = viewModel::executeInteractiveTerminalCommand,
                                    onSaveLogsToTxt = viewModel::exportTerminalLogsToTxtFile,
                                    onSelectDecompiledImgAndNavigate = viewModel::selectDecompiledImgAndNavigate
                                )

                                KitchenTab.HELP -> HelpScreen(
                                    romForgeRootPath = uiState.romForgePublicPath,
                                    onNavigateToTab = viewModel::selectTab,
                                    onRunCommandInTerminal = viewModel::executeInteractiveTerminalCommand
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun KitchenTab.icon(): ImageVector = when (this) {
    KitchenTab.KEY_MAKER -> Icons.Default.Key
    KitchenTab.SIGN_PRO -> Icons.Default.Bolt
    KitchenTab.GENERATOR -> Icons.Default.Memory
    KitchenTab.COMPILER -> Icons.Default.Build
    KitchenTab.AUTO_PORTER -> Icons.Default.AccountTree
    KitchenTab.CONSOLE -> Icons.Default.Terminal
    KitchenTab.HELP -> Icons.Default.HelpOutline
}

private fun KitchenTab.shortLabel(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Key"
    KitchenTab.SIGN_PRO -> "Sign Pro"
    KitchenTab.GENERATOR -> "ART"
    KitchenTab.COMPILER -> "Pack/Unpack"
    KitchenTab.AUTO_PORTER -> "Porting"
    KitchenTab.CONSOLE -> "Console"
    KitchenTab.HELP -> "Aides"
}

private fun KitchenTab.subtitle(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Génération RSA-2048 & Clé Note (-> KEY/)"
    KitchenTab.SIGN_PRO -> "Signature APK & Audit JSON/TXT (-> KEY/Data/)"
    KitchenTab.GENERATOR -> "Compilation dex2oat .odex/.vdex & fs-verity"
    KitchenTab.COMPILER -> "Décompilateur UNPACK & Compilateur PACKED"
    KitchenTab.AUTO_PORTER -> "Portage GSI & FOD Xiaomi Tucana (-> PORT/)"
    KitchenTab.CONSOLE -> "Terminal Shell Interactif & Export .txt"
    KitchenTab.HELP -> "Instructions d'utilisation & Commandes AOSP"
}
