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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Settings
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
import com.example.ui.screens.RecoreScreen
import com.example.ui.screens.SignProScreen
import com.example.ui.theme.MyApplicationTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val viewModel: RomKitchenViewModel = viewModel()
            val uiState by viewModel.uiState.collectAsStateWithLifecycle()
            MyApplicationTheme(themePreference = uiState.themePreference) {
                RomForgeKitchenApp(viewModel = viewModel)
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
            } else if (uiState.currentTab == KitchenTab.CONSOLE || uiState.currentTab == KitchenTab.HELP) {
                viewModel.selectTab(uiState.previousTabBeforeConsole)
            } else {
                viewModel.selectTab(KitchenTab.KEY_MAKER)
            }
        }
    }

    // Sidebar items: Key Maker, Sign Pro, Generator, Compilator (Unpack & Repack), Porting (GSI), R.E.C.O.R.E
    val sidebarModules = listOf(
        KitchenTab.KEY_MAKER,
        KitchenTab.SIGN_PRO,
        KitchenTab.GENERATOR,
        KitchenTab.COMPILER,
        KitchenTab.AUTO_PORTER,
        KitchenTab.RECORE
    )

    // 3-Pane Bottom Navigation Bar:
    // 1. Action (displays the module selected from the Sidebar)
    // 2. Console (full logs, action history, live progress, interactive command input)
    // 3. Paramètres (theme Light/Dark/System, guides/tips, command rules, changelog & features)
    val isConsolePaneActive = uiState.currentTab == KitchenTab.CONSOLE
    val isSettingsPaneActive = uiState.currentTab == KitchenTab.HELP
    val isActionPaneActive = !isConsolePaneActive && !isSettingsPaneActive
    val activeSidebarModule = if (isActionPaneActive) uiState.currentTab else uiState.previousTabBeforeConsole

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
                                    .size(44.dp)
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(androidx.compose.ui.graphics.Color(0xFF101418)),
                                contentAlignment = Alignment.Center
                            ) {
                                androidx.compose.foundation.Image(
                                    painter = androidx.compose.ui.res.painterResource(id = R.drawable.ic_romforger_bolt_gear),
                                    contentDescription = "Logo ROM Forge",
                                    modifier = Modifier.size(36.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "ROM FORGE v3.0",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.ExtraBold
                                )
                                Text(
                                    text = "R.E.C.O.R.E • UKA & GSI Porter",
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
                                    text = "Espaces ROM_FORGE Actifs :",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.secondary
                                )
                                Text(
                                    text = "• UNPACK/ (${uiState.availableDecompiledImgs.size} systèmes)\n" +
                                            "• PACKED/ (Images .img & vbmeta)\n" +
                                            "• KEY/ & KEY/Data/ (Clés & Rapports)\n" +
                                            "• PORT/ (GSI, HAL Vendor & FODstruct)",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "BARRE LATÉRALE • MODULES D'ACTION",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.ExtraBold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)
                    )

                    sidebarModules.forEach { tab ->
                        NavigationDrawerItem(
                            label = {
                                Column {
                                    Text(
                                        text = tab.sidebarTitle(),
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
                                Icon(imageVector = tab.icon(), contentDescription = tab.sidebarTitle())
                            },
                            selected = activeSidebarModule == tab && isActionPaneActive,
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
                        text = "VOLETS SYSTÈME",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.ExtraBold,
                        color = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp)
                    )

                    listOf(KitchenTab.CONSOLE, KitchenTab.HELP).forEach { tab ->
                        NavigationDrawerItem(
                            label = {
                                Column {
                                    Text(
                                        text = tab.sidebarTitle(),
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
                                Icon(imageVector = tab.icon(), contentDescription = tab.sidebarTitle())
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
                    // 3-Pane Bottom Navigation Bar: Action | Console | Paramètres
                    NavigationBar(
                        containerColor = MaterialTheme.colorScheme.surface
                    ) {
                        // Volet 1 : Action (displays the active element chosen from the Sidebar)
                        NavigationBarItem(
                            selected = isActionPaneActive,
                            onClick = {
                                if (!isActionPaneActive) {
                                    viewModel.selectTab(activeSidebarModule)
                                } else {
                                    coroutineScope.launch { drawerState.open() }
                                }
                            },
                            icon = {
                                Icon(
                                    imageVector = activeSidebarModule.icon(),
                                    contentDescription = "Action : ${activeSidebarModule.sidebarTitle()}"
                                )
                            },
                            label = {
                                Text(
                                    text = "Action (${activeSidebarModule.shortLabel()})",
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    fontWeight = FontWeight.Bold
                                )
                            },
                            modifier = Modifier.testTag("nav_pane_action")
                        )

                        // Volet 2 : Console (history, full logs, live progress, interactive command input)
                        NavigationBarItem(
                            selected = isConsolePaneActive,
                            onClick = { viewModel.selectTab(KitchenTab.CONSOLE) },
                            icon = {
                                Icon(
                                    imageVector = Icons.Default.Terminal,
                                    contentDescription = "Console"
                                )
                            },
                            label = {
                                Text(
                                    text = "Console (${uiState.terminalLogs.size})",
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    fontWeight = FontWeight.Bold
                                )
                            },
                            modifier = Modifier.testTag("nav_tab_console")
                        )

                        // Volet 3 : Paramètres (theme Light/Dark/System, guides/tips, command rules, changelog)
                        NavigationBarItem(
                            selected = isSettingsPaneActive,
                            onClick = { viewModel.selectTab(KitchenTab.HELP) },
                            icon = {
                                Icon(
                                    imageVector = Icons.Default.Settings,
                                    contentDescription = "Paramètres"
                                )
                            },
                            label = {
                                Text(
                                    text = "Paramètres",
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    fontWeight = FontWeight.Bold
                                )
                            },
                            modifier = Modifier.testTag("nav_tab_settings")
                        )
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
                            sidebarModules.forEach { tab ->
                                NavigationRailItem(
                                    selected = uiState.currentTab == tab,
                                    onClick = { viewModel.selectTab(tab) },
                                    icon = {
                                        Icon(
                                            imageVector = tab.icon(),
                                            contentDescription = tab.sidebarTitle()
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
                        // Quick Sidebar Module Bar when inside the "Action" pane so the 5 sidebar modules
                        // (Key Maker, Sign Pro, Generator, Compilator, Porting) are also 1-tap accessible
                        if (!isWideScreen && isActionPaneActive) {
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
                                    sidebarModules.forEach { tab ->
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
                                                    contentDescription = tab.sidebarTitle(),
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

                        androidx.compose.animation.Crossfade(
                            targetState = uiState.currentTab,
                            label = "tab_crossfade",
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth()
                        ) { targetTab ->
                            when (targetTab) {
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
                                    onDiscoverMultiKeysAndDeps = viewModel::discoverSignProKeysAndInterdependencies,
                                    onSignAllApksOnly = viewModel::signAllApksOnlyInSystem,
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
                                    onInspectGsiMechanism = viewModel::inspectGsiVendorMechanism,
                                    onScanFodStruct = viewModel::scanGsiFodStruct,
                                    onFixFodCoherentStock = viewModel::applyCoherentStockGradeFodFix,
                                    onFixFodOverlayOnlyZeroSign = viewModel::applyOverlayOnlyZeroSignFodFix,
                                    onExecuteFullAutoPort = viewModel::executeGsiToSystemAutoPort
                                )

                                KitchenTab.RECORE -> RecoreScreen(
                                    uiState = uiState,
                                    onSelectDecompiledImg = viewModel::selectDecompiledImgFolder,
                                    onPickCustomSafTree = viewModel::selectCustomDecompiledDirectoryUri,
                                    onRunRecoreDeepAnalysis = viewModel::runRecoreDeepAnalysis,
                                    onRunRecoreAutonomousReconstruction = viewModel::runRecoreAutonomousReconstruction,
                                    onRunRecoreRegenerateArtifacts = viewModel::runRecoreRegenerateAllStaleArtifacts
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
                                    themePreference = uiState.themePreference,
                                    onSelectThemePreference = viewModel::setThemePreference,
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
    KitchenTab.RECORE -> Icons.Default.Psychology
    KitchenTab.CONSOLE -> Icons.Default.Terminal
    KitchenTab.HELP -> Icons.Default.Settings
}

private fun KitchenTab.sidebarTitle(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Key Maker"
    KitchenTab.SIGN_PRO -> "Sign Pro"
    KitchenTab.GENERATOR -> "Generator"
    KitchenTab.COMPILER -> "Compilator (Unpack & Repack)"
    KitchenTab.AUTO_PORTER -> "Porting (Portage de GSI)"
    KitchenTab.RECORE -> "R.E.C.O.R.E (Cerveau Rust/Z3)"
    KitchenTab.CONSOLE -> "Console & Terminal"
    KitchenTab.HELP -> "Paramètres & Aides"
}

private fun KitchenTab.shortLabel(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Key Maker"
    KitchenTab.SIGN_PRO -> "Sign Pro"
    KitchenTab.GENERATOR -> "Generator"
    KitchenTab.COMPILER -> "Compilator"
    KitchenTab.AUTO_PORTER -> "Porting"
    KitchenTab.RECORE -> "R.E.C.O.R.E"
    KitchenTab.CONSOLE -> "Console"
    KitchenTab.HELP -> "Paramètres"
}

private fun KitchenTab.subtitle(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Génération RSA-2048 & Clé Note (-> KEY/)"
    KitchenTab.SIGN_PRO -> "Signature APK, Clé Entière & XML (-> KEY/Data/)"
    KitchenTab.GENERATOR -> "Compilation dex2oat .odex/.vdex & fs-verity"
    KitchenTab.COMPILER -> "Unpack & Repack UKA EXT4/EROFS (-> UNPACK / PACKED)"
    KitchenTab.AUTO_PORTER -> "Mécanisme GSI/Vendor, Scan FODstruct & Fix FOD Stock"
    KitchenTab.RECORE -> "DAG, Symboles ELF64, Shims, Sandbox ARM64 & Solveur Z3 SMT"
    KitchenTab.CONSOLE -> "Historique, Logs entiers, Progression & Commandes"
    KitchenTab.HELP -> "Thème Clair/Sombre/Système, Aides, Règles & Changelog"
}
