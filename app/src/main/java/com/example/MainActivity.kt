package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.KitchenTab
import com.example.ui.RomKitchenViewModel
import com.example.ui.components.IntegratedTerminalConsole
import com.example.ui.components.TopSystemStatusBar
import com.example.ui.screens.AutoPorterScreen
import com.example.ui.screens.CompilerScreen
import com.example.ui.screens.GeneratorScreen
import com.example.ui.screens.KeyMakerScreen
import com.example.ui.screens.SignProScreen
import com.example.ui.theme.MyApplicationTheme

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

    if (uiState.currentTab != KitchenTab.KEY_MAKER) {
        BackHandler {
            viewModel.selectTab(KitchenTab.KEY_MAKER)
        }
    }

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
                    binaries = uiState.extractedBinaries,
                    verificationSummary = uiState.verificationSummary,
                    alerts = alerts,
                    onToggleMode = viewModel::toggleExecutionMode,
                    onRunVerifier = viewModel::runIntelligentCrossVerifier,
                    onRefreshStorage = viewModel::refreshStorageStatusAndFolders
                )
            },
            bottomBar = {
                Column(modifier = Modifier.fillMaxWidth()) {
                    IntegratedTerminalConsole(
                        logs = uiState.terminalLogs,
                        isExpanded = uiState.isTerminalExpanded,
                        onToggleExpand = viewModel::toggleTerminalExpanded,
                        onClear = viewModel::clearLogs
                    )
                    if (!isWideScreen) {
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.surface
                        ) {
                            KitchenTab.entries.forEach { tab ->
                                NavigationBarItem(
                                    selected = uiState.currentTab == tab,
                                    onClick = { viewModel.selectTab(tab) },
                                    icon = {
                                        Icon(
                                            imageVector = tab.icon(),
                                            contentDescription = tab.label
                                        )
                                    },
                                    label = {
                                        Text(
                                            text = tab.shortLabel(),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    },
                                    modifier = Modifier.testTag("nav_tab_${tab.route}")
                                )
                            }
                        }
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

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight()
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
                            onExecuteFullAutoPort = viewModel::executeGsiToSystemAutoPort
                        )
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
}

private fun KitchenTab.shortLabel(): String = when (this) {
    KitchenTab.KEY_MAKER -> "Key Maker"
    KitchenTab.SIGN_PRO -> "Sign Pro"
    KitchenTab.GENERATOR -> "Generator"
    KitchenTab.COMPILER -> "Compilation"
    KitchenTab.AUTO_PORTER -> "Porting GSI"
}
