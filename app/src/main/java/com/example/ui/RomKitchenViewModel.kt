package com.example.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.core.assets.AssetBinaryManager
import com.example.core.assets.ExtractedBinary
import com.example.core.shell.ExecutionMode
import com.example.core.shell.HybridShellEngine
import com.example.core.shell.ImageInspectionReport
import com.example.core.verifier.CrossVerificationSummary
import com.example.core.verifier.CrossVerifierEngine
import com.example.data.local.AppDatabase
import com.example.data.local.ArtCacheEntity
import com.example.data.local.KeyManifestEntity
import com.example.data.local.PortHistoryEntity
import com.example.data.local.VerificationAlertEntity
import com.example.data.repository.RomKitchenRepository
import com.example.modules.compiler.CompilationBuildOutput
import com.example.modules.compiler.FilesystemFormat
import com.example.modules.compiler.ImgCompilerEngine
import com.example.modules.compiler.PreFlightAuditItem
import com.example.modules.generator.ArtGenerationReport
import com.example.modules.generator.ArtGeneratorEngine
import com.example.modules.keymaker.KeyMakerEngine
import com.example.modules.porter.AutoPorterEngine
import com.example.modules.porter.VirtualDeviceTreePortResult
import com.example.modules.signpro.ApkSignTarget
import com.example.modules.signpro.BatchSignResult
import com.example.modules.signpro.SignProEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class KitchenTab(val route: String, val label: String) {
    KEY_MAKER("key_maker", "Key Maker"),
    SIGN_PRO("sign_pro", "Sign Pro"),
    GENERATOR("generator", "Generator"),
    COMPILER("compiler", "Compilation"),
    AUTO_PORTER("auto_porter", "Porting (GSI to System)")
}

data class TerminalLogEntry(
    val id: Long = System.nanoTime(),
    val timestamp: String,
    val message: String,
    val level: String // INFO, SUCCESS, WARN, ERROR
)

data class KitchenUiState(
    val currentTab: KitchenTab = KitchenTab.KEY_MAKER,
    val isBusy: Boolean = false,
    val activeTaskTitle: String = "",
    val executionMode: ExecutionMode = ExecutionMode.NON_ROOT_USERSPACE,
    val isRootAvailable: Boolean = false,
    val extractedBinaries: List<ExtractedBinary> = emptyList(),
    val terminalLogs: List<TerminalLogEntry> = emptyList(),
    val isTerminalExpanded: Boolean = false,
    // Key Maker state
    val keyOrg: String = "LineageOS-Custom-Forge",
    val keyCommonName: String = "AOSP-Security-Chain",
    val keyCountry: String = "FR",
    val keyValidityYears: Int = 25,
    val cleNoteJsonPreview: String = "",
    // Sign Pro state
    val scannedApks: List<ApkSignTarget> = emptyList(),
    val lastBatchSignResult: BatchSignResult? = null,
    val macPermissionsPreview: String = "",
    // Generator state
    val selectedCompilerFilter: String = "speed-profile",
    val selectedInstructionSet: String = "arm64",
    val enableFsVerity: Boolean = true,
    val lastArtReport: ArtGenerationReport? = null,
    // Compiler state
    val selectedFsFormat: FilesystemFormat = FilesystemFormat.EROFS,
    val enableDmVerity: Boolean = true,
    val disableVerityFlagsInVbmeta: Boolean = false,
    val preFlightItems: List<PreFlightAuditItem> = emptyList(),
    val lastCompilationOutput: CompilationBuildOutput? = null,
    val lastMountedImgReport: ImageInspectionReport? = null,
    // Auto-Porter state
    val portAnalysisResult: VirtualDeviceTreePortResult? = null,
    // Cross-Verifier summary
    val verificationSummary: CrossVerificationSummary? = null
)

class RomKitchenViewModel(application: Application) : AndroidViewModel(application) {

    private val database = AppDatabase.getInstance(application)
    private val repository = RomKitchenRepository(database.romKitchenDao())

    private val assetBinaryManager = AssetBinaryManager(application)
    private val shellEngine = HybridShellEngine(
        binDir = assetBinaryManager.getBinDir(),
        workspaceDir = assetBinaryManager.getWorkspaceDir()
    )
    private val keyMakerEngine = KeyMakerEngine(application.filesDir)
    private val signProEngine = SignProEngine(assetBinaryManager.getWorkspaceDir(), keyMakerEngine)
    private val artGeneratorEngine = ArtGeneratorEngine(
        workspaceDir = assetBinaryManager.getWorkspaceDir(),
        binDir = assetBinaryManager.getBinDir(),
        shellEngine = shellEngine,
        repository = repository
    )
    private val imgCompilerEngine = ImgCompilerEngine(
        workspaceDir = assetBinaryManager.getWorkspaceDir(),
        binDir = assetBinaryManager.getBinDir(),
        shellEngine = shellEngine
    )
    private val autoPorterEngine = AutoPorterEngine(assetBinaryManager.getWorkspaceDir())
    private val crossVerifierEngine = CrossVerifierEngine(assetBinaryManager.getWorkspaceDir())

    private val _uiState = MutableStateFlow(KitchenUiState())
    val uiState: StateFlow<KitchenUiState> = _uiState.asStateFlow()

    val keysFlow: StateFlow<List<KeyManifestEntity>> = repository.keysFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val artCacheFlow: StateFlow<List<ArtCacheEntity>> = repository.artCacheFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val alertsFlow: StateFlow<List<VerificationAlertEntity>> = repository.alertsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val portHistoryFlow: StateFlow<List<PortHistoryEntity>> = repository.portHistoryFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        bootstrapEnvironment()
    }

    private fun bootstrapEnvironment() {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Extraction des binaires ARM64 & initialisation AOSP...") }
            val binaries = assetBinaryManager.extractAndVerifyBinaries { appendLog(it) }
            val rootDetected = shellEngine.probeRootAccess()
            val mode = if (rootDetected) ExecutionMode.ROOT_LOOPBACK else ExecutionMode.NON_ROOT_USERSPACE
            shellEngine.setExecutionMode(mode)

            val apks = signProEngine.scanSystemApks()
            val macXml = signProEngine.readCurrentMacPermissionsXml()
            val cleJson = keyMakerEngine.readCleNoteManifestJson()
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(autoRepairBootloopRisks = false) { appendLog(it) }
            val portInit = autoPorterEngine.analyzeStockAndGsiTrees { appendLog(it) }

            val activeKeys = repository.getAllKeys()
            val verifierSummary = crossVerifierEngine.runFullDiagnostic(activeKeys) { appendLog(it) }
            repository.clearAlerts()
            verifierSummary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    extractedBinaries = binaries,
                    isRootAvailable = rootDetected,
                    executionMode = mode,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    cleNoteJsonPreview = cleJson,
                    preFlightItems = preFlight,
                    portAnalysisResult = portInit,
                    verificationSummary = verifierSummary
                )
            }
        }
    }

    fun selectTab(tab: KitchenTab) {
        _uiState.update { it.copy(currentTab = tab) }
    }

    fun toggleTerminalExpanded() {
        _uiState.update { it.copy(isTerminalExpanded = !it.isTerminalExpanded) }
    }

    fun clearLogs() {
        _uiState.update { it.copy(terminalLogs = emptyList()) }
    }

    fun toggleExecutionMode(mode: ExecutionMode) {
        shellEngine.setExecutionMode(mode)
        appendLog("[MODE-SWITCH] Basculement vers ${mode.name} (Root matériel détecté=${_uiState.value.isRootAvailable})")
        _uiState.update { it.copy(executionMode = mode) }
    }

    // --- Module 1: Key Maker ---
    fun updateKeyParameters(org: String, cn: String, country: String) {
        _uiState.update {
            it.copy(
                keyOrg = org,
                keyCommonName = cn,
                keyCountry = country
            )
        }
    }

    fun generateAospKeySuite() {
        viewModelScope.launch {
            val state = _uiState.value
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Génération RSA-2048 (platform, media, shared, testkey)...") }
            val generated = keyMakerEngine.generateFullKeySuite(
                organization = state.keyOrg.ifBlank { "LineageOS-Forge" },
                commonName = state.keyCommonName.ifBlank { "AOSP-Master" },
                countryCode = state.keyCountry.ifBlank { "FR" }.take(2).uppercase(),
                validityYears = state.keyValidityYears,
                onLog = { appendLog(it) }
            )
            repository.clearKeys()
            generated.forEach { repository.saveKey(it) }

            val cleJson = keyMakerEngine.readCleNoteManifestJson()
            val summary = crossVerifierEngine.runFullDiagnostic(generated) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    cleNoteJsonPreview = cleJson,
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Module 2: Sign Pro ---
    fun signAllSystemApksInMemory(injectMacPermissions: Boolean = true) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Signature In-Memory des APKs & injection mac_permissions.xml...") }
            var currentKeys = repository.getAllKeys()
            if (currentKeys.isEmpty()) {
                appendLog("[SIGN-PRO] Aucune clé détectée -> Auto-génération préalable de la chaîne RSA-2048...")
                currentKeys = keyMakerEngine.generateFullKeySuite(
                    organization = _uiState.value.keyOrg,
                    commonName = _uiState.value.keyCommonName,
                    countryCode = _uiState.value.keyCountry,
                    validityYears = 25,
                    onLog = { appendLog(it) }
                )
                currentKeys.forEach { repository.saveKey(it) }
            }

            val batchResult = signProEngine.signAllApksInMemoryAndPatchMacPermissions(
                keys = currentKeys,
                updateMacPerm = injectMacPermissions,
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks()
            val updatedMacXml = signProEngine.readCurrentMacPermissionsXml()
            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    scannedApks = updatedApks,
                    lastBatchSignResult = batchResult,
                    macPermissionsPreview = updatedMacXml,
                    cleNoteJsonPreview = keyMakerEngine.readCleNoteManifestJson(),
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Module 3: Generator (ART Cache & Security) ---
    fun updateGeneratorOptions(filter: String, isa: String, fsVerity: Boolean) {
        _uiState.update {
            it.copy(
                selectedCompilerFilter = filter,
                selectedInstructionSet = isa,
                enableFsVerity = fsVerity
            )
        }
    }

    fun runArtDex2oatGenerator(forceRecompile: Boolean = false) {
        viewModelScope.launch {
            val state = _uiState.value
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Compilation ART dex2oat (.odex/.vdex) & métadonnées fs-verity...") }
            val currentKeys = repository.getAllKeys()
            val report = artGeneratorEngine.generateArtCacheAndSecurityArtifacts(
                compilerFilter = state.selectedCompilerFilter,
                instructionSet = state.selectedInstructionSet,
                enableFsVerity = state.enableFsVerity,
                forceRecompile = forceRecompile,
                activeKeys = currentKeys,
                onLog = { appendLog(it) }
            )
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    lastArtReport = report
                )
            }
        }
    }

    fun clearMd5ArtCache() {
        viewModelScope.launch {
            repository.clearArtCache()
            appendLog("[MD5-CACHE] Cache MD5 ART vidé avec succès.")
        }
    }

    // --- Module 4: Compilation & Anti-Bootloop ---
    fun updateCompilerOptions(format: FilesystemFormat, dmVerity: Boolean, disableFlags: Boolean) {
        _uiState.update {
            it.copy(
                selectedFsFormat = format,
                enableDmVerity = dmVerity,
                disableVerityFlagsInVbmeta = disableFlags
            )
        }
    }

    fun runPreFlightAudit(autoRepair: Boolean) {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Audit statique SELinux & fs_config...") }
            val items = imgCompilerEngine.runPreFlightStaticAudit(autoRepair) { appendLog(it) }
            val summary = crossVerifierEngine.runFullDiagnostic(repository.getAllKeys()) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    preFlightItems = items,
                    verificationSummary = summary
                )
            }
        }
    }

    fun compileFullSystemAndVbmeta() {
        viewModelScope.launch {
            val state = _uiState.value
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Construction ${state.selectedFsFormat.name} + AVB 2.0 dm-verity...") }
            val activeKeys = repository.getAllKeys()
            val output = imgCompilerEngine.compileSystemAndVbmetaImages(
                format = state.selectedFsFormat,
                enableDmVerity = state.enableDmVerity,
                disableVerityFlagsInVbmeta = state.disableVerityFlagsInVbmeta,
                activeKeys = activeKeys,
                onLog = { appendLog(it) }
            )
            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys) { appendLog(it) }
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    preFlightItems = output.preFlightItems,
                    lastCompilationOutput = output,
                    verificationSummary = summary
                )
            }
        }
    }

    fun importAndInspectExternalImg(uri: Uri?, fallbackName: String = "system_stock.img") {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Inspection binaire & extraction de l'image .img...") }
            val ws = assetBinaryManager.getWorkspaceDir()
            val targetImgFile = File(ws, fallbackName)

            if (uri != null) {
                withContext(Dispatchers.IO) {
                    try {
                        getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                            targetImgFile.outputStream().use { out ->
                                input.copyTo(out)
                            }
                        }
                        appendLog("[SAF-IMPORT] Fichier .img importé via Scoped Storage : ${targetImgFile.name} (${targetImgFile.length() / 1024} KB)")
                    } catch (e: Exception) {
                        appendLog("[SAF-IMPORT] Avertissement lecture URI : ${e.message}")
                    }
                }
            }

            val report = shellEngine.inspectAndMountOrExtractImg(
                imgFile = targetImgFile,
                targetDir = File(ws, "system_ext4"),
                onLog = { appendLog(it) }
            )
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    lastMountedImgReport = report
                )
            }
        }
    }

    // --- Module 5: Auto-Porter (GSI to System) ---
    fun executeGsiToSystemAutoPort() {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Portage GSI -> System (Blobs, RRO, VINTF, SEPolicy & Résolveur FOD)...") }
            val result = autoPorterEngine.executeFullGsiPortingPipeline { appendLog(it) }

            repository.addPortHistory(
                PortHistoryEntity(
                    stockDeviceName = "${result.stockDeviceBrand} ${result.stockDeviceCodename} (${result.stockBoardPlatform})",
                    gsiTargetName = result.gsiTargetName,
                    blobsTransplanted = result.proprietaryBlobs.size,
                    rroOverlayPath = result.rroOverlayApkPath,
                    sepolicyRulesMerged = result.sepolicyCilMergedRulesCount,
                    fodStatus = "Actif (${result.fodDiagnostics.sensorVendor})",
                    hbmSysfsNode = result.fodDiagnostics.hbmSysfsNode
                )
            )

            val updatedApks = signProEngine.scanSystemApks()
            val summary = crossVerifierEngine.runFullDiagnostic(repository.getAllKeys()) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    portAnalysisResult = result,
                    scannedApks = updatedApks,
                    verificationSummary = summary
                )
            }
        }
    }

    fun runIntelligentCrossVerifier() {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Exécution du Vérificateur Croisé Intelligent...") }
            val summary = crossVerifierEngine.runFullDiagnostic(repository.getAllKeys()) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    verificationSummary = summary
                )
            }
        }
    }

    private fun appendLog(rawMessage: String) {
        val time = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val level = when {
            rawMessage.contains("ERREUR") || rawMessage.contains("CRITICAL") || rawMessage.contains("[STDERR]") -> "ERROR"
            rawMessage.contains("Avertissement") || rawMessage.contains("WARN") -> "WARN"
            rawMessage.contains("succès") || rawMessage.contains("terminé") || rawMessage.contains("validés") -> "SUCCESS"
            else -> "INFO"
        }
        val entry = TerminalLogEntry(timestamp = time, message = rawMessage, level = level)
        _uiState.update { current ->
            val updated = (current.terminalLogs + entry).takeLast(250)
            current.copy(terminalLogs = updated)
        }
    }
}
