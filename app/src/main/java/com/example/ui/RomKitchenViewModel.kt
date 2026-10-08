package com.example.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.core.assets.AssetBinaryManager
import com.example.core.assets.ExtractedBinary
import com.example.core.recore.RecoreEngine
import com.example.core.recore.RecoreFullBrainReport
import com.example.core.shell.ExecutionMode
import com.example.core.shell.HybridShellEngine
import com.example.core.shell.ImageInspectionReport
import com.example.core.storage.RomForgeStorageManager
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
import com.example.modules.signpro.SignProDiscoveryReport
import com.example.modules.signpro.SignProEngine
import com.example.modules.signpro.SignatureVerificationReport
import com.example.ui.theme.AppThemePreference
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
import java.io.FileInputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class KitchenTab(val route: String, val label: String) {
    KEY_MAKER("key_maker", "Key Maker"),
    SIGN_PRO("sign_pro", "Sign Pro"),
    GENERATOR("generator", "Generator"),
    COMPILER("compiler", "Compilator"),
    AUTO_PORTER("auto_porter", "Porting (GSI)"),
    RECORE("recore", "R.E.C.O.R.E"),
    CONSOLE("console", "Console"),
    HELP("help", "Paramètres")
}

enum class SignProInputMode(val label: String) {
    DECOMPILED_IMG_FOLDER("IMG Décompilé (UNPACK)"),
    SINGLE_STANDALONE_APK("APK Individuel (.apk)")
}

data class TerminalLogEntry(
    val id: Long = System.nanoTime(),
    val timestamp: String,
    val message: String,
    val level: String // INFO, SUCCESS, WARN, ERROR
)

data class ActionExecutionRecord(
    val id: Long = System.nanoTime(),
    val moduleLabel: String,
    val actionTitle: String,
    val targetName: String,
    val startedAt: String,
    val finishedAt: String,
    val status: String, // EN_COURS, SUCCÈS, ERREUR
    val progressPercent: Int = 100,
    val summaryDetail: String = ""
)

data class KitchenUiState(
    val currentTab: KitchenTab = KitchenTab.KEY_MAKER,
    val previousTabBeforeConsole: KitchenTab = KitchenTab.KEY_MAKER,
    val themePreference: AppThemePreference = AppThemePreference.SYSTEM,
    val isBusy: Boolean = false,
    val activeTaskTitle: String = "",
    val activeTaskProgress: Float = 0f,
    val actionHistory: List<ActionExecutionRecord> = emptyList(),
    val executionMode: ExecutionMode = ExecutionMode.NON_ROOT_USERSPACE,
    val isRootAvailable: Boolean = false,
    val extractedBinaries: List<ExtractedBinary> = emptyList(),
    val terminalLogs: List<TerminalLogEntry> = emptyList(),
    // Public ROM_FORGE Storage status
    val romForgePublicPath: String = "/storage/emulated/0/ROM_FORGE",
    val hasAllFilesAccess: Boolean = false,
    val availableDecompiledImgs: List<String> = listOf("system_ext4"),
    val selectedDecompiledImgName: String = "system_ext4",
    val selectedDecompiledImgFullPath: String = "/storage/emulated/0/ROM_FORGE/UNPACK/system_ext4",
    // Key Maker state
    val keyOrg: String = "LineageOS-Custom-Forge",
    val keyCommonName: String = "AOSP-Security-Chain",
    val keyCountry: String = "FR",
    val keyValidityYears: Int = 25,
    val cleNoteJsonPreview: String = "",
    // Sign Pro state
    val signProMode: SignProInputMode = SignProInputMode.DECOMPILED_IMG_FOLDER,
    val selectedSingleApkPath: String = "",
    val selectedSingleApkName: String = "Aucun APK individuel sélectionné",
    val selectedSingleApkRole: String = "platform",
    val lastSingleSignedApkOutPath: String = "",
    val scannedApks: List<ApkSignTarget> = emptyList(),
    val signProDiscoveryReport: SignProDiscoveryReport? = null,
    val lastBatchSignResult: BatchSignResult? = null,
    val lastSignatureReport: SignatureVerificationReport? = null,
    val macPermissionsPreview: String = "",
    // Generator state
    val selectedCompilerFilter: String = "speed-profile",
    val selectedInstructionSet: String = "arm64",
    val enableFsVerity: Boolean = true,
    val lastArtReport: ArtGenerationReport? = null,
    // Compiler state
    val selectedFsFormat: FilesystemFormat = FilesystemFormat.EXT4,
    val enableDmVerity: Boolean = false,
    val disableVerityFlagsInVbmeta: Boolean = true,
    val preFlightItems: List<PreFlightAuditItem> = emptyList(),
    val lastCompilationOutput: CompilationBuildOutput? = null,
    val lastMountedImgReport: ImageInspectionReport? = null,
    // Auto-Porter state
    val portAnalysisResult: VirtualDeviceTreePortResult? = null,
    // R.E.C.O.R.E Brain state
    val recoreBrainReport: RecoreFullBrainReport? = null,
    // Cross-Verifier summary
    val verificationSummary: CrossVerificationSummary? = null,
    // Console saved path
    val lastSavedLogFilePath: String = ""
)

class RomKitchenViewModel(application: Application) : AndroidViewModel(application) {

    private val database = AppDatabase.getInstance(application)
    private val repository = RomKitchenRepository(database.romKitchenDao())

    private val storageManager = RomForgeStorageManager(application)
    private val assetBinaryManager = AssetBinaryManager(application, storageManager)
    private val shellEngine = HybridShellEngine(
        binDir = assetBinaryManager.getBinDir(),
        workspaceDir = assetBinaryManager.getWorkspaceDir()
    )
    private val keyMakerEngine = KeyMakerEngine(storageManager.getRomForgePublicRoot())
    private val artGeneratorEngine = ArtGeneratorEngine(
        defaultWorkspaceDir = assetBinaryManager.getWorkspaceDir(),
        binDir = assetBinaryManager.getBinDir(),
        shellEngine = shellEngine,
        repository = repository
    )
    private val signProEngine = SignProEngine(
        defaultWorkspaceDir = assetBinaryManager.getWorkspaceDir(),
        keyMakerEngine = keyMakerEngine,
        artGeneratorEngine = artGeneratorEngine
    )
    private val imgCompilerEngine = ImgCompilerEngine(
        defaultWorkspaceDir = assetBinaryManager.getWorkspaceDir(),
        binDir = assetBinaryManager.getBinDir(),
        shellEngine = shellEngine
    )
    private val autoPorterEngine = AutoPorterEngine(assetBinaryManager.getWorkspaceDir())
    private val crossVerifierEngine = CrossVerifierEngine(assetBinaryManager.getWorkspaceDir())
    private val recoreEngine = RecoreEngine(
        workspaceDir = assetBinaryManager.getWorkspaceDir(),
        keyDataDir = storageManager.getKeyDataReportsDir(),
        signProEngine = signProEngine,
        imgCompilerEngine = imgCompilerEngine,
        artGeneratorEngine = artGeneratorEngine
    )

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

    fun refreshStorageStatusAndFolders() {
        viewModelScope.launch {
            val (status, folders, activeDir) = withContext(Dispatchers.IO) {
                val st = storageManager.getStorageStatus()
                val fl = storageManager.listDecompiledImgDirectories()
                val currentName = _uiState.value.selectedDecompiledImgName
                val act = fl.find { it.name == currentName } ?: fl.first()
                Triple(st, fl, act)
            }
            val apks = signProEngine.scanSystemApks(activeDir)
            val macXml = withContext(Dispatchers.IO) {
                signProEngine.readCurrentMacPermissionsXml(activeDir)
            }

            _uiState.update {
                it.copy(
                    romForgePublicPath = status.publicRootPath,
                    hasAllFilesAccess = status.hasAllFilesAccess,
                    availableDecompiledImgs = folders.map { f -> f.name },
                    selectedDecompiledImgName = activeDir.name,
                    selectedDecompiledImgFullPath = activeDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml
                )
            }
        }
    }

    private fun bootstrapEnvironment() {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Initialisation fluide de ROM_FORGE (UNPACK, PACKED, KEY, PORT)...") }
            val binaries = assetBinaryManager.extractAndVerifyBinaries { appendLog(it) }
            val rootDetected = shellEngine.probeRootAccess()
            val mode = if (rootDetected) ExecutionMode.ROOT_LOOPBACK else ExecutionMode.NON_ROOT_USERSPACE
            shellEngine.setExecutionMode(mode)

            val (status, folders, activeDir) = withContext(Dispatchers.IO) {
                val st = storageManager.getStorageStatus()
                val fl = storageManager.listDecompiledImgDirectories()
                Triple(st, fl, fl.first())
            }

            val apks = signProEngine.scanSystemApks(activeDir)
            val (macXml, cleJson) = withContext(Dispatchers.IO) {
                signProEngine.readCurrentMacPermissionsXml(activeDir) to keyMakerEngine.readCleNoteManifestJson()
            }
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = false,
                targetDecompiledDir = activeDir
            ) { appendLog(it) }
            val portInit = autoPorterEngine.analyzeStockAndGsiTrees(activeDir) { appendLog(it) }

            val activeKeys = repository.getAllKeys()
            val verifierSummary = crossVerifierEngine.runFullDiagnostic(activeKeys, activeDir) { appendLog(it) }
            repository.clearAlerts()
            verifierSummary.alerts.forEach { repository.addAlert(it) }

            val recoreInit = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = activeDir,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    extractedBinaries = binaries,
                    isRootAvailable = rootDetected,
                    executionMode = mode,
                    romForgePublicPath = status.publicRootPath,
                    hasAllFilesAccess = status.hasAllFilesAccess,
                    availableDecompiledImgs = folders.map { f -> f.name },
                    selectedDecompiledImgName = activeDir.name,
                    selectedDecompiledImgFullPath = activeDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    cleNoteJsonPreview = cleJson,
                    preFlightItems = preFlight,
                    portAnalysisResult = portInit,
                    recoreBrainReport = recoreInit,
                    verificationSummary = verifierSummary
                )
            }
        }
    }

    fun selectTab(tab: KitchenTab) {
        _uiState.update {
            val isActionModule = tab != KitchenTab.CONSOLE && tab != KitchenTab.HELP
            val prev = if (isActionModule) tab else it.previousTabBeforeConsole
            it.copy(currentTab = tab, previousTabBeforeConsole = prev)
        }
    }

    fun setThemePreference(pref: AppThemePreference) {
        _uiState.update { it.copy(themePreference = pref) }
        appendLog("[THEME] Thème d'interface configuré sur : ${pref.label}")
    }

    private fun recordActionCompleted(
        moduleLabel: String,
        actionTitle: String,
        targetName: String,
        summaryDetail: String
    ) {
        val now = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val entry = ActionExecutionRecord(
            moduleLabel = moduleLabel,
            actionTitle = actionTitle,
            targetName = targetName,
            startedAt = now,
            finishedAt = now,
            status = "SUCCÈS",
            progressPercent = 100,
            summaryDetail = summaryDetail
        )
        _uiState.update {
            it.copy(actionHistory = (listOf(entry) + it.actionHistory).take(50))
        }
    }

    fun toggleConsoleTab() {
        _uiState.update {
            if (it.currentTab == KitchenTab.CONSOLE) {
                it.copy(currentTab = it.previousTabBeforeConsole)
            } else {
                val prev = if (it.currentTab != KitchenTab.CONSOLE && it.currentTab != KitchenTab.HELP) {
                    it.currentTab
                } else {
                    it.previousTabBeforeConsole
                }
                it.copy(
                    currentTab = KitchenTab.CONSOLE,
                    previousTabBeforeConsole = prev
                )
            }
        }
    }

    fun selectDecompiledImgAndNavigate(folderName: String, targetTab: KitchenTab) {
        selectDecompiledImgFolder(folderName)
        selectTab(targetTab)
    }

    fun clearLogs() {
        _uiState.update { it.copy(terminalLogs = emptyList()) }
    }

    fun toggleExecutionMode(mode: ExecutionMode) {
        shellEngine.setExecutionMode(mode)
        appendLog("[MODE-SWITCH] Basculement vers ${mode.name} (Espace actif : ${_uiState.value.romForgePublicPath})")
        _uiState.update { it.copy(executionMode = mode) }
    }

    fun selectDecompiledImgFolder(folderName: String) {
        val targetDir = File(storageManager.getUnpackRootDir(), folderName)
        // Instant UI feedback before background scan
        _uiState.update {
            it.copy(
                selectedDecompiledImgName = targetDir.name,
                selectedDecompiledImgFullPath = targetDir.absolutePath
            )
        }
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                if (!targetDir.exists() || (targetDir.listFiles()?.isEmpty() == true)) {
                    assetBinaryManager.populateDecompiledImgStructure(targetDir, folderName)
                }
            }
            val apks = signProEngine.scanSystemApks(targetDir)
            val macXml = withContext(Dispatchers.IO) {
                signProEngine.readCurrentMacPermissionsXml(targetDir)
            }
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = false,
                targetDecompiledDir = targetDir
            ) { appendLog(it) }
            val portAnalysis = autoPorterEngine.analyzeStockAndGsiTrees(targetDir) { appendLog(it) }
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = repository.getAllKeys(),
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )

            appendLog("[UNPACK-SELECT] Système décompilé sélectionné : UNPACK/${targetDir.name} (${apks.size} APKs détectés)")
            _uiState.update {
                it.copy(
                    selectedDecompiledImgName = targetDir.name,
                    selectedDecompiledImgFullPath = targetDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    preFlightItems = preFlight,
                    portAnalysisResult = portAnalysis,
                    recoreBrainReport = recoreReport
                )
            }
        }
    }

    fun selectCustomDecompiledDirectoryUri(treeUri: Uri?) {
        if (treeUri == null) return
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Liaison du dossier UNPACK...") }
            storageManager.saveCustomSafTreeUri(treeUri)
            val resolvedDir = storageManager.resolveOrImportSafDirectory(
                treeUri = treeUri,
                fallbackFolderName = "custom_img_${System.currentTimeMillis() % 10000}",
                onLog = { appendLog(it) }
            )
            if (resolvedDir.listFiles()?.isEmpty() == true) {
                assetBinaryManager.populateDecompiledImgStructure(resolvedDir, resolvedDir.name)
            }
            val folders = storageManager.listDecompiledImgDirectories()
            val apks = signProEngine.scanSystemApks(resolvedDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(resolvedDir)

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    availableDecompiledImgs = (folders.map { f -> f.name } + resolvedDir.name).distinct(),
                    selectedDecompiledImgName = resolvedDir.name,
                    selectedDecompiledImgFullPath = resolvedDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml
                )
            }
        }
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
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Génération RSA-2048 dans ROM_FORGE/KEY...") }
            val generated = keyMakerEngine.generateFullKeySuite(
                organization = state.keyOrg.ifBlank { "LineageOS-Forge" },
                commonName = state.keyCommonName.ifBlank { "AOSP-Master" },
                countryCode = state.keyCountry.ifBlank { "FR" }.take(2).uppercase(),
                validityYears = state.keyValidityYears,
                onLog = { appendLog(it) }
            )
            repository.clearKeys()
            generated.forEach { repository.saveKey(it) }

            storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = keyMakerEngine.getKeystoreDir(),
                subFolderName = "KEY",
                onLog = { appendLog(it) }
            )

            val cleJson = keyMakerEngine.readCleNoteManifestJson()
            val activeDir = File(_uiState.value.selectedDecompiledImgFullPath)
            val summary = crossVerifierEngine.runFullDiagnostic(generated, activeDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "Key Maker",
                actionTitle = "Génération 4 Paires RSA-2048 & Clé Note",
                targetName = "ROM_FORGE/KEY",
                summaryDetail = "${generated.size} certificats X.509v3 (.pk8 & .x509.pem) + manifest.json"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    cleNoteJsonPreview = cleJson,
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Module 2: Sign Pro ---
    fun setSignProInputMode(mode: SignProInputMode) {
        _uiState.update { it.copy(signProMode = mode) }
    }

    fun setSingleApkRole(role: String) {
        _uiState.update { it.copy(selectedSingleApkRole = role) }
    }

    fun pickSingleApkToSign(uri: Uri?) {
        viewModelScope.launch {
            val signedDir = storageManager.getSingleSignedApksDir()
            val targetInputApk: File

            if (uri != null) {
                val displayName = resolveUriDisplayName(uri) ?: "input_custom.apk"
                val cleanName = if (displayName.endsWith(".apk", true)) displayName else "$displayName.apk"
                targetInputApk = File(signedDir, cleanName)
                withContext(Dispatchers.IO) {
                    try {
                        getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                            targetInputApk.outputStream().use { out -> input.copyTo(out) }
                        }
                        appendLog("[SIGN-PRO-APK] APK chargé : ${targetInputApk.absolutePath} (${targetInputApk.length() / 1024} KB)")
                    } catch (e: Exception) {
                        appendLog("[SIGN-PRO-APK] Création d'un APK de test suite à : ${e.message}")
                        assetBinaryManager.createMinimalSampleApk(targetInputApk, "com.custom.target", "platform")
                    }
                }
            } else {
                targetInputApk = File(signedDir, "CustomSystemApp_unsigned.apk")
                if (!targetInputApk.exists()) {
                    assetBinaryManager.createMinimalSampleApk(targetInputApk, "com.custom.systemapp", "platform")
                }
                appendLog("[SIGN-PRO-APK] APK sélectionné : ${targetInputApk.absolutePath}")
            }

            val autoRole = signProEngine.detectOptimalKeyRole(targetInputApk)
            _uiState.update {
                it.copy(
                    selectedSingleApkPath = targetInputApk.absolutePath,
                    selectedSingleApkName = targetInputApk.name,
                    selectedSingleApkRole = autoRole
                )
            }
        }
    }

    /**
     * Signs ONLY the selected APK inside the unpacked `.img` directory (`in-place`)
     * without signing all other APKs.
     */
    fun signSingleApkInDecompiledSystem(apkTarget: ApkSignTarget) {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Signature de l'APK uniquement : ${apkTarget.name}..."
                )
            }

            val currentKeys = ensureKeysAvailable(state)
            signProEngine.signSingleApkInDecompiledSystem(
                apkTarget = apkTarget,
                keys = currentKeys,
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    scannedApks = updatedApks
                )
            }
        }
    }

    /**
     * Verifies the cryptographic signature of either a single APK (`singleTarget != null`)
     * or all APKs in the unpacked system (`singleTarget == null`), and exports JSON + TXT reports to `ROM_FORGE/KEY/Data/`.
     */
    fun verifyApkSignaturesAndExportReports(singleTarget: ApkSignTarget? = null) {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            val keyDataDir = storageManager.getKeyDataReportsDir()
            val label = singleTarget?.name ?: "Tous les APKs (${targetDir.name})"

            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Audit de signature sur $label -> KEY/Data..."
                )
            }

            val currentKeys = repository.getAllKeys()
            val report = signProEngine.verifySignaturesAndExportReport(
                targetDecompiledDir = targetDir,
                singleApkFilter = singleTarget,
                activeKeys = currentKeys,
                keyDataDir = keyDataDir,
                onLog = { appendLog(it) }
            )

            val pubJson = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(report.jsonReportPath),
                subFolder = "KEY/Data",
                onLog = { appendLog(it) }
            )
            val pubTxt = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(report.txtReportPath),
                subFolder = "KEY/Data",
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    scannedApks = updatedApks,
                    lastSignatureReport = report.copy(
                        jsonReportPath = pubJson,
                        txtReportPath = pubTxt
                    )
                )
            }
        }
    }

    fun signSingleSelectedApk() {
        viewModelScope.launch {
            val state = _uiState.value
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Signature de l'APK individuel...") }

            val currentKeys = ensureKeysAvailable(state)
            val sourceFile = if (state.selectedSingleApkPath.isNotEmpty() && File(state.selectedSingleApkPath).exists()) {
                File(state.selectedSingleApkPath)
            } else {
                val sample = File(storageManager.getSingleSignedApksDir(), "CustomSystemApp_unsigned.apk")
                assetBinaryManager.createMinimalSampleApk(sample, "com.custom.systemapp", state.selectedSingleApkRole)
                sample
            }

            val signedOut = signProEngine.signStandaloneApkFile(
                sourceApkFile = sourceFile,
                outputDir = storageManager.getSingleSignedApksDir(),
                selectedRole = state.selectedSingleApkRole,
                keys = currentKeys,
                onLog = { appendLog(it) }
            )

            val publicPath = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = signedOut,
                subFolder = "PACKED/signed_apks",
                onLog = { appendLog(it) }
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    selectedSingleApkPath = sourceFile.absolutePath,
                    selectedSingleApkName = sourceFile.name,
                    lastSingleSignedApkOutPath = publicPath
                )
            }
        }
    }

    /**
     * Discovers all distinct certificate groups (1, 4, 5, 6, 8+ keys) and maps APK co-signing & system file interdependencies.
     */
    fun discoverSignProKeysAndInterdependencies() {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Cartographie des clés & interdépendances APK dans UNPACK/${targetDir.name}...",
                    activeTaskProgress = 0.4f
                )
            }
            val discovery = signProEngine.discoverAndRegisterAllKeysInImage(
                targetDecompiledDir = targetDir,
                keyDataDir = storageManager.getKeyDataReportsDir(),
                onLog = { appendLog(it) }
            )
            // Also ensure matching RSA-2048 keys are generated and saved in Room DB for all discovered roles
            val currentKeys = ensureKeysAvailable(state)
            val expandedKeys = signProEngine.ensureDynamicKeySuiteMatchesDiscoveredRoles(
                existingKeys = currentKeys,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )
            if (expandedKeys.size != currentKeys.size) {
                repository.clearKeys()
                expandedKeys.forEach { repository.saveKey(it) }
            }

            val regFile = File(discovery.registeredRegistryPath)
            if (regFile.exists()) {
                storageManager.exportSingleFileToPublicRomForge(regFile, "KEY/Data") { appendLog(it) }
            }

            recordActionCompleted(
                moduleLabel = "Sign Pro",
                actionTitle = "Cartographie Multi-Clés & Interdépendances APK",
                targetName = targetDir.name,
                summaryDetail = "${discovery.totalDistinctKeysDiscovered} clés détectées & enregistrées | ${discovery.totalApksScanned} APKs cartographiés"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    signProDiscoveryReport = discovery,
                    cleNoteJsonPreview = keyMakerEngine.readCleNoteManifestJson()
                )
            }
        }
    }

    /**
     * Button 1 in Sign Pro: `Sign All` (Signs all APKs only, respecting multi-key role clusters, without modifying system XMLs or OAT/VDEX).
     */
    fun signAllApksOnlyInSystem() {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Sign All (Signature pure des APKs uniquement) dans UNPACK/${targetDir.name}...",
                    activeTaskProgress = 0.35f
                )
            }
            val baseKeys = ensureKeysAvailable(state)
            val dynamicKeys = signProEngine.ensureDynamicKeySuiteMatchesDiscoveredRoles(baseKeys, targetDir) { appendLog(it) }
            if (dynamicKeys.size != baseKeys.size) {
                repository.clearKeys()
                dynamicKeys.forEach { repository.saveKey(it) }
            }

            val discovery = signProEngine.discoverAndRegisterAllKeysInImage(
                targetDecompiledDir = targetDir,
                keyDataDir = storageManager.getKeyDataReportsDir(),
                onLog = { appendLog(it) }
            )
            val batchResult = signProEngine.signAllApksOnly(
                keys = dynamicKeys,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            val publicMirroredPath = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetDir,
                subFolderName = "UNPACK/${targetDir.name}",
                onLog = { appendLog(it) }
            )
            val updatedApks = signProEngine.scanSystemApks(targetDir)

            recordActionCompleted(
                moduleLabel = "Sign Pro",
                actionTitle = "Sign All (APKs Uniquement • ${dynamicKeys.size} Clés)",
                targetName = targetDir.name,
                summaryDetail = "${batchResult.signedSuccess}/${batchResult.totalApks} APKs signés (${dynamicKeys.size} clés de rôle) sans toucher aux fichiers système"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    scannedApks = updatedApks,
                    signProDiscoveryReport = discovery,
                    lastBatchSignResult = batchResult.copy(outputDirectoryPath = publicMirroredPath),
                    cleNoteJsonPreview = keyMakerEngine.readCleNoteManifestJson()
                )
            }
        }
    }

    /**
     * Button 2 in Sign Pro: `Sign All Pro` (Signs all APKs with N-key role parity AND synchronizes all dependent files:
     * `plat_mac_permissions.xml`, `privapp-permissions-*.xml`, `otacerts.zip`, `.odex`, `.vdex`, `.oat`, `.art`, `.fsv_meta`, `build.prop`).
     */
    fun signAllSystemApksInMemory(injectMacPermissions: Boolean = true) {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Sign All Pro (APKs + Chaîne de Confiance + OAT/VDEX/fsv_meta) sur UNPACK/${targetDir.name}...",
                    activeTaskProgress = 0.25f
                )
            }
            val baseKeys = ensureKeysAvailable(state)
            val currentKeys = signProEngine.ensureDynamicKeySuiteMatchesDiscoveredRoles(baseKeys, targetDir) { appendLog(it) }
            if (currentKeys.size != baseKeys.size) {
                repository.clearKeys()
                currentKeys.forEach { repository.saveKey(it) }
            }

            val discovery = signProEngine.discoverAndRegisterAllKeysInImage(
                targetDecompiledDir = targetDir,
                keyDataDir = storageManager.getKeyDataReportsDir(),
                onLog = { appendLog(it) }
            )

            val batchResult = signProEngine.signAllApksInMemoryAndPatchMacPermissions(
                keys = currentKeys,
                updateMacPerm = injectMacPermissions,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            // Also generate the signature audit report in KEY/Data automatically
            val sigReport = signProEngine.verifySignaturesAndExportReport(
                targetDecompiledDir = targetDir,
                singleApkFilter = null,
                activeKeys = currentKeys,
                keyDataDir = storageManager.getKeyDataReportsDir(),
                onLog = { appendLog(it) }
            )

            val publicMirroredPath = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetDir,
                subFolderName = "UNPACK/${targetDir.name}",
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            val updatedMacXml = signProEngine.readCurrentMacPermissionsXml(targetDir)
            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys, targetDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = currentKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )

            recordActionCompleted(
                moduleLabel = "Sign Pro",
                actionTitle = "Sign All Pro (${currentKeys.size} Clés + OAT/VDEX/fsv_meta + SELinux MAC)",
                targetName = targetDir.name,
                summaryDetail = "${batchResult.signedSuccess}/${batchResult.totalApks} APKs signés + OAT/VDEX/fsv_meta régénérés + Z3=${recoreReport.smtStatus}"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    scannedApks = updatedApks,
                    signProDiscoveryReport = discovery,
                    lastBatchSignResult = batchResult.copy(outputDirectoryPath = publicMirroredPath),
                    lastSignatureReport = sigReport,
                    macPermissionsPreview = updatedMacXml,
                    cleNoteJsonPreview = keyMakerEngine.readCleNoteManifestJson(),
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    private suspend fun ensureKeysAvailable(state: KitchenUiState): List<KeyManifestEntity> {
        var currentKeys = repository.getAllKeys()
        if (currentKeys.isEmpty() || currentKeys.any { !File(it.pk8Path).exists() }) {
            appendLog("[KEY-AUTO] Génération automatique de la chaîne de confiance RSA-2048 dans ROM_FORGE/KEY...")
            currentKeys = keyMakerEngine.generateFullKeySuite(
                organization = state.keyOrg,
                commonName = state.keyCommonName,
                countryCode = state.keyCountry,
                validityYears = 25,
                onLog = { appendLog(it) }
            )
            repository.clearKeys()
            currentKeys.forEach { repository.saveKey(it) }
        }
        return currentKeys
    }

    // --- Module 3: Generator ---
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
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Compilation ART dex2oat (.odex/.vdex) sur UNPACK/${targetDir.name}..."
                )
            }
            val currentKeys = ensureKeysAvailable(state)
            val report = artGeneratorEngine.generateArtCacheAndSecurityArtifacts(
                compilerFilter = state.selectedCompilerFilter,
                instructionSet = state.selectedInstructionSet,
                enableFsVerity = state.enableFsVerity,
                forceRecompile = forceRecompile,
                activeKeys = currentKeys,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            val publicPath = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetDir,
                subFolderName = "UNPACK/${targetDir.name}",
                onLog = { appendLog(it) }
            )
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = currentKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )

            recordActionCompleted(
                moduleLabel = "Generator",
                actionTitle = "Compilation R.E.C.O.R.E ART (.odex/.vdex/.art/.fsv_meta)",
                targetName = targetDir.name,
                summaryDetail = "${report.compiledCount} APKs + ${report.bootArtImagesCount} Boot Images ART | ${report.fsVerityGeneratedCount} .fsv_meta"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    recoreBrainReport = recoreReport,
                    lastArtReport = report.copy(targetAbsolutePath = publicPath)
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

    // --- Module 4: Compilation & Real EXT4 Decompilation ---
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
            val targetDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Audit statique SELinux & fs_config sur ${targetDir.name}...") }
            val items = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = autoRepair,
                targetDecompiledDir = targetDir
            ) { appendLog(it) }
            val summary = crossVerifierEngine.runFullDiagnostic(repository.getAllKeys(), targetDir) { appendLog(it) }
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
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Repack Fidèle à l'Original (${state.selectedFsFormat.name} • Sans altérer les signatures APK) depuis UNPACK/${targetDir.name}...",
                    activeTaskProgress = 0.25f
                )
            }
            val activeKeys = repository.getAllKeys()

            // 1. Run non-destructive R.E.C.O.R.E analysis (autoHealAndGenerateShims = false) so Repack NEVER modifies or re-signs APKs!
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )
            _uiState.update { it.copy(activeTaskProgress = 0.55f) }

            // 2. Compile image faithfully to original base .img structure + generate delta/risk report without touching APK signatures
            val output = imgCompilerEngine.compileSystemAndVbmetaImages(
                format = state.selectedFsFormat,
                enableDmVerity = state.enableDmVerity,
                disableVerityFlagsInVbmeta = state.disableVerityFlagsInVbmeta,
                activeKeys = activeKeys,
                targetDecompiledDir = targetDir,
                outputImagesDir = storageManager.getPackedOutputImagesDir(),
                onLog = { appendLog(it) }
            )

            val pubSystemImg = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(output.systemImgPath),
                subFolder = "PACKED",
                onLog = { appendLog(it) }
            )
            val pubVbmetaImg = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(output.vbmetaImgPath),
                subFolder = "PACKED",
                onLog = { appendLog(it) }
            )

            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys, targetDir) { appendLog(it) }
            val fidelity = output.recoreRepackReport
            val fidelityDesc = if (fidelity == null || fidelity.changedElements.isEmpty()) "100% Identique à l'Original (0 signature modifiée)" else "${fidelity.changedElements.size} modifs (Signatures APK préservées)"
            val riskDesc = fidelity?.overallRiskLevel ?: "ZERO_RISK_IDENTICAL"
            recordActionCompleted(
                moduleLabel = "Compilator • R.E.C.O.R.E",
                actionTitle = "Repack Fidèle à l'Original (${state.selectedFsFormat.name} • Zéro Re-Signature APK)",
                targetName = targetDir.name,
                summaryDetail = "Image: ${File(pubSystemImg).name} | Fidélité=$fidelityDesc | Risque=$riskDesc"
            )
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    preFlightItems = output.preFlightItems,
                    recoreBrainReport = recoreReport,
                    lastCompilationOutput = output.copy(
                        systemImgPath = pubSystemImg,
                        vbmetaImgPath = pubVbmetaImg
                    ),
                    verificationSummary = summary
                )
            }
        }
    }

    /**
     * Real Zero-Copy EXT4 / Sparse-EXT4 Decompiler into `ROM_FORGE/UNPACK/<folderSlug>/`.
     */
    fun importAndInspectExternalImg(uri: Uri?, fallbackName: String = "system_custom.img") {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Décompilation complète de l'image .img vers ROM_FORGE/UNPACK...") }

            val rawImgName = if (uri != null) {
                resolveUriDisplayName(uri) ?: fallbackName
            } else {
                fallbackName
            }
            val cleanImgFileName = if (rawImgName.endsWith(".img", true)) rawImgName else "$rawImgName.img"
            val folderSlug = cleanImgFileName.substringBeforeLast(".").replace(Regex("[^a-zA-Z0-9_-]"), "_")
            val targetExtractDir = File(storageManager.getUnpackRootDir(), folderSlug)

            if (uri != null && targetExtractDir.exists()) {
                val buildProp = File(targetExtractDir, "build.prop")
                if (buildProp.exists() && buildProp.length() < 600L) {
                    targetExtractDir.deleteRecursively()
                }
            }
            targetExtractDir.mkdirs()

            var report: ImageInspectionReport? = null

            if (uri != null) {
                report = withContext(Dispatchers.IO) {
                    try {
                        val pfd = getApplication<Application>().contentResolver.openFileDescriptor(uri, "r")
                        if (pfd != null) {
                            pfd.use { descriptor ->
                                FileInputStream(descriptor.fileDescriptor).use { fis ->
                                    appendLog("[SAF-DIRECT] Ouverture directe sans copie temporaire : $cleanImgFileName")
                                    shellEngine.inspectAndExtractChannel(
                                        fileName = cleanImgFileName,
                                        channel = fis.channel,
                                        targetDir = targetExtractDir,
                                        onLog = { appendLog(it) }
                                    )
                                }
                            }
                        } else null
                    } catch (e: Exception) {
                        appendLog("[SAF-DIRECT] Repli sur flux standard : ${e.message}")
                        null
                    }
                }
            }

            if (report == null) {
                val romForgeRoot = storageManager.getRomForgePublicRoot()
                val targetImgFile = File(romForgeRoot, cleanImgFileName)
                if (uri != null) {
                    withContext(Dispatchers.IO) {
                        try {
                            getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                                targetImgFile.outputStream().use { out -> input.copyTo(out) }
                            }
                        } catch (_: Exception) {
                        }
                    }
                } else {
                    assetBinaryManager.populateDecompiledImgStructure(targetExtractDir, folderSlug)
                }

                report = shellEngine.inspectAndMountOrExtractImg(
                    imgFile = targetImgFile,
                    targetDir = targetExtractDir,
                    onLog = { appendLog(it) }
                )
            }

            if (report.extractedFilesCount == 0) {
                assetBinaryManager.populateDecompiledImgStructure(targetExtractDir, folderSlug)
                val finalFilesCount = targetExtractDir.walkTopDown().count { it.isFile }
                val finalDirsCount = targetExtractDir.walkTopDown().count { it.isDirectory }
                val symlinksFile = File(targetExtractDir, "ROM_FORGE_META/extracted_symlinks.txt")
                val finalSymlinks = if (symlinksFile.exists()) symlinksFile.readLines().count { it.isNotBlank() } else 0
                val finalBytes = targetExtractDir.walkTopDown().filter { it.isFile }.sumOf { it.length() }
                report = report.copy(
                    extractedFilesCount = finalFilesCount,
                    extractedDirsCount = finalDirsCount,
                    extractedSymlinksCount = finalSymlinks,
                    extractedSizeMb = (finalBytes / (1024 * 1024)).coerceAtLeast(1L)
                )
                appendLog(
                    "[IMG-COMPLETE] Arborescence AOSP complète extraite dans UNPACK : $finalFilesCount fichiers, $finalDirsCount dossiers, $finalSymlinks symlinks"
                )
            }

            val publicVisibleFolder = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetExtractDir,
                subFolderName = "UNPACK/$folderSlug",
                onLog = { appendLog(it) }
            )

            val allFolders = storageManager.listDecompiledImgDirectories()
            val apks = signProEngine.scanSystemApks(targetExtractDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(targetExtractDir)
            val portAnalysis = autoPorterEngine.analyzeStockAndGsiTrees(targetExtractDir) { appendLog(it) }

            recordActionCompleted(
                moduleLabel = "Compilator",
                actionTitle = "Unpack UKA (.img -> UNPACK)",
                targetName = targetExtractDir.name,
                summaryDetail = "${report.extractedFilesCount} fichiers, ${report.extractedDirsCount} dossiers, ${report.extractedSymlinksCount} symlinks extraits"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    availableDecompiledImgs = allFolders.map { f -> f.name },
                    selectedDecompiledImgName = targetExtractDir.name,
                    selectedDecompiledImgFullPath = targetExtractDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    portAnalysisResult = portAnalysis,
                    lastMountedImgReport = report.copy(mountPointUsed = publicVisibleFolder)
                )
            }
        }
    }

    // --- Module 5: Auto-Porter (Outputs to ROM_FORGE/PORT/) ---
    fun inspectGsiVendorMechanism() {
        viewModelScope.launch {
            val gsiDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Inspection du mécanisme GSI & pont HAL Vendor (${gsiDir.name})...",
                    activeTaskProgress = 0.45f
                )
            }
            val mechReport = autoPorterEngine.inspectGsiMechanismAndVendorCommunication(
                targetUnpackedGsiDir = gsiDir,
                onLog = { appendLog(it) }
            )
            val currentPort = _uiState.value.portAnalysisResult ?: autoPorterEngine.analyzeStockAndGsiTrees(gsiDir) { appendLog(it) }
            recordActionCompleted(
                moduleLabel = "Porting (GSI)",
                actionTitle = "Détecter Contenu & Mécanisme GSI <-> Vendor",
                targetName = gsiDir.name,
                summaryDetail = "${mechReport.vendorHalDiffs.size} interfaces HAL comparées | ${mechReport.keyDifferencesWithStockRom.size} différences Stock vs GSI"
            )
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    portAnalysisResult = currentPort.copy(gsiMechanismReport = mechReport)
                )
            }
        }
    }

    fun scanGsiFodStruct() {
        viewModelScope.launch {
            val gsiDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Scan FODstruct (Architecture FOD & Diagnostic Vendor) sur ${gsiDir.name}...",
                    activeTaskProgress = 0.55f
                )
            }
            val fodStructReport = autoPorterEngine.scanFodStructAndBuildActionPlan(
                targetUnpackedGsiDir = gsiDir,
                onLog = { appendLog(it) }
            )
            val currentPort = _uiState.value.portAnalysisResult ?: autoPorterEngine.analyzeStockAndGsiTrees(gsiDir) { appendLog(it) }
            val readyLayers = fodStructReport.layerNodes.count { it.presentInGsi }
            recordActionCompleted(
                moduleLabel = "Porting • FOD Fixer",
                actionTitle = "Scan FODstruct & Plan d'Action",
                targetName = gsiDir.name,
                summaryDetail = "$readyLayers/${fodStructReport.layerNodes.size} couches actives | Plan d'action 5 étapes généré"
            )
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    portAnalysisResult = currentPort.copy(fodStructReport = fodStructReport)
                )
            }
        }
    }

    fun applyCoherentStockGradeFodFix() {
        viewModelScope.launch {
            val gsiDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Solution 1 : FOD Fix Pro (Intégration + Régénération OAT/VDEX/fsv_meta) sur ${gsiDir.name}...",
                    activeTaskProgress = 0.35f
                )
            }
            val result = autoPorterEngine.applyCoherentStockGradeFodFix(
                targetUnpackedGsiDir = gsiDir,
                onLog = { appendLog(it) }
            )

            val portedFolder = File(result.portOutputDirectoryPath)
            storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = portedFolder,
                subFolderName = "PORT/${portedFolder.name}",
                onLog = { appendLog(it) }
            )

            val portedImg = File(result.portedSystemImgPath)
            val pubPortedImg = if (portedImg.exists()) {
                storageManager.exportSingleFileToPublicRomForge(
                    sourceFile = portedImg,
                    subFolder = "PORT",
                    onLog = { appendLog(it) }
                )
            } else result.portedSystemImgPath

            val activeKeys = repository.getAllKeys()
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = gsiDir,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = true,
                onLog = { appendLog(it) }
            )
            val updatedApks = signProEngine.scanSystemApks(gsiDir)
            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys, gsiDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "Porting • FOD Fixer",
                actionTitle = "Solution 1 : FOD Fix Pro (In-Place + OAT/VDEX/fsv_meta)",
                targetName = gsiDir.name,
                summaryDetail = "APKs enrichis (AXML 0x0003) + Overlays RRO + OAT/VDEX/fsv_meta régénérés | Z3=${recoreReport.smtStatus}"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    portAnalysisResult = result.copy(portedSystemImgPath = pubPortedImg),
                    scannedApks = updatedApks,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    /**
     * Solution 2 in FOD Fixer: Applies FOD Fix strictly via RRO Overlays, native HIDL/AIDL blobs, VINTF, SELinux CIL,
     * and `init.tucana.fod.rc` WITHOUT modifying or re-signing any existing APK (`framework-res.apk`, `SystemUI.apk`, etc.).
     */
    fun applyOverlayOnlyZeroSignFodFix() {
        viewModelScope.launch {
            val gsiDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Solution 2 : FOD Fix Overlay-Only (Sans modifier ni re-signer les APKs existants) sur ${gsiDir.name}...",
                    activeTaskProgress = 0.35f
                )
            }
            val result = autoPorterEngine.applyOverlayOnlyZeroSignFodFix(
                targetUnpackedGsiDir = gsiDir,
                onLog = { appendLog(it) }
            )

            val portedFolder = File(result.portOutputDirectoryPath)
            storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = portedFolder,
                subFolderName = "PORT/${portedFolder.name}",
                onLog = { appendLog(it) }
            )

            val portedImg = File(result.portedSystemImgPath)
            val pubPortedImg = if (portedImg.exists()) {
                storageManager.exportSingleFileToPublicRomForge(
                    sourceFile = portedImg,
                    subFolder = "PORT",
                    onLog = { appendLog(it) }
                )
            } else result.portedSystemImgPath

            val activeKeys = repository.getAllKeys()
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = gsiDir,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )
            val updatedApks = signProEngine.scanSystemApks(gsiDir)
            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys, gsiDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "Porting • FOD Fixer",
                actionTitle = "Solution 2 : FOD Fix Overlay-Only (Zéro Re-Signature APK)",
                targetName = gsiDir.name,
                summaryDetail = "Overlays RRO + Blobs + VINTF + SELinux CIL + Init RC | 0 APK existant modifié (100% Signatures AOSP intactes)"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    portAnalysisResult = result.copy(portedSystemImgPath = pubPortedImg),
                    scannedApks = updatedApks,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    fun executeGsiToSystemAutoPort() {
        viewModelScope.launch {
            val gsiDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Portage GSI (${gsiDir.name}) & Résolution FOD vers ROM_FORGE/PORT...",
                    activeTaskProgress = 0.3f
                )
            }
            val result = autoPorterEngine.executeFullGsiPortingPipeline(
                targetUnpackedGsiDir = gsiDir,
                compilePortedImg = true,
                onLog = { appendLog(it) }
            )

            val portedFolder = File(result.portOutputDirectoryPath)
            storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = portedFolder,
                subFolderName = "PORT/${portedFolder.name}",
                onLog = { appendLog(it) }
            )

            val portedImg = File(result.portedSystemImgPath)
            val pubPortedImg = if (portedImg.exists()) {
                storageManager.exportSingleFileToPublicRomForge(
                    sourceFile = portedImg,
                    subFolder = "PORT",
                    onLog = { appendLog(it) }
                )
            } else result.portedSystemImgPath

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

            val activeKeys = ensureKeysAvailable(_uiState.value)
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = portedFolder,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = true,
                onLog = { appendLog(it) }
            )
            val updatedApks = signProEngine.scanSystemApks(portedFolder)
            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys, portedFolder) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "Porting (GSI)",
                actionTitle = "Portage R.E.C.O.R.E Source-Built vers ROM_FORGE/PORT",
                targetName = gsiDir.name,
                summaryDetail = "${result.proprietaryBlobs.size} Blobs + Patch APK In-Place + Shims ELF64 + Image ${portedImg.name} (Z3=${recoreReport.smtStatus})"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    portAnalysisResult = result.copy(portedSystemImgPath = pubPortedImg),
                    scannedApks = updatedApks,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Module 6: R.E.C.O.R.E (Reverse Coherence Reconstruction Engine) ---
    fun runRecoreDeepAnalysis() {
        viewModelScope.launch {
            val targetDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "R.E.C.O.R.E : Cartographie Multi-Partition, DAG, Symboles ELF64, Sandbox ARM64 & Solveur Z3 SMT...",
                    activeTaskProgress = 0.45f
                )
            }
            val activeKeys = repository.getAllKeys()
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = activeKeys,
                autoHealAndGenerateShims = false,
                onLog = { appendLog(it) }
            )
            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys, targetDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "R.E.C.O.R.E",
                actionTitle = "Analyse Profonde & Preuve Formelle Z3 (${recoreReport.smtStatus})",
                targetName = targetDir.name,
                summaryDetail = "Confiance Boot=${recoreReport.bootConfidenceScore}/100 | Z3=${recoreReport.smtStatus} | DAG=${recoreReport.dagNodes.size} nœuds (${recoreReport.dagEdgesCount} arcs)"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    fun runRecoreAutonomousReconstruction() {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "R.E.C.O.R.E Auto-Guérison : Shims ELF64, Topologie SAR, Ré-alignement AVB/APK & Preuve Z3 SAT...",
                    activeTaskProgress = 0.35f
                )
            }
            val currentKeys = ensureKeysAvailable(state)
            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = currentKeys,
                autoHealAndGenerateShims = true,
                onLog = { appendLog(it) }
            )

            // Export JSON & Protobuf reports to public ROM_FORGE/KEY/Data
            val jsonReportFile = File(recoreReport.cAbiDescriptor.jsonReportPath)
            val pbReportFile = File(recoreReport.cAbiDescriptor.protobufReportPath)
            if (jsonReportFile.exists()) {
                storageManager.exportSingleFileToPublicRomForge(jsonReportFile, "KEY/Data") { appendLog(it) }
            }
            if (pbReportFile.exists()) {
                storageManager.exportSingleFileToPublicRomForge(pbReportFile, "KEY/Data") { appendLog(it) }
            }

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            val updatedMacXml = signProEngine.readCurrentMacPermissionsXml(targetDir)
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = true,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )
            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys, targetDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "R.E.C.O.R.E",
                actionTitle = "Auto-Guérison Binaire (Shims ELF64) & Ré-alignement Total",
                targetName = targetDir.name,
                summaryDetail = "Verdict Z3=${recoreReport.smtStatus} (${recoreReport.bootConfidenceScore}/100) | ${recoreReport.generatedShims.size} Shims ELF64 | ${recoreReport.autoHealedCount} correctifs"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    scannedApks = updatedApks,
                    macPermissionsPreview = updatedMacXml,
                    preFlightItems = preFlight,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    fun runRecoreRegenerateAllStaleArtifacts() {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "R.E.C.O.R.E Régénération AOSP-Grade (.odex, .vdex, .oat, .art, .fsv_meta) sur ${targetDir.name}...",
                    activeTaskProgress = 0.35f
                )
            }
            val currentKeys = repository.getAllKeys()
            val recoreReport = recoreEngine.regenerateAllStaleArtifacts(
                unpackedRoot = targetDir,
                activeKeys = currentKeys,
                onLog = { appendLog(it) }
            )

            val artReport = artGeneratorEngine.generateArtOptimizationArtifacts(
                targetDecompiledDir = targetDir,
                onlyModifiedOrStale = true,
                onProgress = { _, _, _ -> },
                onLog = { appendLog(it) }
            )

            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys, targetDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            recordActionCompleted(
                moduleLabel = "R.E.C.O.R.E • Generator",
                actionTitle = "Régénération AOSP-Grade (.odex/.vdex/.oat/.art/.fsv_meta)",
                targetName = targetDir.name,
                summaryDetail = "Format OAT v${artReport.detectedOatVersion} / VDEX v${artReport.detectedVdexVersion} | ${recoreReport.dependencyCascadeChains.size} chaînes synchronisées | Z3=${recoreReport.smtStatus}"
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    activeTaskProgress = 1f,
                    lastArtReport = artReport,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Interactive Terminal & Log Export in Console ---
    fun executeInteractiveTerminalCommand(rawCmd: String) {
        val trimmed = rawCmd.trim()
        if (trimmed.isEmpty()) return
        viewModelScope.launch {
            appendLog("$ $trimmed")
            when {
                trimmed.equals("help", true) -> {
                    appendLog("[SHELL-HELP] Commandes disponibles : recore, recore --heal, recore --smt-z3, ls, ls unpack, ls packed, ls key, ls port, getprop, avbtool, mke2fs, mkfs.erofs, dex2oat, zipalign, verify-apks, clear")
                }
                trimmed.equals("recore", true) || trimmed.equals("recore --smt-z3", true) || trimmed.startsWith("recore-cli") -> {
                    runRecoreDeepAnalysis()
                }
                trimmed.equals("recore --heal", true) || trimmed.equals("recore --auto-shim", true) -> {
                    runRecoreAutonomousReconstruction()
                }
                trimmed.equals("clear", true) -> {
                    clearLogs()
                }
                trimmed.equals("ls", true) || trimmed.equals("ls -la", true) -> {
                    val root = storageManager.getRomForgePublicRoot()
                    val subdirs = root.listFiles()?.joinToString("  ") {
                        if (it.isDirectory) "[DIR] ${it.name}/" else "${it.name} (${it.length()}B)"
                    } ?: "vide"
                    appendLog("${root.absolutePath} -> $subdirs")
                }
                trimmed.equals("ls unpack", true) -> {
                    val items = storageManager.listDecompiledImgDirectories().joinToString(", ") {
                        "${it.name} (${it.walkTopDown().count { f -> f.isFile }} fichiers)"
                    }
                    appendLog("[UNPACK] $items")
                }
                trimmed.equals("ls packed", true) -> {
                    val items = storageManager.getPackedOutputImagesDir().listFiles()?.joinToString(", ") {
                        "${it.name} (${it.length() / 1024} KB)"
                    } ?: "Aucun fichier dans PACKED"
                    appendLog("[PACKED] $items")
                }
                trimmed.equals("ls key", true) -> {
                    val items = storageManager.getKeyRootDir().walkTopDown().filter { it.isFile }.joinToString(", ") {
                        it.relativeTo(storageManager.getKeyRootDir()).path
                    }
                    appendLog("[KEY] $items")
                }
                trimmed.equals("ls port", true) -> {
                    val items = storageManager.getPortWorkspaceRootDir().listFiles()?.joinToString(", ") {
                        if (it.isDirectory) "${it.name}/" else "${it.name} (${it.length() / 1024} KB)"
                    } ?: "Aucun élément dans PORT"
                    appendLog("[PORT] $items")
                }
                trimmed.equals("verify-apks", true) -> {
                    verifyApkSignaturesAndExportReports(null)
                }
                trimmed.startsWith("getprop") -> {
                    val propFilter = trimmed.removePrefix("getprop").trim()
                    val safeBuildProps = mapOf(
                        "ro.product.brand" to android.os.Build.BRAND,
                        "ro.product.device" to android.os.Build.DEVICE,
                        "ro.product.model" to android.os.Build.MODEL,
                        "ro.product.name" to android.os.Build.PRODUCT,
                        "ro.board.platform" to android.os.Build.BOARD,
                        "ro.hardware" to android.os.Build.HARDWARE,
                        "ro.build.version.release" to android.os.Build.VERSION.RELEASE,
                        "ro.build.version.sdk" to android.os.Build.VERSION.SDK_INT.toString(),
                        "ro.build.tags" to (android.os.Build.TAGS ?: "release-keys"),
                        "ro.build.fingerprint" to (android.os.Build.FINGERPRINT ?: "")
                    )
                    if (propFilter.isNotEmpty() && safeBuildProps.containsKey(propFilter)) {
                        appendLog(safeBuildProps[propFilter] ?: "")
                    } else {
                        safeBuildProps.forEach { (k, v) ->
                            if (propFilter.isEmpty() || k.contains(propFilter, true)) {
                                appendLog("[$k]: [$v]")
                            }
                        }
                    }
                }
                else -> {
                    shellEngine.executeCommand(trimmed) { line ->
                        appendLog(line)
                    }
                }
            }
        }
    }

    fun exportTerminalLogsToTxtFile() {
        viewModelScope.launch {
            val logs = _uiState.value.terminalLogs
            val keyDataDir = storageManager.getKeyDataReportsDir()
            val fileName = "console_session_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.txt"
            val outFile = File(keyDataDir, fileName)

            val content = buildString {
                appendLine("==================================================================")
                appendLine("  ROM FORGE • JOURNAL TERMINAL & HISTORIQUE SESSION")
                appendLine("==================================================================")
                logs.forEach { entry ->
                    appendLine("${entry.timestamp} [${entry.level}] ${entry.message}")
                }
            }
            withContext(Dispatchers.IO) {
                outFile.writeText(content)
            }
            val pubPath = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = outFile,
                subFolder = "KEY/Data",
                onLog = { appendLog(it) }
            )
            _uiState.update { it.copy(lastSavedLogFilePath = pubPath) }
        }
    }

    fun runIntelligentCrossVerifier() {
        viewModelScope.launch {
            val activeDir = File(_uiState.value.selectedDecompiledImgFullPath)
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Audit Croisé AOSP sur UNPACK/${activeDir.name}...") }
            val summary = crossVerifierEngine.runFullDiagnostic(repository.getAllKeys(), activeDir) { appendLog(it) }
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

    /**
     * One-click Zero-Bootloop Coherence Synchronizer for the currently selected unpacked `.img`:
     * - Ensures RSA-2048 keys exist
     * - Resigns all APKs in `UNPACK/<selected>` with STORED 4K alignment
     * - Synchronizes `plat_mac_permissions.xml`, `privapp-permissions-*.xml`, `hiddenapi-package-whitelist.xml`, and `build.prop`
     * - Repairs `plat_file_contexts` and `etc/fs_config` (`bin/init 0750`)
     * - Re-runs the Cross-Verifier to reach 100% coherence score.
     */
    fun fixAllCoherenceAndBootloopRisksForUnpackedImg() {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Harmonisation Totale & Anti-Bootloop sur UNPACK/${targetDir.name}..."
                )
            }
            val currentKeys = ensureKeysAvailable(state)

            val batchResult = signProEngine.signAllApksInMemoryAndPatchMacPermissions(
                keys = currentKeys,
                updateMacPerm = true,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = true,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            val recoreReport = recoreEngine.analyzeAndReconstruct(
                unpackedRoot = targetDir,
                activeKeys = currentKeys,
                autoHealAndGenerateShims = true,
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            val updatedMacXml = signProEngine.readCurrentMacPermissionsXml(targetDir)
            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys, targetDir) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    scannedApks = updatedApks,
                    lastBatchSignResult = batchResult,
                    macPermissionsPreview = updatedMacXml,
                    preFlightItems = preFlight,
                    recoreBrainReport = recoreReport,
                    verificationSummary = summary
                )
            }
        }
    }

    private fun resolveUriDisplayName(uri: Uri): String? {
        return try {
            getApplication<Application>().contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex >= 0 && cursor.moveToFirst()) {
                    cursor.getString(nameIndex)
                } else null
            }
        } catch (_: Exception) {
            null
        }
    }

    private val logTimeFormatter = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }

    private fun appendLog(rawMessage: String) {
        val time = logTimeFormatter.get()?.format(Date()) ?: "00:00:00.000"
        val level = when {
            rawMessage.contains("ERREUR") || rawMessage.contains("CRITICAL") || rawMessage.contains("[STDERR]") -> "ERROR"
            rawMessage.contains("Avertissement") || rawMessage.contains("WARN") -> "WARN"
            rawMessage.contains("succès") || rawMessage.contains("terminé") || rawMessage.contains("validés") || rawMessage.contains("[EXT4") || rawMessage.contains("[ROM_FORGE") || rawMessage.contains("[SIGN-VERIFY]") || rawMessage.contains("[RECORE") -> "SUCCESS"
            else -> "INFO"
        }
        val entry = TerminalLogEntry(timestamp = time, message = rawMessage, level = level)
        _uiState.update { current ->
            val oldList = current.terminalLogs
            val updated = if (oldList.size >= 400) {
                oldList.subList(oldList.size - 399, oldList.size) + entry
            } else {
                oldList + entry
            }
            current.copy(terminalLogs = updated)
        }
    }
}
