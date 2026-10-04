package com.example.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.core.assets.AssetBinaryManager
import com.example.core.assets.ExtractedBinary
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

enum class SignProInputMode(val label: String) {
    DECOMPILED_IMG_FOLDER("IMG Décompilé (Tous les APKs)"),
    SINGLE_STANDALONE_APK("APK Individuel (.apk)")
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
    // Public ROM_FORGE Storage status
    val romForgePublicPath: String = "/storage/emulated/0/ROM_FORGE",
    val hasAllFilesAccess: Boolean = false,
    val availableDecompiledImgs: List<String> = listOf("system_ext4"),
    val selectedDecompiledImgName: String = "system_ext4",
    val selectedDecompiledImgFullPath: String = "/storage/emulated/0/ROM_FORGE/decompiled_imgs/system_ext4",
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

    private val storageManager = RomForgeStorageManager(application)
    private val assetBinaryManager = AssetBinaryManager(application, storageManager)
    private val shellEngine = HybridShellEngine(
        binDir = assetBinaryManager.getBinDir(),
        workspaceDir = assetBinaryManager.getWorkspaceDir()
    )
    private val keyMakerEngine = KeyMakerEngine(storageManager.getKeystorePublicDir().parentFile ?: application.filesDir)
    private val signProEngine = SignProEngine(assetBinaryManager.getWorkspaceDir(), keyMakerEngine)
    private val artGeneratorEngine = ArtGeneratorEngine(
        defaultWorkspaceDir = assetBinaryManager.getWorkspaceDir(),
        binDir = assetBinaryManager.getBinDir(),
        shellEngine = shellEngine,
        repository = repository
    )
    private val imgCompilerEngine = ImgCompilerEngine(
        defaultWorkspaceDir = assetBinaryManager.getWorkspaceDir(),
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

    fun refreshStorageStatusAndFolders() {
        viewModelScope.launch {
            val status = storageManager.getStorageStatus()
            val folders = storageManager.listDecompiledImgDirectories()
            val currentName = _uiState.value.selectedDecompiledImgName
            val activeDir = folders.find { it.name == currentName } ?: folders.first()
            val apks = signProEngine.scanSystemApks(activeDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(activeDir)

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
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Initialisation du dossier public ROM_FORGE & binaires ARM64...") }
            val binaries = assetBinaryManager.extractAndVerifyBinaries { appendLog(it) }
            val rootDetected = shellEngine.probeRootAccess()
            val mode = if (rootDetected) ExecutionMode.ROOT_LOOPBACK else ExecutionMode.NON_ROOT_USERSPACE
            shellEngine.setExecutionMode(mode)

            val status = storageManager.getStorageStatus()
            val folders = storageManager.listDecompiledImgDirectories()
            val activeDir = folders.first()

            val apks = signProEngine.scanSystemApks(activeDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(activeDir)
            val cleJson = keyMakerEngine.readCleNoteManifestJson()
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = false,
                targetDecompiledDir = activeDir
            ) { appendLog(it) }
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
        appendLog("[MODE-SWITCH] Basculement vers ${mode.name} (Dossier actif : ${_uiState.value.romForgePublicPath})")
        _uiState.update { it.copy(executionMode = mode) }
    }

    /**
     * Allows user to switch the active decompiled .img folder across Sign Pro, Generator, and Compiler.
     */
    fun selectDecompiledImgFolder(folderName: String) {
        viewModelScope.launch {
            val targetDir = File(storageManager.getExtractedImagesRoot(), folderName)
            assetBinaryManager.populateDecompiledImgStructure(targetDir, folderName)
            val apks = signProEngine.scanSystemApks(targetDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(targetDir)
            val preFlight = imgCompilerEngine.runPreFlightStaticAudit(
                autoRepairBootloopRisks = false,
                targetDecompiledDir = targetDir
            ) { appendLog(it) }

            appendLog("[IMG-TARGET] Image décompilée sélectionnée : ${targetDir.absolutePath} (${apks.size} APKs)")
            _uiState.update {
                it.copy(
                    selectedDecompiledImgName = targetDir.name,
                    selectedDecompiledImgFullPath = targetDir.absolutePath,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    preFlightItems = preFlight
                )
            }
        }
    }

    /**
     * Allows user to pick any external decompiled .img directory via SAF DocumentTree picker (`OpenDocumentTree`).
     */
    fun selectCustomDecompiledDirectoryUri(treeUri: Uri?) {
        if (treeUri == null) return
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Liaison du dossier IMG décompilé...") }
            storageManager.saveCustomSafTreeUri(treeUri)
            val resolvedDir = storageManager.resolveOrImportSafDirectory(
                treeUri = treeUri,
                fallbackFolderName = "custom_img_${System.currentTimeMillis() % 10000}",
                onLog = { appendLog(it) }
            )
            assetBinaryManager.populateDecompiledImgStructure(resolvedDir, resolvedDir.name)
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
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Génération RSA-2048 dans ROM_FORGE/keystore_aosp...") }
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
                subFolderName = "keystore_aosp",
                onLog = { appendLog(it) }
            )

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

    // --- Module 2: Sign Pro (Both Decompiled IMG Folder & Single APK Mode) ---
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
                appendLog("[SIGN-PRO-APK] APK sélectionné depuis ROM_FORGE : ${targetInputApk.absolutePath}")
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

    fun signSingleSelectedApk() {
        viewModelScope.launch {
            val state = _uiState.value
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Resignature In-Memory de l'APK individuel...") }

            var currentKeys = repository.getAllKeys()
            if (currentKeys.isEmpty()) {
                currentKeys = keyMakerEngine.generateFullKeySuite(
                    organization = state.keyOrg,
                    commonName = state.keyCommonName,
                    countryCode = state.keyCountry,
                    validityYears = 25,
                    onLog = { appendLog(it) }
                )
                currentKeys.forEach { repository.saveKey(it) }
            }

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
                subFolder = "signed_apks",
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

    fun signAllSystemApksInMemory(injectMacPermissions: Boolean = true) {
        viewModelScope.launch {
            val state = _uiState.value
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Signature In-Memory de tous les APKs dans ${targetDir.name}..."
                )
            }
            var currentKeys = repository.getAllKeys()
            if (currentKeys.isEmpty()) {
                appendLog("[SIGN-PRO] Aucune clé détectée -> Auto-génération préalable de la chaîne RSA-2048...")
                currentKeys = keyMakerEngine.generateFullKeySuite(
                    organization = state.keyOrg,
                    commonName = state.keyCommonName,
                    countryCode = state.keyCountry,
                    validityYears = 25,
                    onLog = { appendLog(it) }
                )
                currentKeys.forEach { repository.saveKey(it) }
            }

            val batchResult = signProEngine.signAllApksInMemoryAndPatchMacPermissions(
                keys = currentKeys,
                updateMacPerm = injectMacPermissions,
                targetDecompiledDir = targetDir,
                onLog = { appendLog(it) }
            )

            val publicMirroredPath = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetDir,
                subFolderName = "decompiled_imgs/${targetDir.name}",
                onLog = { appendLog(it) }
            )

            val updatedApks = signProEngine.scanSystemApks(targetDir)
            val updatedMacXml = signProEngine.readCurrentMacPermissionsXml(targetDir)
            val summary = crossVerifierEngine.runFullDiagnostic(currentKeys) { appendLog(it) }
            repository.clearAlerts()
            summary.alerts.forEach { repository.addAlert(it) }

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    scannedApks = updatedApks,
                    lastBatchSignResult = batchResult.copy(outputDirectoryPath = publicMirroredPath),
                    macPermissionsPreview = updatedMacXml,
                    cleNoteJsonPreview = keyMakerEngine.readCleNoteManifestJson(),
                    verificationSummary = summary
                )
            }
        }
    }

    // --- Module 3: Generator (ART Cache & Security on Selected Decompiled IMG) ---
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
                    activeTaskTitle = "Compilation ART dex2oat (.odex/.vdex) sur ${targetDir.name}..."
                )
            }
            val currentKeys = repository.getAllKeys()
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
                subFolderName = "decompiled_imgs/${targetDir.name}",
                onLog = { appendLog(it) }
            )

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
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

    // --- Module 4: Compilation & Decompilation into ROM_FORGE ---
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
            val targetDir = File(state.selectedDecompiledImgFullPath)
            _uiState.update {
                it.copy(
                    isBusy = true,
                    activeTaskTitle = "Construction ${state.selectedFsFormat.name} depuis ${targetDir.name} -> ROM_FORGE/compiled_imgs..."
                )
            }
            val activeKeys = repository.getAllKeys()
            val output = imgCompilerEngine.compileSystemAndVbmetaImages(
                format = state.selectedFsFormat,
                enableDmVerity = state.enableDmVerity,
                disableVerityFlagsInVbmeta = state.disableVerityFlagsInVbmeta,
                activeKeys = activeKeys,
                targetDecompiledDir = targetDir,
                outputImagesDir = storageManager.getCompiledOutputImagesDir(),
                onLog = { appendLog(it) }
            )

            val pubSystemImg = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(output.systemImgPath),
                subFolder = "compiled_imgs",
                onLog = { appendLog(it) }
            )
            val pubVbmetaImg = storageManager.exportSingleFileToPublicRomForge(
                sourceFile = File(output.vbmetaImgPath),
                subFolder = "compiled_imgs",
                onLog = { appendLog(it) }
            )

            val summary = crossVerifierEngine.runFullDiagnostic(activeKeys) { appendLog(it) }
            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    preFlightItems = output.preFlightItems,
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
     * Decompiles / extracts an `.img` file directly into `/storage/emulated/0/ROM_FORGE/decompiled_imgs/<img_name>/`
     * (and mirrors to `/storage/emulated/0/Download/ROM_FORGE/decompiled_imgs/<img_name>/` in Non-Root mode without permissions),
     * then automatically sets it as the active decompiled image for Sign Pro, Generator, and Compiler!
     */
    fun importAndInspectExternalImg(uri: Uri?, fallbackName: String = "system_custom.img") {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Décompilation .img vers le stockage public ROM_FORGE...") }

            val rawImgName = if (uri != null) {
                resolveUriDisplayName(uri) ?: fallbackName
            } else {
                fallbackName
            }
            val cleanImgFileName = if (rawImgName.endsWith(".img", true)) rawImgName else "$rawImgName.img"
            val folderSlug = cleanImgFileName.substringBeforeLast(".").replace(Regex("[^a-zA-Z0-9_-]"), "_")

            val romForgeRoot = storageManager.getRomForgePublicRoot()
            val targetImgFile = File(romForgeRoot, cleanImgFileName)
            val targetExtractDir = File(storageManager.getExtractedImagesRoot(), folderSlug).apply { mkdirs() }

            if (uri != null) {
                withContext(Dispatchers.IO) {
                    try {
                        getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
                            targetImgFile.outputStream().use { out ->
                                input.copyTo(out)
                            }
                        }
                        appendLog("[SAF-IMPORT] Image copiée dans : ${targetImgFile.absolutePath} (${targetImgFile.length() / 1024} KB)")
                    } catch (e: Exception) {
                        appendLog("[SAF-IMPORT] Avertissement lecture URI : ${e.message}")
                    }
                }
            }

            // Populate extracted filesystem structure inside ROM_FORGE/decompiled_imgs/<folderSlug>
            assetBinaryManager.populateDecompiledImgStructure(targetExtractDir, folderSlug)

            val report = shellEngine.inspectAndMountOrExtractImg(
                imgFile = targetImgFile,
                targetDir = targetExtractDir,
                onLog = { appendLog(it) }
            )

            // Guarantee Non-Root visibility in /storage/emulated/0/ROM_FORGE or /storage/emulated/0/Download/ROM_FORGE
            val publicVisibleFolder = storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetExtractDir,
                subFolderName = "decompiled_imgs/$folderSlug",
                onLog = { appendLog(it) }
            )

            val allFolders = storageManager.listDecompiledImgDirectories()
            val apks = signProEngine.scanSystemApks(targetExtractDir)
            val macXml = signProEngine.readCurrentMacPermissionsXml(targetExtractDir)

            _uiState.update {
                it.copy(
                    isBusy = false,
                    activeTaskTitle = "",
                    availableDecompiledImgs = allFolders.map { f -> f.name },
                    selectedDecompiledImgName = targetExtractDir.name,
                    selectedDecompiledImgFullPath = publicVisibleFolder,
                    scannedApks = apks,
                    macPermissionsPreview = macXml,
                    lastMountedImgReport = report.copy(mountPointUsed = publicVisibleFolder)
                )
            }
        }
    }

    // --- Module 5: Auto-Porter (GSI to System) ---
    fun executeGsiToSystemAutoPort() {
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, activeTaskTitle = "Portage GSI -> System dans ROM_FORGE...") }
            val result = autoPorterEngine.executeFullGsiPortingPipeline { appendLog(it) }

            val targetDir = File(_uiState.value.selectedDecompiledImgFullPath)
            storageManager.mirrorDirectoryToPublicDownloadRomForge(
                sourceDir = targetDir,
                subFolderName = "decompiled_imgs/${targetDir.name}",
                onLog = { appendLog(it) }
            )

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

            val updatedApks = signProEngine.scanSystemApks(targetDir)
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

    private fun appendLog(rawMessage: String) {
        val time = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        val level = when {
            rawMessage.contains("ERREUR") || rawMessage.contains("CRITICAL") || rawMessage.contains("[STDERR]") -> "ERROR"
            rawMessage.contains("Avertissement") || rawMessage.contains("WARN") -> "WARN"
            rawMessage.contains("succès") || rawMessage.contains("terminé") || rawMessage.contains("validés") || rawMessage.contains("[BYPASS-NON-ROOT]") || rawMessage.contains("[ROM_FORGE") -> "SUCCESS"
            else -> "INFO"
        }
        val entry = TerminalLogEntry(timestamp = time, message = rawMessage, level = level)
        _uiState.update { current ->
            val updated = (current.terminalLogs + entry).takeLast(250)
            current.copy(terminalLogs = updated)
        }
    }
}
