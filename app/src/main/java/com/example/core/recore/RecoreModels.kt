package com.example.core.recore

/**
 * Data Models for **R.E.C.O.R.E — Reverse Coherence Reconstruction Engine** (`librecore_ffi`).
 *
 * Implements the 15 functional pillars of the R.E.C.O.R.E brain:
 * 1. Multi-Partition Analysis & Mapping (`system`, `vendor`, `product`, `system_ext`, `apex`, `boot`, `odm`)
 * 2. Multi-Layer Dependency Graph (`DAG`) across files, ELF libraries, init processes, and SELinux domains
 * 3. ELF Symbol & `DT_NEEDED` Inspector (`.so`, executables, C/C++ import/export tables)
 * 4. `init.rc` Boot Sequence Parser & Trigger Simulator (`early-init`, `init`, `late-fs`, `post-fs-data`, `boot`)
 * 5. Project Treble / HAL & VINTF Matrix Compatibility Auditor (HIDL `hwbinder` / AIDL `binder`)
 * 6. SELinux Security Modeler (`file_contexts` regex + `sepolicy` / `.cil` domain transition rules)
 * 7. Internal Trust & Verification Chain Analyzer (AVB 2.0, `dm-verity`, `vbmeta`, X.509, `otacerts.zip`, APK/APEX signatures)
 * 8. Intelligent Signature & Trust Re-Alignment (`test-keys` -> `release-keys`, `vbmeta` flags, `plat_mac_permissions.xml`)
 * 9. Predictive Boot & Pre-Boot ARM64 Sandbox (`init` + `linker64` execution trace & symbol binding interception)
 * 10. SMT Constraint Solver (Formal Z3-style Satisfiability Proof: `SAT` vs `UNSAT` bootloop proof)
 * 11. Automatic Binary Shim Generator (Self-Healing `.so` bridges re-exporting missing C++ symbols without modifying blobs)
 * 12. Autonomous Context & Manifest Auto-Corrector (SELinux contexts, `fs_config`, VINTF XML, SAR symlink healing)
 * 13. Real-Time Incremental File Watcher & Delta Graph Indexer (recalculates only impacted DAG branches)
 * 14. Structured Diagnostic Engine (JSON + Protobuf wire format export with Boot Confidence Score & auto-fixes)
 * 15. Headless Rust C-ABI / FFI Core (`librecore.so` JNI/C-ABI bridge for Kotlin, CLI, Electron, Qt)
 */

data class RecorePartitionMapItem(
    val partitionName: String,          // system, vendor, product, system_ext, apex, boot, odm
    val canonicalMountPoint: String,    // /, /system, /vendor, /product, /system_ext, /apex, /odm
    val physicalPathInUnpack: String,   // e.g. system/product or product
    val detectedTopology: String,       // SAR_NESTED, SYMLINK_BRIDGED, STANDALONE_DIR, VIRTUAL_REF
    val filesCount: Int,
    val elfBinariesCount: Int,
    val apksAndApexCount: Int,
    val totalBytes: Long,
    val symlinkStatus: String,
    val healthy: Boolean
)

data class RecoreDagNode(
    val nodeId: String,
    val layer: String,                  // FILE, ELF_LIB, INIT_SERVICE, HAL_BINDER, SELINUX_DOMAIN, APK_PACKAGE
    val label: String,
    val dependsOnNodeIds: List<String>,
    val dependedByCount: Int,
    val status: String,                 // RESOLVED, MISSING_DEP, HEALED_BY_SHIM
    val detail: String
)

data class RecoreElfSymbolAuditItem(
    val binaryRelativePath: String,
    val elfClass: String,               // ELF64 (AArch64)
    val soname: String,
    val dtNeededLibs: List<String>,
    val missingLibraries: List<String>,
    val unresolvedSymbols: List<String>,
    val exportedSymbolsSample: List<String>,
    val shimGenerated: Boolean,
    val shimLibraryPath: String = ""
)

data class RecoreInitSimulationStep(
    val stageOrder: Int,
    val triggerName: String,            // early-init, init, late-fs, post-fs-data, boot, property:sys.boot_completed=1
    val sourceRcFile: String,
    val serviceOrAction: String,
    val targetBinaryOrSysfs: String,
    val selinuxDomain: String,
    val envVarsSet: List<String>,
    val simulatedStatus: String,        // PASS, BLOCKED_SELINUX, MISSING_BINARY, AUTO_HEALED
    val diagnosticNote: String
)

data class RecoreTrustChainStatus(
    val avbVersion: String,             // AVB 2.0 (libavb 1.2)
    val dmVerityMode: String,           // FEC + SHA256 Merkle Tree / Disabled Flags 0x03
    val vbmetaStructValid: Boolean,
    val buildTagsMode: String,          // release-keys vs test-keys
    val otaCertsSynced: Boolean,
    val macPermissionsSynced: Boolean,
    val totalApksAudited: Int,
    val alignedAndSignedApks: Int,
    val apexContainersAudited: Int,
    val trustChainCoherencePercent: Int,
    val realignmentActionsApplied: List<String>
)

data class RecorePreBootSandboxTrace(
    val sandboxArch: String = "ARM64 (aarch64-linux-android)",
    val initEntryBinary: String = "/system/bin/init -> /init",
    val linkerBinary: String = "/system/bin/bootstrap/linker64",
    val ldLibraryPath: String = "/system/lib64:/system/product/lib64:/vendor/lib64",
    val simulatedSteps: List<String>,
    val interceptedCrashesCount: Int,
    val allDynamicRelocationsBound: Boolean,
    val sandboxVerdict: String          // BOOT_SUCCESS_PREDICTED, CRASH_INTERCEPTED, HEALED_AND_VERIFIED
)

data class RecoreSmtConstraintClause(
    val clauseId: String,
    val domainCategory: String,         // TOPOLOGY_SAR, ELF_ABI, VINTF_HAL, SELINUX_MAC, AVB_TRUST, INIT_BOOT
    val formalAssertion: String,        // SMT-LIBv2 style formula e.g. "(assert (=> (sar_root img) (= (readlink /product) /system/product)))"
    val satisfied: Boolean,
    val counterExampleOrProof: String,
    val autoFixRemediation: String
)

data class RecoreSmtSolverResult(
    val solverEngineName: String = "R.E.C.O.R.E SMT-Z3 Formal Solver v3.2",
    val overallSatStatus: String,       // SAT (Bootable Guarantee) | UNSAT (Bootloop Mathematical Proof)
    val totalConstraintsChecked: Int,
    val satisfiedConstraintsCount: Int,
    val unsatClausesCount: Int,
    val clauses: List<RecoreSmtConstraintClause>,
    val smtLib2ExportPreview: String
)

data class RecoreShimDescriptor(
    val shimFileName: String,
    val installedRelativePath: String,
    val targetProprietaryBlob: String,
    val bridgedMissingSymbols: List<String>,
    val elfSizeBytes: Long,
    val selinuxContext: String
)

data class RecoreFileWatcherDelta(
    val observerActive: Boolean,
    val watchedRootPath: String,
    val totalIndexedFiles: Int,
    val lastDeltaTimestamp: String,
    val modifiedPathsDelta: List<String>,
    val impactedDagNodesRecalculated: Int,
    val fullRescanAvoided: Boolean
)

data class RecoreCAbiFfiDescriptor(
    val libraryName: String = "librecore.so (Rust C-ABI / JNI Bridge)",
    val abiVersion: String = "RECORE_C_ABI_v3.2 (aarch64-linux-android / x86_64)",
    val exportedSymbols: List<String>,
    val headlessCliCommand: String,
    val jsonReportPath: String,
    val protobufReportPath: String,
    val protobufWireSizeBytes: Int
)

data class RecoreArtifactRegenItem(
    val relativePath: String,
    val artifactType: String,           // ODEX_OAT, VDEX_DEX, ART_BOOT, FSV_META, MAC_PERMS, OTACERTS
    val parentBinaryOrApk: String,
    val status: String,                 // UP_TO_DATE, STALE_NEEDS_REGEN, REGENERATED_AOSP_GRADE
    val reason: String,
    val baseChecksumOrVersion: String,
    val updatedChecksumOrVersion: String
)

data class RecoreDependencyCascadeChain(
    val modifiedSourcePath: String,
    val changeType: String,             // MODIFIED, ADDED, REMOVED
    val directDependents: List<String>,
    val cascadeChainOrdered: List<String>,
    val requiresApkResign: Boolean,
    val requiresArtRegen: Boolean,
    val riskIfUnresolved: String,
    val resolutionStatus: String        // COHERENT, NEEDS_REGENERATION, AUTO_RESOLVED
)

data class RecoreInitialStructureBlueprint(
    val baseImageName: String,
    val baseFilesystemFormat: String,
    val baseArchitectureLayout: String,       // SAR_SYSTEM_AS_ROOT vs FLAT_PARTITION
    val baseMountPoint: String,
    val baseBlockSize: Int,
    val baseOriginalSizeBytes: Long,
    val baseTotalBlocks: Long,
    val baseTotalInodes: Long,
    val baseUuidHex: String,
    val exactSourceImgAvailable: Boolean,
    val exactSourceImgPath: String,
    val totalRecordedExtentsCount: Int,
    val topLevelDirectories: List<String>,
    val unmodifiedFilesCount: Int,
    val modifiedFilesPaths: List<String>,
    val addedFilesPaths: List<String>,
    val deletedFilesPaths: List<String>,
    val is100PercentIdenticalToInitial: Boolean,
    val repackExecutionMode: String,          // CLONE_1TO1_BIT_FOR_BIT, SURGICAL_INPLACE_DELTA_AND_GRAFT, ZERO_MUTATION_EXT4_REBUILD
    val chainedCoherenceMechanismsTriggered: List<String>,
    val lastCompiledOutputImgPath: String = ""
)

data class RecoreFullBrainReport(
    val targetImageName: String,
    val targetUnpackedPath: String,
    val analysisTimestamp: String,
    val bootConfidenceScore: Int,       // 0..100
    val smtStatus: String,              // "SAT" or "UNSAT"
    val blockingErrorsCount: Int,
    val autoHealedCount: Int,
    val partitions: List<RecorePartitionMapItem>,
    val dagNodes: List<RecoreDagNode>,
    val dagEdgesCount: Int,
    val elfAudits: List<RecoreElfSymbolAuditItem>,
    val generatedShims: List<RecoreShimDescriptor>,
    val initSimulationSteps: List<RecoreInitSimulationStep>,
    val trustChain: RecoreTrustChainStatus,
    val sandboxTrace: RecorePreBootSandboxTrace,
    val smtSolverResult: RecoreSmtSolverResult,
    val fileWatcherDelta: RecoreFileWatcherDelta,
    val cAbiDescriptor: RecoreCAbiFfiDescriptor,
    val structuredJsonPreview: String,
    val artifactRegenItems: List<RecoreArtifactRegenItem> = emptyList(),
    val dependencyCascadeChains: List<RecoreDependencyCascadeChain> = emptyList(),
    val staleArtifactsNeedingRegenCount: Int = 0,
    val initialStructureBlueprint: RecoreInitialStructureBlueprint? = null,
    val scannerMasterReport: RecoreScannerMasterReport? = null,
    val compareEngineReport: RecoreCompareEngineReport? = null
)
