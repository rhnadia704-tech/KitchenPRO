package com.example.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "key_manifests")
data class KeyManifestEntity(
    @PrimaryKey val role: String, // platform, media, shared, testkey
    val algorithm: String,
    val keySize: Int,
    val subjectDn: String,
    val sha256Fingerprint: String,
    val pk8Path: String,
    val pemPath: String,
    val publicHexBlock: String,
    val createdAt: Long
)

@Entity(tableName = "art_md5_cache")
data class ArtCacheEntity(
    @PrimaryKey val apkRelativePath: String,
    val md5Hash: String,
    val odexPath: String,
    val vdexPath: String,
    val fsvMetaPath: String?,
    val compilerFilter: String,
    val instructionSet: String,
    val odexSizeBytes: Long,
    val updatedAt: Long
)

@Entity(tableName = "verification_alerts")
data class VerificationAlertEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val module: String,
    val severity: String, // CRITICAL, WARNING, INFO, PASS
    val title: String,
    val technicalDetail: String,
    val remediationCommand: String,
    val resolved: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "port_history")
data class PortHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val stockDeviceName: String,
    val gsiTargetName: String,
    val blobsTransplanted: Int,
    val rroOverlayPath: String,
    val sepolicyRulesMerged: Int,
    val fodStatus: String,
    val hbmSysfsNode: String,
    val timestamp: Long = System.currentTimeMillis()
)
