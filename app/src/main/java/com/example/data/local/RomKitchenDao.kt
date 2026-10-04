package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface RomKitchenDao {
    // Key Maker Manifest ("Clé Note")
    @Query("SELECT * FROM key_manifests ORDER BY role ASC")
    fun observeKeys(): Flow<List<KeyManifestEntity>>

    @Query("SELECT * FROM key_manifests ORDER BY role ASC")
    suspend fun getAllKeys(): List<KeyManifestEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKey(entity: KeyManifestEntity)

    @Query("DELETE FROM key_manifests")
    suspend fun clearAllKeys()

    // ART MD5 Cache
    @Query("SELECT * FROM art_md5_cache ORDER BY updatedAt DESC")
    fun observeArtCache(): Flow<List<ArtCacheEntity>>

    @Query("SELECT * FROM art_md5_cache WHERE apkRelativePath = :path LIMIT 1")
    suspend fun getCacheForApk(path: String): ArtCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertArtCache(entity: ArtCacheEntity)

    @Query("DELETE FROM art_md5_cache")
    suspend fun clearArtCache()

    // Cross-Verification Alerts
    @Query("SELECT * FROM verification_alerts ORDER BY timestamp DESC")
    fun observeAlerts(): Flow<List<VerificationAlertEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAlert(alert: VerificationAlertEntity)

    @Query("UPDATE verification_alerts SET resolved = 1 WHERE id = :id")
    suspend fun markAlertResolved(id: Long)

    @Query("DELETE FROM verification_alerts")
    suspend fun clearAlerts()

    // Porting History
    @Query("SELECT * FROM port_history ORDER BY timestamp DESC")
    fun observePortHistory(): Flow<List<PortHistoryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPortHistory(entry: PortHistoryEntity)
}
