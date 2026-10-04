package com.example.data.repository

import com.example.data.local.ArtCacheEntity
import com.example.data.local.KeyManifestEntity
import com.example.data.local.PortHistoryEntity
import com.example.data.local.RomKitchenDao
import com.example.data.local.VerificationAlertEntity
import kotlinx.coroutines.flow.Flow

class RomKitchenRepository(private val dao: RomKitchenDao) {
    val keysFlow: Flow<List<KeyManifestEntity>> = dao.observeKeys()
    val artCacheFlow: Flow<List<ArtCacheEntity>> = dao.observeArtCache()
    val alertsFlow: Flow<List<VerificationAlertEntity>> = dao.observeAlerts()
    val portHistoryFlow: Flow<List<PortHistoryEntity>> = dao.observePortHistory()

    suspend fun getAllKeys(): List<KeyManifestEntity> = dao.getAllKeys()
    suspend fun saveKey(entity: KeyManifestEntity) = dao.insertKey(entity)
    suspend fun clearKeys() = dao.clearAllKeys()

    suspend fun getCacheForApk(path: String): ArtCacheEntity? = dao.getCacheForApk(path)
    suspend fun saveArtCache(entity: ArtCacheEntity) = dao.insertArtCache(entity)
    suspend fun clearArtCache() = dao.clearArtCache()

    suspend fun addAlert(alert: VerificationAlertEntity) = dao.insertAlert(alert)
    suspend fun resolveAlert(id: Long) = dao.markAlertResolved(id)
    suspend fun clearAlerts() = dao.clearAlerts()

    suspend fun addPortHistory(entry: PortHistoryEntity) = dao.insertPortHistory(entry)
}
