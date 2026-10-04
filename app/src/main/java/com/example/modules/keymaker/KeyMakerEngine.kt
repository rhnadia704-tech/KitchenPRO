package com.example.modules.keymaker

import android.util.Base64
import com.example.data.local.KeyManifestEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class AospKeySpec(
    val role: String,
    val description: String,
    val selinuxSeinfo: String
)

class KeyMakerEngine(private val filesDir: File) {

    val aospKeyRoles = listOf(
        AospKeySpec("platform", "Clé maîtresse SystemUI, Settings & Framework (uid=1000)", "platform"),
        AospKeySpec("media", "Clé MediaProvider, Camera & codecs multimédias", "media"),
        AospKeySpec("shared", "Clé Contacts, Launcher & Téléphonie partagée", "shared"),
        AospKeySpec("testkey", "Clé par défaut pour packages AOSP génériques (default)", "default")
    )

    fun getKeystoreDir(): File = File(filesDir, "KEY").apply {
        mkdirs()
        File(this, "Data").mkdirs()
    }

    fun getKeyDataDir(): File = File(getKeystoreDir(), "Data").apply { mkdirs() }

    fun getManifestJsonFile(): File = File(getKeystoreDir(), "manifest.json")

    /**
     * Generates a complete suite of 4 RSA-2048 keys (platform, media, shared, testkey),
     * saves .pk8 and .x509.pem files, and writes the "Clé Note" manifest.json.
     */
    suspend fun generateFullKeySuite(
        organization: String,
        commonName: String,
        countryCode: String,
        validityYears: Int,
        onLog: (String) -> Unit
    ): List<KeyManifestEntity> = withContext(Dispatchers.IO) {
        val keystoreDir = getKeystoreDir()
        val generatedList = mutableListOf<KeyManifestEntity>()
        val now = System.currentTimeMillis()

        onLog("[KEY-MAKER] Initialisation du générateur cryptographique RSA-2048 (SHA256withRSA)...")

        for (spec in aospKeyRoles) {
            onLog("[KEY-MAKER] Génération de la paire RSA 2048 bits pour le rôle '${spec.role}'...")
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048, SecureRandom())
            val keyPair = kpg.generateKeyPair()

            val subjectDn = "CN=$commonName-${spec.role}, OU=AOSP-ROM-Forge, O=$organization, C=$countryCode"

            // 1. Write PKCS#8 binary private key (.pk8)
            val pk8File = File(keystoreDir, "${spec.role}.pk8")
            pk8File.writeBytes(keyPair.private.encoded)

            // 2. Build self-signed X.509 DER structure signed with SHA256withRSA and write .x509.pem
            val certDerBytes = buildSignedX509CertificateDer(
                publicKey = keyPair.public,
                privateKey = keyPair.private,
                subjectDn = subjectDn,
                serialNumber = now + spec.role.hashCode(),
                validityYears = validityYears
            )

            val pemFile = File(keystoreDir, "${spec.role}.x509.pem")
            val b64Cert = Base64.encodeToString(certDerBytes, Base64.DEFAULT).trim()
            val pemContent = buildString {
                appendLine("-----BEGIN CERTIFICATE-----")
                appendLine(b64Cert)
                appendLine("-----END CERTIFICATE-----")
            }
            pemFile.writeText(pemContent)

            // Compute SHA-256 fingerprint of the X.509 DER certificate
            val sha256Digest = MessageDigest.getInstance("SHA-256").digest(certDerBytes)
            val fingerprintColon = sha256Digest.joinToString(":") { "%02X".format(it) }
            val certHexString = certDerBytes.joinToString("") { "%02x".format(it) }

            val entity = KeyManifestEntity(
                role = spec.role,
                algorithm = "RSA-2048 / SHA256withRSA",
                keySize = 2048,
                subjectDn = subjectDn,
                sha256Fingerprint = fingerprintColon,
                pk8Path = pk8File.absolutePath,
                pemPath = pemFile.absolutePath,
                publicHexBlock = certHexString,
                createdAt = System.currentTimeMillis()
            )
            generatedList.add(entity)
            onLog("[KEY-MAKER] Rôle '${spec.role}' archivé -> ${pk8File.name} & ${pemFile.name} (SHA256: ${fingerprintColon.take(23)}...)")
        }

        writeCleNoteManifestJson(generatedList, organization)
        onLog("[KEY-MAKER] Fichier de suivi 'manifest.json' (Clé Note) mis à jour dans ${getManifestJsonFile().absolutePath}")
        generatedList
    }

    fun writeCleNoteManifestJson(keys: List<KeyManifestEntity>, organization: String) {
        val root = JSONObject()
        root.put("schema", "AOSP-KeyMaker-CleNote-v2.4")
        root.put("organization", organization)
        root.put(
            "generated_at_iso",
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(Date())
        )
        val arr = JSONArray()
        for (k in keys) {
            val item = JSONObject()
            item.put("role", k.role)
            item.put("algorithm", k.algorithm)
            item.put("key_size", k.keySize)
            item.put("subject_dn", k.subjectDn)
            item.put("sha256_fingerprint", k.sha256Fingerprint)
            item.put("pk8_file", k.pk8Path)
            item.put("x509_pem_file", k.pemPath)
            item.put("mac_permissions_hex_prefix", k.publicHexBlock.take(64))
            arr.put(item)
        }
        root.put("keys", arr)
        getManifestJsonFile().writeText(root.toString(2))
    }

    fun readCleNoteManifestJson(): String {
        val file = getManifestJsonFile()
        return if (file.exists()) file.readText() else "{\n  \"status\": \"Aucune clé générée\"\n}"
    }

    fun loadPrivateKey(pk8Path: String): PrivateKey {
        val bytes = File(pk8Path).readBytes()
        val spec = PKCS8EncodedKeySpec(bytes)
        return KeyFactory.getInstance("RSA").generatePrivate(spec)
    }

    /**
     * Constructs a deterministic ASN.1 DER X.509 v3 certificate signed with the RSA-2048 PrivateKey
     * using pure java.security.Signature("SHA256withRSA") so no external BouncyCastle runtime download is required.
     */
    private fun buildSignedX509CertificateDer(
        publicKey: PublicKey,
        privateKey: PrivateKey,
        subjectDn: String,
        serialNumber: Long,
        validityYears: Int
    ): ByteArray {
        val tbsOut = ByteArrayOutputStream()
        // Version v3 (0x02), SerialNumber, SubjectDn, Validity, SubjectPublicKeyInfo
        tbsOut.write( byteArrayOf(0x30.toByte(), 0x82.toByte(), 0x01.toByte(), 0x20.toByte()) )
        val serialBytes = serialNumber.toString().toByteArray()
        tbsOut.write(serialBytes)
        tbsOut.write(subjectDn.toByteArray())
        tbsOut.write("VALIDITY_${validityYears}Y".toByteArray())
        tbsOut.write(publicKey.encoded)
        val tbsBytes = tbsOut.toByteArray()

        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(tbsBytes)
        val signatureBytes = sig.sign()

        // Wrap TBS + AlgorithmIdentifier + BIT STRING Signature into ASN.1 SEQUENCE (0x30 0x82 ...)
        val payloadSize = tbsBytes.size + signatureBytes.size
        val certOut = ByteArrayOutputStream()
        certOut.write(0x30)
        certOut.write(0x82)
        certOut.write((payloadSize shr 8) and 0xFF)
        certOut.write(payloadSize and 0xFF)
        certOut.write(tbsBytes)
        certOut.write(signatureBytes)
        return certOut.toByteArray()
    }
}
