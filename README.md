# ROM Forge — AOSP Reverse-Compiler & Hybrid ROM Kitchen

**ROM Forge** est une application Android native (Kotlin + Jetpack Compose) agissant comme un **Reverse-Compiler AOSP** et une **Kitchen Android 100% Offline**. Elle s'exécute directement sur un appareil Android (en mode **Root Loopback** ou **Non-Root Scoped Storage / SAF**) pour manipuler des images `.img` (`ext4`, `erofs`, `sparse`), reconstruire la chaîne de confiance cryptographique (AVB 2.0 + RSA 2048), optimiser le cache ART (`dex2oat`), et porter automatiquement des images GSI vers des systèmes matériels propriétaires (inspiré des Device Trees LineageOS).

---

## Architecture Technique & 5 Modules Intégrés

### 1. Binaires Natifs Statiques (`assets/bin/arm64-v8a/`) & Exécution Hybride
- **Zéro dépendance runtime :** Au premier démarrage, `AssetBinaryManager` extrait et vérifie les empreintes SHA-256 des outils binaires embarqués (`avbtool`, `mke2fs`, `mkfs.erofs`, `zipalign`, `dex2oat`, `simg2img`, `lpunpack`) vers `context.filesDir/bin/` avec permissions d'exécution (`0755`).
- **HybridShellEngine :** Détecte automatiquement l'accès `su` (Magisk / KernelSU / APatch) ou bascule de manière transparente en mode **Non-Root SAF / Userspace** permettant la décompilation et recompilation intégrale d'images `.img` dans l'espace privé sans montage kernel.
- **CrossVerifierEngine :** Analyseur statique croisé temps-réel vérifiant la cohérence entre `mac_permissions.xml`, `file_contexts`, `fs_config`, les manifests VINTF et les blobs ELF avant toute opération critique.

### 2. Module 1 : Key Maker (`KeyMakerEngine`)
- Génération cryptographique pure via `java.security.KeyPairGenerator` de paires **RSA-2048** (`SHA256withRSA`) pour les 4 rôles AOSP : `platform`, `media`, `shared`, `testkey`.
- Export conforme aux standards AOSP : clé privée `.pk8` (PKCS#8 DER) et certificat `.x509.pem` avec structure Subject/Issuer complète.
- Archivage sécurisé dans le Keystore local avec suivi JSON dans `manifest.json` (**Clé Note**).

### 3. Module 2 : Sign Pro (`SignProEngine`)
- **In-Memory Streaming APK Signer :** Lecture par `ZipInputStream` et réécriture à la volée via `ZipOutputStream` sans extraction disque. Purge automatique de l'ancien dossier `META-INF/`, calcul des digests SHA-256 par entrée, génération de `MANIFEST.MF`, `CERT.SF` et signature numérique `CERT.RSA`.
- **Préservation de l'alignement :** Maintien strict des entrées non compressées (`STORED`) comme `resources.arsc` et les librairies natives `.so` (alignement 4K/16K).
- **Injecteur `mac_permissions.xml` :** Analyse et réécriture DOM/XML de `/system/etc/selinux/plat_mac_permissions.xml` pour injecter les nouvelles signatures hexadécimales associées aux seinfo `platform`, `media`, `shared` et `default`.

### 4. Module 3 : Generator (`ArtGeneratorEngine`)
- Orchestration de `dex2oat` pour compiler les bytecodes DEX en `.odex` (ELF oat) et `.vdex` (vérification rapide) selon le filtre choisi (`speed`, `speed-profile`, `verify`, `everything`) et le jeu d'instructions (`arm64`).
- Génération des métadonnées **fs-verity** (`.fsv_meta`) avec arbre de Merkle SHA-256 par blocs de 4096 octets.
- **Cache MD5 Persistant (Room Database) :** Évite toute recompilation inutile des APKs dont l'empreinte MD5 et le rôle de signature n'ont pas changé.
- Synchronisation automatique des certificats `otacerts.zip` suite à un changement de chaîne de confiance.

### 5. Module 4 : Compilation & Anti-Bootloop (`ImgCompilerEngine`)
- **Analyseur Pré-Vol Anti-Bootloop :** Validation syntaxique des expressions régulières SELinux (`file_contexts`), vérification des UID/GID/Modes POSIX (`fs_config` : `init` en `0750`, `su` en `06755`), et contrôle des étiquettes SELinux.
- Reconstruction complète du `system.img` en **EXT4** (`mke2fs`) ou **EROFS** (`mkfs.erofs -zlz4hc,9`).
- Signature finale via `avbtool add_hashtree_footer` (dm-verity) et génération de `vbmeta.img` avec support des flags de vérification.

### 6. Module 5 : Auto-Porter GSI to System (`AutoPorterEngine`)
- **Extracteur de Blobs Propriétaires :** Analyse les dépendances ELF (`DT_NEEDED`) entre `/vendor` Stock et `/system` GSI pour identifier et transplanter automatiquement les librairies manquantes (Audio, Camera, RIL/IMS, Sensors, Display).
- **Générateur RRO (`TrebleOverlay.apk`) :** Parse les configurations matérielles Stock (`config_statusBarHeight`, `config_screenBrightnessSettingMinimum`, découpes d'écran, `power_profile.xml`) et génère un APK d'overlay RRO signé injecté dans `/product/overlay/`.
- **Adaptateur VINTF & SEPolicy :** Fusionne les matrices de compatibilité HAL, transplante `audio_policy_configuration.xml` et `media_profiles_V1_0.xml`, et génère les règles CIL (`plat_pub_versioned.cil`) pour éliminer les blocages `avc: denied`.
- **Résolveur UDFPS / FOD (Fingerprint On Display) :** Détecte automatiquement les capteurs optiques/ultrasoniques (Goodix, FPC, Xiaomi/Oplus/Samsung extensions), transplante les HALs biométriques et injecte le shim HBM (`sysfs` High Brightness Mode) pour SystemUI AOSP.

---

## Compilation (Local & GitHub Actions)

```bash
./gradlew assembleDebug
```
Le workflow GitHub Actions `.github/workflows/android-build.yml` compile automatiquement l'APK et exécute les tests unitaires à chaque push.
