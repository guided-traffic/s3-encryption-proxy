# Internal Orchestration Package

Das `internal/orchestration` Package ist das zentrale Orchestrierungslayer für alle Verschlüsselungsoperationen im S3 Encryption Proxy. Es koordiniert zwischen allen spezialisierten Komponenten und stellt eine klare Datenfluss-Architektur bereit.

## Architektur-Übersicht

```
Client Request → Manager → [Provider Manager + Operations] → Factory → S3 Storage
                    ↓
            [SinglePart | Multipart | Streaming]
                    ↓
            [Metadata Manager + HMAC Manager]
```

## Komponenten-Aufgaben

### 1. **manager.go** - Zentrale Orchestrierung
**Verantwortlichkeiten:**
- Hauptfassade für alle Verschlüsselungsoperationen
- Request-Routing zu entsprechenden Operation-Handlern
- Konfigurationsmanagement
- Komponenten-Koordination
- Öffentliche API-Fassade

**Entscheidungslogik:**
- Dateigröße < 5MB → SinglePart mit AES-GCM
- Dateigröße ≥ 5MB → SinglePart mit AES-CTR oder Multipart
- S3 Multipart Upload → Multipart Operations

### 2. **providers.go** - Provider-Management
**Verantwortlichkeiten:**
- KEK/DEK Verschlüsselungs- und Entschlüsselungsoperationen
- Provider-Registrierung und Lifecycle-Management
- Fingerprint-Tracking und Validierung
- Provider-Auswahl für Entschlüsselung
- Key-Caching für Performance-Optimierung

**Verwaltete Provider:**
- **KEK Provider**: AES, RSA, Tink, None
- **DEK Provider**: AES-CTR, AES-GCM
- **Factory Pattern**: Kombiniert KEK + DEK basierend auf Content-Type

### 3. **singlepart.go** - Komplette Objekt-Verschlüsselung
**Klare Datenpfade:**
- **EncryptGCM()**: Daten ≤ streaming_threshold → AES-GCM → Komplette Objekt-Verschlüsselung
- **EncryptCTR()**: Daten > streaming_threshold → AES-CTR → Streaming-Verschlüsselung
- **DecryptGCM()**: AES-GCM verschlüsselte Objekte → Vollständige Entschlüsselung
- **DecryptCTR()**: AES-CTR Single-Part Objekte → Streaming-Entschlüsselung

**Algorithmus-Auswahl:**
- **AES-GCM**: Authenticated Encryption für kleine Objekte
- **AES-CTR**: Streaming Encryption für große Dateien

### 4. **multipart.go** - Multipart Upload-Sessions
**Klarer Session-Lifecycle:**
1. **InitiateSession()**: DEK erstellen, IV setup, HMAC Calculator
2. **ProcessPart()**: Part mit AES-CTR verschlüsseln, HMAC sequenziell aktualisieren
3. **FinalizeSession()**: HMAC-Verifikation abschließen, finale Metadaten generieren
4. **AbortSession()**: Ressourcen und State aufräumen

**Session-Management:**
- Thread-sichere Verwaltung von Upload-Sessions
- ETag und Part-Größen-Tracking
- Sequenzielle HMAC-Berechnung über alle Parts
- Timeout-Management für Sessions

### 5. **streaming.go** - Memory-optimierte Streaming-Operationen
**Optimiert für Memory-Effizienz:**
- **CreateEncryptionReader()**: Input-Stream für On-the-fly Verschlüsselung wrappen
- **CreateDecryptionReader()**: Verschlüsselten Stream für On-the-fly Entschlüsselung wrappen
- **StreamWithSegments()**: Daten in konfigurierbaren Segmenten für große Objekte verarbeiten

**Performance-Features:**
- Echte AES-CTR Streaming-Verschlüsselung mit Cipher-State-Erhaltung
- Memory-effiziente Verarbeitung ohne Zwischenpuffer
- HMAC-Berechnung während des Streamings
- Buffer-Pools für Memory-Optimierung

### 6. **metadata.go** - Metadaten-Management
**Zentralisierte Metadaten-Operationen:**
- **BuildMetadataForEncryption()**: Vollständige Metadaten-Map für Verschlüsselungsergebnisse
- **FilterClientMetadata()**: Verschlüsselungs-Metadaten aus Client-Antworten filtern
- **GetAlgorithm()**: Verschlüsselungsalgorithmus aus Metadaten extrahieren
- **ParseMetadata()**: Base64-Decoding und Metadaten-Parsing

**Metadaten-Konventionen:**
- Prefix: `s3ep-` (konfigurierbar)
- Kritische Felder: `encrypted-dek`, `encryption-mode`, Algorithmus-Metadaten
- Security-Isolation durch Metadaten-Filterung

## Unterschiede: Multipart vs. Streaming

### **Multipart Operations**
- **S3-spezifisch**: Implementiert das S3 Multipart Upload API
- **Session-basiert**: Verwaltet Upload-Sessions mit persistentem State
- **Part-Management**: Einzelne Parts werden separat verschlüsselt
- **HMAC über alle Parts**: Berechnet Integrität über den gesamten Upload
- **ETag-Tracking**: Verwaltet S3 ETags für jeden Part
- **Use Case**: Große Dateien (>5MB) mit S3 Multipart Upload API

### **Streaming Operations**
- **Memory-optimiert**: Verarbeitet Daten ohne komplette Ladung in Memory
- **Reader-Interface**: Stellt `io.Reader` für On-the-fly Verschlüsselung bereit
- **Segment-basiert**: Verarbeitet Daten in konfigurierbaren Segmenten (Standard: 12MB)
- **Generisch**: Kann für Single-Part und Multipart verwendet werden
- **Use Case**: Memory-effiziente Verarbeitung für alle Dateigrößen

## Datenfluss-Dokumentation

### PUT Request Flow (Upload)
```
Client Request → ManagerV2.Encrypt()
                ↓
        [Size Check: < 5MB?]
                ↓                    ↓
         SinglePartOps.           SinglePartOps.
         EncryptGCM()           EncryptCTR()
                ↓                    ↓
         [AES-GCM Path]           [AES-CTR Path]
                ↓                    ↓
         ProviderManager.         ProviderManager.
         EncryptDEK()            EncryptDEK()
                ↓                    ↓
         Factory.CreateGCM()     Factory.CreateCTR()
                ↓                    ↓
         [Single Operation]      [Streaming Operation]
                ↓                    ↓
         MetadataManager.        MetadataManager.
         BuildResult()           BuildResult()
                ↓                    ↓
              S3 Storage            S3 Storage
```

### Multipart PUT Flow
```
Client Initiate → MultipartOps.InitiateSession()
                        ↓
                [Create DEK, IV, HMAC Calculator]
                        ↓
Client Part Upload → MultipartOps.ProcessPart()
                        ↓
                [AES-CTR Encrypt + Sequential HMAC]
                        ↓
                [Store Part ETag & Size]
                        ↓
Client Complete → MultipartOps.FinalizeSession()
                        ↓
                [Verify Final HMAC]
                        ↓
                [Generate Object Metadata]
                        ↓
                     S3 Storage
```

### GET Request Flow (Download)
```
S3 Storage → ManagerV2.Decrypt()
                ↓
        MetadataManager.GetAlgorithm()
                ↓
        [Algorithm Check: GCM vs CTR?]
                ↓                    ↓
         SinglePartOps.           SinglePartOps.
         DecryptGCM()            DecryptCTR()
                ↓                    ↓
         ProviderManager.         ProviderManager.
         DecryptDEK()            DecryptDEK()
                ↓                    ↓
         Factory.CreateGCM()     Factory.CreateCTR()
                ↓                    ↓
         [Single Operation]      [Streaming Operation]
                ↓                    ↓
         HMACManager.            HMACManager.
         verifyIntegrity()       verifyIntegrity()
                ↓                    ↓
              Client               Client
```

## Warum diese Aufteilung?

### **Singlepart vs. Multipart**
- **Singlepart**: Komplette Objekte, die als eine Einheit behandelt werden
- **Multipart**: S3's native API für große Dateien (>5MB), die in Teilen hochgeladen werden

### **Streaming als Querschnittsfunktion**
Streaming ist eine **Implementierungstechnik** für memory-effiziente Verarbeitung:
- Wird **sowohl** von Singlepart **als auch** von Multipart verwendet
- Singlepart kann Streaming für große Dateien verwenden (EncryptCTR)
- Multipart verwendet immer Streaming für die einzelnen Parts

### **Architektur-Trennung**
Die Architektur trennt klar:
1. **Was** verschlüsselt wird (Single vs. Multi-Part)
2. **Wie** verschlüsselt wird (GCM vs. CTR Algorithmus)
3. **Auf welche Weise** verarbeitet wird (Memory-optimiert durch Streaming)

## Performance-Optimierungen

### **Memory-Management**
- Buffer-Pools für wiederverwendbare Buffer
- Streaming-Verarbeitung ohne komplette Memory-Ladung
- Konfigurierbare Segment-Größen (Minimum: 5MB, Standard: 12MB)

### **Key-Management**
- DEK-Caching für Performance
- Sichere DEK-Löschung nach Verwendung
- Thread-sichere Provider-Verwaltung

### **HMAC-Optimierung**
- Streaming HMAC-Berechnung
- HKDF-basierte Key-Derivation
- Sequenzielle HMAC-Updates für Multipart

## Konfiguration

### **Provider-Konfiguration**
```yaml
encryption:
  encryption_method_alias: "current-provider"  # Aktiv für Writes
  providers:                                   # Alle Provider für Reads
    - alias: "current-provider"
      type: "aes-ctr"  # oder "tink", "rsa-envelope", "aes-gcm", "none"
      config: { ... }
```

### **Performance-Tuning**
```yaml
optimizations:
  streaming_segment_size: 12582912  # 12MB Segmente
  enable_hmac_verification: true    # Integrität-Verifikation
```

## Error Handling

### **Strukturiertes Logging**
- Verwendung von `logrus.WithFields()` für alle Error-Reports
- Kontextuelle Informationen: bucket, key, operation, error details
- Provider-spezifische Logs mit Alias und Type

### **Error-Kategorien**
- **Provider-Errors**: Verschlüsselungs-/Entschlüsselungsfehler
- **Validation-Errors**: HMAC-Verifikationsfehler
- **Session-Errors**: Multipart-Session-Management-Fehler
- **Streaming-Errors**: Memory- und IO-Fehler
