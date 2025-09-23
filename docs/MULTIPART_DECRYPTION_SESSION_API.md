# Multipart Decryption Session API

## Übersicht

Das neue Multipart Decryption Session API löst das Problem der sequentiellen HMAC-Verifikation bei der Entschlüsselung von Multipart-Objekten. Anstatt jeden Part unabhängig zu entschlüsseln (was bei HMAC-Verifikation nicht funktioniert), verwaltet das System jetzt Entschlüsselungssitzungen, die das HMAC-Objekt über alle Parts hinweg am Leben halten.

## Problem mit der alten Implementierung

Die alte `DecryptMultipartData` Methode versuchte, jeden Part unabhängig mit seinem eigenen Offset zu entschlüsseln:

```go
// ❌ FEHLERHAFT: Jeder Part wird unabhängig entschlüsselt
partDecryptor, err := dataencryption.NewAESCTRStreamingDecryptor(dek, iv, offset)
decryptedData := partDecryptor.DecryptPart(encryptedData)
```

**Warum das nicht funktioniert:**
- HMAC muss sequentiell über alle entschlüsselten Daten berechnet werden
- Das HMAC-Objekt muss zwischen den Parts erhalten bleiben
- Die Reihenfolge der Parts ist kritisch für die HMAC-Verifikation

## Neue Lösung: Session-basierte Entschlüsselung

### 1. Neue Datenstrukturen

```go
type MultipartDecryptionState struct {
    DecryptionID     string            // Eindeutige Sitzungs-ID
    ObjectKey        string            // S3 Object Key
    DEK              []byte            // Data Encryption Key
    IV               []byte            // Initialization Vector

    // HMAC-Verifikationsstatus
    HMACEnabled      bool              // Ob HMAC-Verifikation aktiviert ist
    HMACCalculator   hash.Hash         // Das HMAC-Objekt (lebt über alle Parts)
    ExpectedHMAC     []byte            // Erwarteter HMAC aus Metadaten
    NextPartNumber   int               // Nächste erwartete Partnummer
    TotalBytesRead   int64             // Gesamte verarbeitete Bytes

    // Thread-safe Zugriff
    mutex sync.RWMutex
}
```

### 2. API-Workflow

#### Schritt 1: Entschlüsselungssitzung starten

```go
err := manager.InitiateMultipartDecryption(
    ctx,
    "decryption-session-123", // Eindeutige Session ID
    "my-object-key",         // Object Key
    "my-bucket",             // Bucket Name (optional)
    encryptedDEK,            // Verschlüsselter DEK
    metadata,                // Object Metadaten mit IV und HMAC
)
if err != nil {
    return fmt.Errorf("failed to initiate decryption: %w", err)
}
```

#### Schritt 2: Parts sequentiell entschlüsseln

```go
// Parts MÜSSEN in der richtigen Reihenfolge (1, 2, 3, ...) verarbeitet werden
for partNumber := 1; partNumber <= totalParts; partNumber++ {
    encryptedPartData := getPartData(partNumber) // Ihre Implementierung

    decryptedData, err := manager.DecryptMultipartDataWithSession(
        ctx,
        "decryption-session-123", // Session ID
        partNumber,               // Part-Nummer (MUSS sequentiell sein!)
        encryptedPartData,        // Verschlüsselte Part-Daten
    )
    if err != nil {
        return fmt.Errorf("failed to decrypt part %d: %w", partNumber, err)
    }

    // Verarbeiten Sie die entschlüsselten Daten
    handleDecryptedData(decryptedData)
}
```

#### Schritt 3: Sitzung abschließen und HMAC verifizieren

```go
err = manager.CompleteMultipartDecryption(ctx, "decryption-session-123")
if err != nil {
    return fmt.Errorf("HMAC verification failed: %w", err)
}

// Optional: Sitzung aus dem Speicher entfernen
manager.CleanupMultipartDecryption("decryption-session-123")
```

### 3. Wichtige Einschränkungen

⚠️ **KRITISCH: Sequentielle Verarbeitung erforderlich**

```go
// ✅ RICHTIG: Parts werden sequentiell verarbeitet
for partNumber := 1; partNumber <= totalParts; partNumber++ {
    decryptedData, err := manager.DecryptMultipartDataWithSession(ctx, sessionID, partNumber, data)
    // ...
}

// ❌ FALSCH: Parts werden parallel oder in falscher Reihenfolge verarbeitet
go func() {
    manager.DecryptMultipartDataWithSession(ctx, sessionID, 3, data3) // Fehler!
}()
go func() {
    manager.DecryptMultipartDataWithSession(ctx, sessionID, 1, data1) // Fehler!
}()
```

Wenn Parts nicht sequentiell verarbeitet werden, erhalten Sie diese Fehlermeldung:
```
parts must be processed sequentially for HMAC verification: expected part 2, got part 3
```

### 4. Fehlerbehandlung

```go
// Session abbrechen bei Fehlern
defer func() {
    if err != nil {
        manager.AbortMultipartDecryption(ctx, sessionID)
    }
}()
```

### 5. Vollständiges Beispiel

```go
func decryptMultipartObject(manager *Manager, objectKey string, encryptedDEK []byte,
                           metadata map[string]string, partData map[int][]byte) error {

    sessionID := fmt.Sprintf("decrypt-%s-%d", objectKey, time.Now().Unix())

    // 1. Sitzung initialisieren
    err := manager.InitiateMultipartDecryption(ctx, sessionID, objectKey, "bucket", encryptedDEK, metadata)
    if err != nil {
        return fmt.Errorf("failed to initiate decryption: %w", err)
    }

    // Cleanup bei Fehlern
    defer func() {
        if err != nil {
            manager.AbortMultipartDecryption(ctx, sessionID)
        } else {
            manager.CleanupMultipartDecryption(sessionID)
        }
    }()

    // 2. Parts sequentiell entschlüsseln
    var decryptedData []byte
    for partNumber := 1; partNumber <= len(partData); partNumber++ {
        encrypted := partData[partNumber]

        decrypted, err := manager.DecryptMultipartDataWithSession(ctx, sessionID, partNumber, encrypted)
        if err != nil {
            return fmt.Errorf("failed to decrypt part %d: %w", partNumber, err)
        }

        decryptedData = append(decryptedData, decrypted...)
    }

    // 3. HMAC verifizieren und abschließen
    err = manager.CompleteMultipartDecryption(ctx, sessionID)
    if err != nil {
        return fmt.Errorf("HMAC verification failed: %w", err)
    }

    // decryptedData enthält jetzt die vollständig entschlüsselten Daten
    fmt.Printf("Successfully decrypted %d bytes\n", len(decryptedData))
    return nil
}
```

## Vorteile der neuen Implementierung

1. **Korrekte HMAC-Verifikation**: Das HMAC-Objekt wird über alle Parts hinweg am Leben gehalten
2. **Sequentielle Integrität**: Erzwingt die korrekte Reihenfolge der Part-Verarbeitung
3. **Memory-effizient**: Nur das 32-Byte HMAC-Objekt wird im Speicher gehalten, nicht die gesamten Daten
4. **Thread-safe**: Sichere parallele Nutzung durch Mutex-Schutz
5. **Fehlerresistent**: Ordnungsgemäße Cleanup-Mechanismen bei Fehlern
6. **Überwachbar**: Detailliertes Logging für Debugging und Monitoring

## Migration von der alten API

Wenn Sie aktuell `DecryptMultipartData` verwenden:

```go
// Alt (funktioniert nicht korrekt mit HMAC)
decryptedData, err := manager.DecryptMultipartData(ctx, encryptedData, encryptedDEK, metadata, objectKey, partNumber)

// Neu (korrekte HMAC-Verifikation)
sessionID := "unique-session-id"
manager.InitiateMultipartDecryption(ctx, sessionID, objectKey, bucket, encryptedDEK, metadata)
decryptedData, err := manager.DecryptMultipartDataWithSession(ctx, sessionID, partNumber, encryptedData)
manager.CompleteMultipartDecryption(ctx, sessionID)
```

## Monitoring und Debugging

Verwenden Sie `GetMultipartDecryptionState` um den Zustand einer Sitzung zu überwachen:

```go
state, err := manager.GetMultipartDecryptionState(sessionID)
if err != nil {
    log.Printf("Session %s not found", sessionID)
} else {
    log.Printf("Session %s: processed %d bytes, next part: %d",
               sessionID, state.TotalBytesRead, state.NextPartNumber)
}
```
