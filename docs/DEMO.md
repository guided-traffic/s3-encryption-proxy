# S3 Encryption Proxy Demo

Diese Docker Compose Demo zeigt den S3 Encryption Proxy in Aktion mit MinIO und zwei S3 Explorern.

## 🏗️ Architektur

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  S3 Explorer    │    │  S3 Explorer    │    │                 │
│  (Direkt)       │    │  (Verschlüsselt)│    │     MinIO       │
│  Port: 8081     │    │  Port: 8082     │    │  Console: 9001  │
└─────────┬───────┘    └─────────┬───────┘    │   API: 9000     │
          │                      │            └─────────────────┘
          │              ┌───────▼───────┐             ▲
          │              │ S3 Encryption │             │
          │              │     Proxy     │             │
          │              │  Port: 8080   │             │
          │              └───────┬───────┘             │
          │                      │                     │
          └──────────────────────┼─────────────────────┘
                                 │
                        🔒 RSA Envelope
                           Encryption
```

## 🚀 Schnellstart

### 1. Demo starten
```bash
# Alle Services starten
docker-compose -f docker-compose.demo.yml up -d --build

# Logs verfolgen
docker-compose -f docker-compose.demo.yml logs -f
```

### 2. Services öffnen

| Service | URL | Beschreibung |
|---------|-----|--------------|
| **MinIO Console** | http://localhost:9001 | MinIO Management Interface |
| **S3 Explorer (Direkt)** | http://localhost:8081 | Unverschlüsselte Dateien anzeigen |
| **S3 Explorer (Verschlüsselt)** | http://localhost:8082 | Verschlüsselte Dateien hochladen |

**Login für MinIO Console:**
- Benutzername: `minioadmin`
- Passwort: `minioadmin123`

## 🧪 Demo durchführen

### Schritt 1: Bucket erstellen
1. Öffne den **S3 Explorer (Verschlüsselt)** (Port 8082)
2. Erstelle einen neuen Bucket, z.B. `demo-bucket`

### Schritt 2: Datei verschlüsselt hochladen
1. Im **S3 Explorer (Verschlüsselt)** (Port 8082):
   - Lade eine Testdatei in den `demo-bucket` hoch
   - Die Datei wird automatisch mit RSA Envelope Encryption verschlüsselt

### Schritt 3: Verschlüsselte Datei in MinIO anschauen
1. Öffne die **MinIO Console** (Port 9001)
2. Navigiere zu `demo-bucket`
3. Lade die Datei herunter und öffne sie
4. ➡️ **Die Datei ist verschlüsselt und unleserlich!**

### Schritt 4: Datei entschlüsselt lesen
1. Im **S3 Explorer (Verschlüsselt)** (Port 8082):
   - Lade dieselbe Datei herunter
   - ➡️ **Die Datei wird automatisch entschlüsselt und ist lesbar!**

### Schritt 5: Vergleich mit unverschlüsselten Dateien
1. Im **S3 Explorer (Direkt)** (Port 8081):
   - Lade eine andere Datei direkt in MinIO hoch
2. In der **MinIO Console** (Port 9001):
   - Diese Datei ist unverschlüsselt und direkt lesbar

## 🔐 Verschlüsselung

Die Demo verwendet **RSA Envelope Encryption**:
- **RSA 2048-bit** Schlüsselpaar für KEK (Key Encryption Key)
- **AES-256-GCM** für DEK (Data Encryption Key) pro Datei
- Jede Datei bekommt einen neuen, zufälligen AES-Schlüssel
- Der AES-Schlüssel wird mit dem RSA Public Key verschlüsselt

## 🔧 Troubleshooting

### Services prüfen
```bash
# Status aller Services
docker-compose -f docker-compose.demo.yml ps

# Health Checks
curl http://localhost:8080/health  # S3 Encryption Proxy
curl http://localhost:9000/minio/health/live  # MinIO
```

### Logs anschauen
```bash
# Alle Logs
docker-compose -f docker-compose.demo.yml logs

# Nur Proxy Logs
docker-compose -f docker-compose.demo.yml logs s3-encryption-proxy

# Nur MinIO Logs
docker-compose -f docker-compose.demo.yml logs minio
```

### Demo zurücksetzen
```bash
# Alle Services stoppen und Daten löschen
docker-compose -f docker-compose.demo.yml down -v

# Neu starten
docker-compose -f docker-compose.demo.yml up -d --build
```

## 📋 Service Details

### MinIO
- **S3 API**: Port 9000
- **Management Console**: Port 9001
- **Credentials**: minioadmin / minioadmin123
- **Daten**: Persistent in Docker Volume `minio_data`

### S3 Encryption Proxy
- **Port**: 8080
- **Verschlüsselung**: RSA Envelope (2048-bit)
- **Target**: MinIO auf Port 9000
- **Health Check**: `/health` Endpoint

### S3 Explorer (Direkt)
- **Port**: 8081
- **Verbindung**: Direkt zu MinIO
- **Zweck**: Unverschlüsselte Dateien anzeigen

### S3 Explorer (Verschlüsselt)
- **Port**: 8082
- **Verbindung**: Über S3 Encryption Proxy
- **Zweck**: Verschlüsselte Dateien up-/downloaden

## 🔑 Sicherheitshinweise

⚠️ **Wichtig**: Die RSA-Schlüssel in dieser Demo sind nur für Testzwecke!

Für Produktionsumgebungen:
- Generiere neue Schlüsselpaare mit `./build/s3ep-rsa-keygen`
- Verwende 4096-bit RSA-Schlüssel für höhere Sicherheit
- Speichere private Schlüssel sicher (z.B. in einem Key Management System)
- Verwende unterschiedliche Schlüssel für verschiedene Umgebungen
