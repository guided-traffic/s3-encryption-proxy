# CA Certificates in Distroless Images

## TL;DR
In distroless images liegen die CA-Zertifikate unter:
- **`/etc/ssl/certs/ca-certificates.crt`** - Hauptdatei mit allen CA-Zertifikaten

## Dateistruktur

```
/etc/ssl/
├── certs/
│   └── ca-certificates.crt  (Bundle aller CA-Zertifikate)
```

## Details

### Distroless vs Alpine

| Aspekt | Distroless | Alpine |
|--------|-----------|---------|
| CA-Zertifikat Pfad | `/etc/ssl/certs/ca-certificates.crt` | `/etc/ssl/certs/ca-certificates.crt` |
| Anzahl der Dateien | **1 Bundle-Datei** | Bundle + einzelne Zertifikate (hunderte) |
| Symlinks | Keine | Viele (für Hash-basierte Lookups) |
| Größe | ~220 KB | ~350 KB |
| Update-Mechanismus | Build-time (Debian upstream) | apk update ca-certificates |

### Go's Standard Library Verhalten

Go's `crypto/x509` sucht automatisch nach CA-Zertifikaten in mehreren Standard-Pfaden:

```go
// Standard certificate file locations (from crypto/x509/root_unix.go)
var certFiles = []string{
    "/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL
    "/etc/ssl/ca-bundle.pem",                            // OpenSUSE
    "/etc/pki/tls/cacert.pem",                           // OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
    "/etc/ssl/cert.pem",                                 // Alpine Linux
}
```

**Distroless verwendet den Debian-Standard**: `/etc/ssl/certs/ca-certificates.crt`

Daher funktioniert unsere statisch kompilierte Go-Binary **ohne zusätzliche Konfiguration**!

## Verifizierung im Container

Da distroless keine Shell hat, müssen wir externe Tools zur Verifikation nutzen:

### Methode 1: Container Export
```bash
docker export <container-id> | tar -t | grep ca-certificates
```

### Methode 2: Docker CP
```bash
docker cp <container-id>:/etc/ssl/certs/ca-certificates.crt ./ca-bundle.crt
openssl crl2pkcs7 -nocrl -certfile ./ca-bundle.crt | openssl pkcs7 -print_certs -noout | grep "subject="
```

### Methode 3: Application Logs
Der S3 Encryption Proxy zeigt TLS-Fehler in den Logs, falls CA-Zertifikate fehlen:
```bash
docker logs proxy | grep -i "certificate"
```

## Häufige Probleme & Lösungen

### Problem: "x509: certificate signed by unknown authority"

**Ursache**: CA-Zertifikate fehlen oder sind veraltet

**Lösung für Distroless**:
```dockerfile
# Die distroless/static-debian12 Images enthalten bereits aktuelle CA-Zertifikate
# Kein manuelles Kopieren notwendig!
FROM gcr.io/distroless/static-debian12:nonroot
```

**Lösung für Scratch** (falls du auf scratch wechselst):
```dockerfile
FROM scratch
# Kopiere CA-Zertifikate vom Builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
```

### Problem: Custom CA-Zertifikate hinzufügen

**Für Distroless** (Multi-Stage Build):
```dockerfile
FROM debian:12-slim AS certs
RUN apt-get update && apt-get install -y ca-certificates
COPY custom-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
```

### Problem: Go ignoriert CA-Zertifikate

**Lösung**: Setze `SSL_CERT_FILE` Environment Variable (falls Go nicht den Standard-Pfad findet):
```dockerfile
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

## Update-Strategie

### Distroless
- CA-Zertifikate werden mit dem Base-Image aktualisiert
- Google aktualisiert die distroless-Images regelmäßig
- **Best Practice**: Rebuild dein Image regelmäßig mit neuestem distroless-Tag

```bash
# Pull latest distroless image
docker pull gcr.io/distroless/static-debian12:nonroot

# Rebuild your application
docker build --no-cache -t s3-encryption-proxy:latest .
```

### CI/CD Integration
```yaml
# GitHub Actions Beispiel
- name: Update base images
  run: docker pull gcr.io/distroless/static-debian12:nonroot

- name: Build with latest base
  run: docker build --pull -t s3-encryption-proxy:${{ github.sha }} .
```

## Zusätzliche Ressourcen

- [Distroless GitHub](https://github.com/GoogleContainerTools/distroless)
- [Go crypto/x509 Source](https://github.com/golang/go/blob/master/src/crypto/x509/root_unix.go)
- [Debian CA Certificates](https://packages.debian.org/bookworm/ca-certificates)

## Testing CA-Funktionalität

Test ob HTTPS-Verbindungen funktionieren:

```bash
# Test mit AWS S3
docker run --rm s3-encryption-proxy:latest ./s3-encryption-proxy --config /etc/s3ep/config.yaml &
curl http://localhost:8080/health

# Prüfe Logs auf TLS-Fehler
docker logs proxy 2>&1 | grep -i "certificate\|tls\|x509"
```

Wenn keine Fehler auftreten, funktionieren die CA-Zertifikate korrekt! ✅
