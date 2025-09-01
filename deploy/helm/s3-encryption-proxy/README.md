# S3 Encryption Proxy Helm Chart

This Helm chart deploys the S3 Encryption Proxy application to a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- cert-manager (optional, for TLS certificate management)

## Installing the Chart

To install the chart with the release name `my-s3-proxy`:

```bash
helm repo add s3-encryption-proxy https://your-helm-repo.com
helm install my-s3-proxy s3-encryption-proxy/s3-encryption-proxy
```

Or from the source:

```bash
cd deploy/helm/s3-encryption-proxy
helm install my-s3-proxy .
```

## Uninstalling the Chart

To uninstall/delete the `my-s3-proxy` deployment:

```bash
helm delete my-s3-proxy
```

## Configuration

The following table lists the configurable parameters of the S3 Encryption Proxy chart and their default values.

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Container image repository | `s3-encryption-proxy` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `image.tag` | Image tag | `""` (uses chart appVersion) |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `service.targetPort` | Container port | `8080` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `podSecurityContext.runAsUser` | User ID to run container | `1001` |
| `podSecurityContext.runAsNonRoot` | Run as non-root user | `true` |
| `securityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |
| `securityContext.readOnlyRootFilesystem` | Read-only root filesystem | `true` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `250m` |
| `resources.requests.memory` | Memory request | `256Mi` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable horizontal pod autoscaler | `false` |
| `autoscaling.minReplicas` | Minimum number of replicas | `2` |
| `autoscaling.maxReplicas` | Maximum number of replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts configuration | See values.yaml |
| `ingress.tls` | Ingress TLS configuration | `[]` |

### Certificate Configuration (cert-manager)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certificate.enabled` | Enable cert-manager certificate | `false` |
| `certificate.issuer.kind` | Certificate issuer kind | `ClusterIssuer` |
| `certificate.issuer.name` | Certificate issuer name | `letsencrypt-prod` |
| `certificate.dnsNames` | Certificate DNS names | `["s3-proxy.local"]` |
| `certificate.secretName` | Certificate secret name | `s3-proxy-tls` |

### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.bindAddress` | Server bind address | `"0.0.0.0:8080"` |
| `config.logLevel` | Log level | `"info"` |
| `config.targetEndpoint` | Target S3 endpoint | `"https://s3.amazonaws.com"` |
| `config.region` | AWS region | `"us-east-1"` |

### Encryption Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.encryption.encryptionMethodAlias` | Active encryption method | `"default"` |
| `config.encryption.providers` | Encryption providers configuration | See values.yaml |

### Secrets Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.s3.accessKeyId` | S3 access key ID | `""` |
| `secrets.s3.secretKey` | S3 secret key | `""` |
| `secrets.gcp.serviceAccountKey` | GCP service account key (base64) | `""` |
| `secrets.aws.accessKeyId` | AWS access key ID | `""` |
| `secrets.aws.secretAccessKey` | AWS secret access key | `""` |

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `monitoring.serviceMonitor.enabled` | Enable Prometheus ServiceMonitor | `false` |
| `monitoring.serviceMonitor.namespace` | ServiceMonitor namespace | `monitoring` |
| `monitoring.serviceMonitor.interval` | Scrape interval | `30s` |

## Examples

### Basic Installation

```bash
helm install my-s3-proxy . \
  --set secrets.s3.accessKeyId="your-access-key" \
  --set secrets.s3.secretKey="your-secret-key"
```

### Production Installation with cert-manager

```bash
helm install my-s3-proxy . \
  --values values-production.yaml \
  --set secrets.s3.accessKeyId="your-access-key" \
  --set secrets.s3.secretKey="your-secret-key" \
  --set secrets.gcp.serviceAccountKey="$(base64 -w 0 < gcp-credentials.json)" \
  --set certificate.dnsNames[0]="s3-proxy.yourdomain.com" \
  --set ingress.hosts[0].host="s3-proxy.yourdomain.com"
```

### Development Installation

```bash
helm install my-s3-proxy . \
  --values values-development.yaml
```

## Security Considerations

1. **Secrets Management**: Never store secrets in values files. Use external secret management systems or pass them via `--set` during installation.

2. **Network Policies**: Enable network policies in production to restrict pod-to-pod communication.

3. **Pod Security**: The chart uses a non-root user and read-only root filesystem for enhanced security.

4. **TLS**: Enable TLS in production environments using cert-manager for automatic certificate management.

## Troubleshooting

### Common Issues

1. **Pod not starting**: Check resource limits and ensure the image is accessible.
2. **Configuration errors**: Verify the ConfigMap content and environment variables.
3. **Certificate issues**: Ensure cert-manager is installed and the issuer is configured correctly.

### Debugging Commands

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=s3-encryption-proxy

# View logs
kubectl logs -l app.kubernetes.io/name=s3-encryption-proxy

# Check configuration
kubectl describe configmap my-s3-proxy-config

# Check certificate status (if enabled)
kubectl describe certificate my-s3-proxy-tls
```

## Contributing

Please refer to the main project repository for contribution guidelines.
