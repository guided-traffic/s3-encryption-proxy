# Deployment Guide

## Overview

This guide covers various deployment options for the S3 Encryption Proxy, from local development to production-ready deployments with high availability and security.

## Quick Start

### Docker (Recommended)

The fastest way to get started:

```bash
# Using environment variables
docker run -p 8080:8080 \
  -e S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com \
  -e S3EP_REGION=us-east-1 \
  -e S3EP_ACCESS_KEY_ID=your-access-key \
  -e S3EP_SECRET_KEY=your-secret-key \
  -e S3EP_ENCRYPTION_TYPE=aes256-gcm \
  -e S3EP_AES_KEY=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ== \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest
```

### Binary

Download and run the binary directly:

```bash
# Download latest release
wget https://github.com/guided-traffic/s3-encryption-proxy/releases/latest/download/s3-encryption-proxy-linux-amd64

# Make executable
chmod +x s3-encryption-proxy-linux-amd64

# Run with configuration file
./s3-encryption-proxy-linux-amd64 --config config.yaml
```

## Container Deployments

### Docker

#### Using Docker Compose

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com
      - S3EP_REGION=us-east-1
      - S3EP_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - S3EP_SECRET_KEY=${AWS_SECRET_ACCESS_KEY}
      - S3EP_ENCRYPTION_TYPE=tink
      - S3EP_KEK_URI=${GCP_KEK_URI}
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./gcp-credentials.json:/credentials.json:ro
    command: ["--config", "/app/config.yaml", "--credentials-path", "/credentials.json"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: MinIO for local testing
  minio:
    image: minio/minio:latest
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      - MINIO_ACCESS_KEY=minioadmin
      - MINIO_SECRET_KEY=minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio-data:/data

volumes:
  minio-data:
```

**Usage:**
```bash
# Start services
docker-compose up -d

# Check logs
docker-compose logs -f s3-encryption-proxy

# Stop services
docker-compose down
```

#### Docker with Secrets

For production deployments, use Docker secrets:

```yaml
version: '3.8'

services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
    environment:
      - S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com
      - S3EP_REGION=us-east-1
      - S3EP_ENCRYPTION_TYPE=tink
      - S3EP_KEK_URI_FILE=/run/secrets/kek_uri
      - S3EP_ACCESS_KEY_ID_FILE=/run/secrets/aws_access_key
      - S3EP_SECRET_KEY_FILE=/run/secrets/aws_secret_key
    secrets:
      - aws_access_key
      - aws_secret_key
      - kek_uri
      - gcp_credentials
    volumes:
      - type: bind
        source: /run/secrets/gcp_credentials
        target: /credentials.json
        read_only: true

secrets:
  aws_access_key:
    file: ./secrets/aws_access_key.txt
  aws_secret_key:
    file: ./secrets/aws_secret_key.txt
  kek_uri:
    file: ./secrets/kek_uri.txt
  gcp_credentials:
    file: ./secrets/gcp_credentials.json
```

## Kubernetes Deployments

### Basic Deployment

**namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: s3-encryption-proxy
```

**secrets.yaml:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: aws-credentials
  namespace: s3-encryption-proxy
type: Opaque
data:
  access-key-id: <base64-encoded-access-key>
  secret-access-key: <base64-encoded-secret-key>

---
apiVersion: v1
kind: Secret
metadata:
  name: gcp-credentials
  namespace: s3-encryption-proxy
type: Opaque
data:
  credentials.json: <base64-encoded-gcp-service-account-json>
```

**configmap.yaml:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: s3-encryption-proxy-config
  namespace: s3-encryption-proxy
data:
  config.yaml: |
    bind_address: "0.0.0.0:8080"
    log_level: "info"
    target_endpoint: "https://s3.amazonaws.com"
    region: "us-east-1"
    encryption_type: "tink"
    kek_uri: "gcp-kms://projects/my-project/locations/global/keyRings/s3-encryption/cryptoKeys/master-key"
    credentials_path: "/etc/gcp/credentials.json"
```

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-encryption-proxy
  namespace: s3-encryption-proxy
  labels:
    app: s3-encryption-proxy
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: s3-encryption-proxy
  template:
    metadata:
      labels:
        app: s3-encryption-proxy
    spec:
      containers:
      - name: s3-encryption-proxy
        image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: S3EP_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: aws-credentials
              key: access-key-id
        - name: S3EP_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: aws-credentials
              key: secret-access-key
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
          readOnly: true
        - name: gcp-credentials
          mountPath: /etc/gcp
          readOnly: true
        args:
        - "--config"
        - "/app/config.yaml"
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: s3-encryption-proxy-config
      - name: gcp-credentials
        secret:
          secretName: gcp-credentials
      securityContext:
        fsGroup: 1000
```

**service.yaml:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: s3-encryption-proxy
  namespace: s3-encryption-proxy
  labels:
    app: s3-encryption-proxy
spec:
  selector:
    app: s3-encryption-proxy
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  type: ClusterIP
```

**ingress.yaml:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: s3-encryption-proxy
  namespace: s3-encryption-proxy
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - s3-proxy.yourdomain.com
    secretName: s3-encryption-proxy-tls
  rules:
  - host: s3-proxy.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: s3-encryption-proxy
            port:
              number: 80
```

### High Availability Deployment

**hpa.yaml (Horizontal Pod Autoscaler):**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: s3-encryption-proxy
  namespace: s3-encryption-proxy
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: s3-encryption-proxy
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

**pdb.yaml (Pod Disruption Budget):**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: s3-encryption-proxy
  namespace: s3-encryption-proxy
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: s3-encryption-proxy
```

### Deploy to Kubernetes

```bash
# Create namespace and secrets
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml

# Deploy application
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml

# For high availability
kubectl apply -f hpa.yaml
kubectl apply -f pdb.yaml

# Check deployment status
kubectl get pods -n s3-encryption-proxy
kubectl get svc -n s3-encryption-proxy
kubectl logs -f deployment/s3-encryption-proxy -n s3-encryption-proxy
```

## Cloud Provider Deployments

### AWS ECS

**task-definition.json:**
```json
{
  "family": "s3-encryption-proxy",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::123456789012:role/s3EncryptionProxyTaskRole",
  "containerDefinitions": [
    {
      "name": "s3-encryption-proxy",
      "image": "ghcr.io/guided-traffic/s3-encryption-proxy:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "S3EP_TARGET_ENDPOINT",
          "value": "https://s3.amazonaws.com"
        },
        {
          "name": "S3EP_REGION",
          "value": "us-east-1"
        },
        {
          "name": "S3EP_ENCRYPTION_TYPE",
          "value": "tink"
        }
      ],
      "secrets": [
        {
          "name": "S3EP_ACCESS_KEY_ID",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:s3-encryption-proxy/aws-credentials:access-key-id::"
        },
        {
          "name": "S3EP_SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:s3-encryption-proxy/aws-credentials:secret-access-key::"
        },
        {
          "name": "S3EP_KEK_URI",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:s3-encryption-proxy/kms:kek-uri::"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/s3-encryption-proxy",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8080/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Google Cloud Run

**cloudbuild.yaml:**
```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['pull', 'ghcr.io/guided-traffic/s3-encryption-proxy:latest']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['tag', 'ghcr.io/guided-traffic/s3-encryption-proxy:latest', 'gcr.io/$PROJECT_ID/s3-encryption-proxy:latest']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/s3-encryption-proxy:latest']
  - name: 'gcr.io/cloud-builders/gcloud'
    args:
      - 'run'
      - 'deploy'
      - 's3-encryption-proxy'
      - '--image=gcr.io/$PROJECT_ID/s3-encryption-proxy:latest'
      - '--region=us-central1'
      - '--platform=managed'
      - '--allow-unauthenticated'
      - '--set-env-vars=S3EP_TARGET_ENDPOINT=https://s3.amazonaws.com,S3EP_REGION=us-east-1,S3EP_ENCRYPTION_TYPE=tink'
      - '--set-secrets=S3EP_ACCESS_KEY_ID=aws-access-key-id:latest,S3EP_SECRET_KEY=aws-secret-key:latest,S3EP_KEK_URI=gcp-kek-uri:latest'
```

### Azure Container Instances

**container-group.yaml:**
```yaml
apiVersion: 2019-12-01
location: eastus
name: s3-encryption-proxy
properties:
  containers:
  - name: s3-encryption-proxy
    properties:
      image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
      ports:
      - port: 8080
        protocol: TCP
      environmentVariables:
      - name: S3EP_TARGET_ENDPOINT
        value: https://s3.amazonaws.com
      - name: S3EP_REGION
        value: us-east-1
      - name: S3EP_ENCRYPTION_TYPE
        value: tink
      - name: S3EP_ACCESS_KEY_ID
        secureValue: <aws-access-key-id>
      - name: S3EP_SECRET_KEY
        secureValue: <aws-secret-key>
      - name: S3EP_KEK_URI
        secureValue: <gcp-kek-uri>
      resources:
        requests:
          cpu: 0.5
          memoryInGB: 1
  osType: Linux
  ipAddress:
    type: Public
    ports:
    - port: 8080
      protocol: TCP
  restartPolicy: Always
type: Microsoft.ContainerInstance/containerGroups
```

## Load Balancer Configuration

### NGINX

**nginx.conf:**
```nginx
upstream s3_encryption_proxy {
    least_conn;
    server 10.0.1.10:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    listen [::]:80;
    server_name s3-proxy.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name s3-proxy.yourdomain.com;

    ssl_certificate /etc/ssl/certs/s3-proxy.crt;
    ssl_certificate_key /etc/ssl/private/s3-proxy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    client_max_body_size 0;
    client_body_timeout 300s;
    client_header_timeout 300s;

    location / {
        proxy_pass http://s3_encryption_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 30s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;

        proxy_buffering off;
        proxy_request_buffering off;
    }

    location /health {
        proxy_pass http://s3_encryption_proxy/health;
        access_log off;
    }
}
```

### HAProxy

**haproxy.cfg:**
```
global
    daemon
    log 127.0.0.1:514 local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    timeout connect 5s
    timeout client 300s
    timeout server 300s

frontend s3_encryption_proxy_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/s3-proxy.pem
    redirect scheme https if !{ ssl_fc }
    default_backend s3_encryption_proxy_backend

backend s3_encryption_proxy_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server proxy1 10.0.1.10:8080 check inter 10s fall 3 rise 2
    server proxy2 10.0.1.11:8080 check inter 10s fall 3 rise 2
    server proxy3 10.0.1.12:8080 check inter 10s fall 3 rise 2
```

## Monitoring and Observability

### Health Checks

The proxy provides health check endpoints:

- `GET /health` - Overall health status
- `GET /ready` - Readiness for traffic

### Prometheus Metrics

Add Prometheus monitoring:

```yaml
# prometheus-config.yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 's3-encryption-proxy'
    static_configs:
      - targets: ['s3-encryption-proxy:8080']
    metrics_path: /metrics
    scrape_interval: 30s
```

### Logging

Configure structured logging:

```yaml
# In your config.yaml
log_level: "info"
log_format: "json"  # or "text"
```

## Security Considerations

### Network Security

- **TLS Termination**: Always use HTTPS in production
- **VPC/Private Networks**: Deploy in private subnets
- **Security Groups**: Restrict access to necessary ports
- **WAF**: Consider Web Application Firewall

### Container Security

- **Non-root User**: Containers run as non-root user (UID 1000)
- **Read-only Filesystem**: Use read-only root filesystem
- **Security Contexts**: Apply proper Kubernetes security contexts
- **Image Scanning**: Regularly scan container images

### Secret Management

- **Never in Environment Variables**: Use proper secret management
- **Kubernetes Secrets**: For K8s deployments
- **AWS Secrets Manager**: For AWS deployments
- **GCP Secret Manager**: For GCP deployments
- **Azure Key Vault**: For Azure deployments

## Troubleshooting

### Common Issues

**Connection refused:**
```bash
# Check if service is running
kubectl get pods -n s3-encryption-proxy

# Check logs
kubectl logs -f deployment/s3-encryption-proxy -n s3-encryption-proxy
```

**TLS certificate issues:**
```bash
# Verify certificate
openssl s_client -connect s3-proxy.yourdomain.com:443

# Check certificate expiry
echo | openssl s_client -connect s3-proxy.yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates
```

**Performance issues:**
```bash
# Check resource usage
kubectl top pods -n s3-encryption-proxy

# Scale up if needed
kubectl scale deployment s3-encryption-proxy --replicas=5 -n s3-encryption-proxy
```

### Deployment Validation

**Test the deployment:**
```bash
# Basic connectivity
curl -I http://your-proxy-url/health

# S3 API test
aws s3 --endpoint-url http://your-proxy-url ls s3://your-bucket/
```

For more troubleshooting information, see [Troubleshooting Guide](./troubleshooting.md).
