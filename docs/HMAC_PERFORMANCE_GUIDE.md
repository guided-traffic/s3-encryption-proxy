# HMAC Performance Optimization Guide

## Overview

This guide covers performance optimization strategies for HMAC integrity verification in S3 Encryption Proxy v2.x. The smart HMAC policy feature provides significant performance improvements while maintaining security standards.

## Performance Results Summary

### Before Optimization (Always HMAC)
- **Small Files (1MB AES-GCM)**: 723 MB/s encrypt, 1063 MB/s decrypt
- **Large Files (100MB AES-CTR)**: ~1300 MB/s with HMAC overhead

### After Optimization (Smart HMAC Policy)
- **Small Files (1MB AES-GCM)**: 1521 MB/s encrypt (+110%), 2030 MB/s decrypt (+91%)
- **Large Files (100MB AES-CTR)**: 5200+ MB/s without HMAC, 1400 MB/s with HMAC
- **Memory Efficiency**: <50% of data size, 0.05ms average GC pause

## HMAC Policy Options

### 1. `auto` Policy (RECOMMENDED)
**Best balance of security and performance**

```yaml
encryption:
  integrity_verification: true
  hmac_policy: "auto"
```

**Behavior:**
- **AES-GCM (small files)**: Skip HMAC (authenticated encryption redundant)
- **AES-CTR (large files)**: Use HMAC (encryption-only, needs integrity)

**Performance Impact:**
- Small files: **+100% improvement** (eliminates redundant HMAC)
- Large files: Selective HMAC only where needed
- Memory: Optimal usage, minimal GC pressure

**Use Cases:**
- Production environments requiring integrity verification
- Mixed workloads (small and large files)
- Performance-critical applications

### 2. `always` Policy
**Maximum security, performance cost**

```yaml
encryption:
  integrity_verification: true
  hmac_policy: "always"
```

**Behavior:**
- All files get HMAC regardless of encryption algorithm
- Redundant for AES-GCM but provides double verification

**Performance Impact:**
- Small files: 44% encryption overhead, 157% decryption overhead
- Large files: ~275% HMAC overhead
- Memory: Higher allocation due to parallel HMAC calculation

**Use Cases:**
- Ultra-high security requirements
- Regulatory compliance requiring double verification
- Environments where performance is secondary to security

### 3. `never` Policy
**Maximum performance, security risk**

```yaml
encryption:
  integrity_verification: true  # Still enabled for config compatibility
  hmac_policy: "never"
```

**Behavior:**
- No HMAC calculation for any files
- Relies solely on underlying encryption authentication

**Performance Impact:**
- Small files: Same as `auto` (AES-GCM authenticated)
- Large files: **5200+ MB/s** (no HMAC overhead)
- Memory: Minimal allocation, fastest GC

**Use Cases:**
- Maximum performance scenarios
- Trusted environments with other integrity mechanisms
- Testing and development (not recommended for production)

## Configuration Examples

### Production Deployment
```yaml
encryption:
  encryption_method_alias: "production-aes"
  integrity_verification: true
  hmac_policy: "auto"  # Smart optimization
  metadata_key_prefix: "s3ep-"

optimizations:
  streaming_segment_size: 16777216  # 16MB
  buffer_pool_size: 64
  max_buffer_size: 33554432  # 32MB

monitoring:
  hmac_metrics_enabled: true
  hmac_policy_logging: true
```

### High-Performance Deployment
```yaml
encryption:
  integrity_verification: true
  hmac_policy: "never"  # Maximum speed

optimizations:
  streaming_segment_size: 33554432  # 32MB
  buffer_pool_size: 128
  max_buffer_size: 67108864  # 64MB
```

### High-Security Deployment
```yaml
encryption:
  integrity_verification: true
  hmac_policy: "always"  # Double verification

monitoring:
  level: "debug"  # Log all HMAC decisions
  hmac_policy_logging: true
```

## Performance Tuning Guidelines

### 1. Content Type Optimization
The system automatically selects encryption algorithms based on file size:

- **< 50MB**: Uses `ContentTypeWhole` → AES-GCM
- **≥ 50MB**: Uses `ContentTypeMultipart` → AES-CTR

**Tuning Options:**
```go
// Force specific encryption mode via Content-Type headers
Content-Type: application/x-s3ep-force-aes-gcm  // Force AES-GCM
Content-Type: application/x-s3ep-force-aes-ctr  // Force AES-CTR
```

### 2. Streaming Configuration
Optimize for your workload patterns:

```yaml
optimizations:
  # Small files (< 10MB): Use smaller segments
  streaming_segment_size: 5242880   # 5MB

  # Large files (> 100MB): Use larger segments
  streaming_segment_size: 33554432  # 32MB

  # Very large files (> 1GB): Maximum segments
  streaming_segment_size: 67108864  # 64MB (max recommended)
```

### 3. Memory Optimization
Configure buffer pools for your memory constraints:

```yaml
optimizations:
  # Low memory environments
  buffer_pool_size: 32
  max_buffer_size: 16777216  # 16MB

  # High memory environments
  buffer_pool_size: 256
  max_buffer_size: 134217728  # 128MB
```

## Monitoring and Observability

### Key Metrics to Monitor

1. **HMAC Policy Decisions**
   ```promql
   s3ep_hmac_policy_decisions_total{policy="auto",decision="skipped"}
   s3ep_hmac_policy_decisions_total{policy="auto",decision="enabled"}
   ```

2. **HMAC Performance**
   ```promql
   histogram_quantile(0.95, s3ep_hmac_performance_seconds)
   histogram_quantile(0.99, s3ep_hmac_throughput_mbps)
   ```

3. **Overall Throughput**
   ```promql
   rate(s3ep_bytes_transferred_total[5m])
   ```

### Performance Alerts
```yaml
groups:
  - name: s3ep_performance
    rules:
      - alert: HMACPerformanceDegraded
        expr: histogram_quantile(0.95, s3ep_hmac_throughput_mbps) < 500
        labels:
          severity: warning
        annotations:
          summary: "HMAC throughput below 500 MB/s"

      - alert: PolicyDecisionImbalance
        expr: |
          (
            rate(s3ep_hmac_policy_decisions_total{decision="skipped"}[5m]) /
            rate(s3ep_hmac_policy_decisions_total[5m])
          ) < 0.3
        labels:
          severity: info
        annotations:
          summary: "Less than 30% of operations optimized by auto policy"
```

## Troubleshooting

### Common Performance Issues

1. **Low Throughput with `auto` Policy**
   - Check content type distribution in logs
   - Verify streaming segment size matches workload
   - Monitor memory allocation patterns

2. **High Memory Usage**
   - Reduce buffer pool size
   - Lower streaming segment size
   - Check for memory leaks in long-running operations

3. **HMAC Policy Not Working**
   - Enable debug logging: `log_level: "debug"`
   - Check `hmac_policy_logging: true` in config
   - Verify content type detection in logs

### Debug Commands
```bash
# Check HMAC policy decisions
grep "HMAC-enabled\|skip_reason" /var/log/s3ep/app.log

# Monitor real-time throughput
curl -s http://localhost:9090/metrics | grep s3ep_hmac_throughput

# Memory usage analysis
go tool pprof http://localhost:6060/debug/pprof/heap
```

## Migration Guide

### From v1.x to v2.x with HMAC
1. **Enable smart policy gradually**:
   ```yaml
   # Start with always (existing behavior)
   hmac_policy: "always"

   # Monitor performance metrics
   # Switch to auto after validation
   hmac_policy: "auto"
   ```

2. **Monitor backward compatibility**:
   - Legacy objects without HMAC are handled gracefully
   - Logs show "backward compatibility" warnings
   - No service interruption during migration

3. **Performance validation**:
   - Run `TestHMACPerformanceSummary` before deployment
   - Compare throughput metrics pre/post migration
   - Validate memory usage patterns

## Best Practices Summary

1. ✅ **Use `auto` policy** for production deployments
2. ✅ **Monitor HMAC metrics** to validate optimization
3. ✅ **Tune streaming segment size** for your workload
4. ✅ **Enable performance logging** during initial deployment
5. ✅ **Test with realistic data sizes** before production
6. ✅ **Plan memory allocation** based on concurrent operations
7. ✅ **Set up alerts** for performance degradation
8. ✅ **Document your specific optimizations** for team knowledge

The smart HMAC policy provides a **+100% performance improvement** for small files while maintaining full security for streaming scenarios. This optimization is production-ready and backward-compatible.
