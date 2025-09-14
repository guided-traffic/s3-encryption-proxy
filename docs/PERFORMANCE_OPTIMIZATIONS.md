# Performance Optimizations Configuration

The S3 Encryption Proxy now supports configurable performance optimizations to fine-tune buffer sizes and processing strategies for different deployment scenarios.

## Configuration Options

### optimizations

The `optimizations` section in the configuration file allows you to customize performance-related settings:

```yaml
optimizations:
  # Streaming buffer size for chunk-wise processing (4KB - 2MB)
  # Default: 64KB (65536 bytes)
  # Higher values: Better throughput for large files, more memory usage
  # Lower values: Better for memory-constrained environments, more CPU overhead
  streaming_buffer_size: 65536  # 64KB

  # Streaming segment size for multipart uploads (5MB - 5GB)
  # Default: 12MB (12582912 bytes)
  # This defines how much data is collected before sending as one S3 upload part
  streaming_segment_size: 12582912  # 12MB

  # Enable adaptive buffering based on system load (experimental)
  # When enabled, buffer sizes adjust dynamically
  enable_adaptive_buffering: false

  # Processing strategy threshold
  # Files larger than streaming_threshold use streaming uploads (AES-CTR for multipart)
  # Files smaller than streaming_threshold use direct encryption (AES-GCM for whole files)
  streaming_threshold: 1048576  # 1MB
```

## Configuration Options

### streaming_buffer_size

Controls the size of buffers used during streaming encryption/decryption operations.

- **Range**: 4KB (4,096 bytes) to 2MB (2,097,152 bytes)
- **Default**: 64KB (65,536 bytes)
- **Impact**:
  - **Larger buffers**: Better throughput for large files, increased memory usage
  - **Smaller buffers**: Lower memory footprint, more CPU overhead due to frequent read/write operations

### streaming_segment_size

Controls the size of segments for multipart uploads. Data is collected until this size is reached, then sent as one S3 upload part.

- **Range**: 5MB (5,242,880 bytes) to 5GB (5,368,709,120 bytes)
- **Default**: 12MB (12,582,912 bytes)
- **S3 Requirements**: Minimum 5MB per part (except last part), maximum 5GB per part
- **Impact**:
  - **Larger segments**: Fewer API calls, better efficiency for very large files, more memory usage
  - **Smaller segments**: More frequent uploads, better for slow connections, faster error recovery

## Recommended Settings by Environment#### Memory-Constrained Environments
```yaml
optimizations:
  streaming_buffer_size: 8192      # 8KB - minimal memory usage
  streaming_segment_size: 5242880  # 5MB - minimum allowed segment size
```

#### High-Throughput Environments
```yaml
optimizations:
  streaming_buffer_size: 1048576    # 1MB - maximum throughput
  streaming_segment_size: 104857600 # 100MB - fewer API calls for large files
```

#### Balanced Production Environment
```yaml
optimizations:
  streaming_buffer_size: 65536     # 64KB - balanced performance (default)
  streaming_segment_size: 12582912 # 12MB - balanced segment size (default)
```

#### Slow Network Connections
```yaml
optimizations:
  streaming_buffer_size: 32768     # 32KB - smaller buffers
  streaming_segment_size: 5242880  # 5MB - faster error recovery
```

## Adaptive Buffering (Experimental)

### enable_adaptive_buffering

When enabled, the proxy will automatically choose between traditional and streaming processing based on file size thresholds.

- **Default**: `false` (disabled)
- **Note**: This feature is experimental and may change in future versions

### Threshold Configuration

When adaptive buffering is enabled, you can configure the threshold that determines processing strategy:

#### streaming_threshold
- **Default**: 1MB (1,048,576 bytes)
- **Purpose**: Files larger than this size use streaming processing (AES-CTR multipart), files smaller use direct encryption (AES-GCM whole file)
- **Minimum**: 1MB

## Performance Tuning Guidelines

### For Small Files (< streaming_threshold)
- Direct encryption with AES-GCM is more efficient
- Buffer size has minimal impact
- Consider reducing `streaming_buffer_size` to save memory

### For Large Files (> 5MB)
- Streaming processing is required for multipart uploads
- Larger `streaming_buffer_size` improves throughput
- Consider increasing to 256KB or 1MB for maximum performance

### For Mixed Workloads
- Use default settings (64KB buffer)
- Consider enabling adaptive buffering for automatic optimization
- Monitor memory usage and adjust accordingly

## Validation Rules

The configuration system validates optimization settings:

1. **Buffer Size**: Must be between 4KB and 2MB
2. **Segment Size**: Must be between 5MB and 5GB (S3 multipart upload requirements)
3. **Streaming Threshold**: Must be at least 1MB

## Example Configurations

### High-Performance Server
```yaml
optimizations:
  streaming_buffer_size: 1048576    # 1MB buffers
  streaming_segment_size: 52428800  # 50MB segments
  enable_adaptive_buffering: true
  streaming_threshold: 2097152  # 2MB threshold
```

### Memory-Constrained Container
```yaml
optimizations:
  streaming_buffer_size: 16384     # 16KB buffers
  streaming_segment_size: 5242880  # 5MB segments (minimum)
  enable_adaptive_buffering: false
  streaming_threshold: 1048576     # 1MB threshold (minimum)
```

### Development Environment
```yaml
optimizations:
  streaming_buffer_size: 32768     # 32KB buffers
  streaming_segment_size: 12582912 # 12MB segments (default)
  enable_adaptive_buffering: false
```

## Configuration Migration

### streaming.segment_size → optimizations.streaming_segment_size

**Previous Configuration (no longer supported):**
```yaml
streaming:
  segment_size: 12582912  # 12MB - REMOVED
```

**Current Configuration:**
```yaml
optimizations:
  streaming_segment_size: 12582912  # 12MB
```

**Migration Required**: All `streaming.segment_size` configurations must be moved to `optimizations.streaming_segment_size`.

## Monitoring and Troubleshooting

### Performance Monitoring
- Enable debug logging to see buffer allocation details
- Monitor memory usage patterns with different buffer sizes
- Measure throughput with various configurations

### Common Issues
- **High Memory Usage**: Reduce `streaming_buffer_size`
- **Low Throughput**: Increase `streaming_buffer_size`
- **Configuration Errors**: Check validation rules and constraints

### Debug Logging
```yaml
log_level: "debug"
```

This will show detailed information about buffer allocation and optimization decisions.
