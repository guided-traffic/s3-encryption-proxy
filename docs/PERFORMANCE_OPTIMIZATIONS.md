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

  # Enable adaptive buffering based on system load (experimental)
  # When enabled, buffer sizes adjust dynamically
  enable_adaptive_buffering: false

  # Thresholds for processing strategy selection (when adaptive buffering is enabled)
  # Files smaller than force_traditional_threshold use traditional processing
  force_traditional_threshold: 1048576  # 1MB

  # Files larger than streaming_threshold always use streaming
  streaming_threshold: 5242880  # 5MB
```

## Buffer Size Configuration

### streaming_buffer_size

Controls the size of buffers used during streaming encryption/decryption operations.

- **Range**: 4KB (4,096 bytes) to 2MB (2,097,152 bytes)
- **Default**: 64KB (65,536 bytes)
- **Impact**:
  - **Larger buffers**: Better throughput for large files, increased memory usage
  - **Smaller buffers**: Lower memory footprint, more CPU overhead due to frequent read/write operations

### Recommended Settings by Environment

#### Memory-Constrained Environments
```yaml
optimizations:
  streaming_buffer_size: 8192  # 8KB - minimal memory usage
```

#### High-Throughput Environments
```yaml
optimizations:
  streaming_buffer_size: 1048576  # 1MB - maximum throughput
```

#### Balanced Production Environment
```yaml
optimizations:
  streaming_buffer_size: 65536  # 64KB - balanced performance (default)
```

## Adaptive Buffering (Experimental)

### enable_adaptive_buffering

When enabled, the proxy will automatically choose between traditional and streaming processing based on file size thresholds.

- **Default**: `false` (disabled)
- **Note**: This feature is experimental and may change in future versions

### Threshold Configuration

When adaptive buffering is enabled, you can configure the thresholds that determine processing strategy:

#### force_traditional_threshold
- **Default**: 1MB (1,048,576 bytes)
- **Purpose**: Files smaller than this size will always use traditional (in-memory) processing
- **Minimum**: 1MB

#### streaming_threshold
- **Default**: 5MB (5,242,880 bytes)
- **Purpose**: Files larger than this size will always use streaming processing
- **Minimum**: 5MB
- **Constraint**: Must be larger than `force_traditional_threshold`

## Performance Tuning Guidelines

### For Small Files (< 1MB)
- Traditional processing is more efficient
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
2. **Threshold Relationship**: `force_traditional_threshold` must be less than `streaming_threshold`
3. **Minimum Thresholds**: Traditional threshold ≥ 1MB, Streaming threshold ≥ 5MB

## Example Configurations

### High-Performance Server
```yaml
optimizations:
  streaming_buffer_size: 1048576  # 1MB buffers
  enable_adaptive_buffering: true
  force_traditional_threshold: 1048576  # 1MB
  streaming_threshold: 5242880  # 5MB
```

### Memory-Constrained Container
```yaml
optimizations:
  streaming_buffer_size: 16384  # 16KB buffers
  enable_adaptive_buffering: false
```

### Development Environment
```yaml
optimizations:
  streaming_buffer_size: 32768  # 32KB buffers
  enable_adaptive_buffering: false
```

## Migration from Previous Versions

If upgrading from a version without optimization configuration:

1. **No Action Required**: The proxy will use default values (64KB buffer)
2. **Optional Tuning**: Add `optimizations` section to your configuration file
3. **Backward Compatibility**: All existing configurations continue to work unchanged

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
