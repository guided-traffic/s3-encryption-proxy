# Config

> God node · 73 connections · `internal/config/config.go`

**Community:** [Configuration Accessors](Configuration_Accessors.md)

## Connections by Relation

### contains
- config.go `EXTRACTED`

### method
- .GetActiveProvider() `EXTRACTED`
- .GetAllProviders() `EXTRACTED`
- .GetProviderByAlias() `EXTRACTED`
- .GetS3SecurityConfig() `EXTRACTED`
- .ValidateS3ClientCredentials() `EXTRACTED`
- .IsS3ClientAuthEnabled() `EXTRACTED`
- .GetStreamingSegmentSize() `EXTRACTED`
- .GetStreamingThreshold() `EXTRACTED`
- .GetStreamingBufferSize() `EXTRACTED`

### references
- [Manager](Manager.md) `EXTRACTED`
- NewParser() `EXTRACTED`
- createTestMultipartOperations() `EXTRACTED`
- OrcPartAESConfig() `EXTRACTED`
- createTestMultipartConfig() `EXTRACTED`
- NewMetadataManager() `EXTRACTED`
- NewHandler() `EXTRACTED`
- Parser `EXTRACTED`
- ProviderManager `EXTRACTED`
- NewManager() `EXTRACTED`
- OrcPartNewMultipartOps() `EXTRACTED`
- MetadataManager `EXTRACTED`
- MultipartOperations `EXTRACTED`
- OrcMgrNewManager() `EXTRACTED`
- OrcMgrAESConfig() `EXTRACTED`
- NewServer() `EXTRACTED`
- Load() `EXTRACTED`
- NewProviderManager() `EXTRACTED`
- OrcPartNewManager() `EXTRACTED`
- OrcMetaConfig() `EXTRACTED`
- *…and 43 more `references` connection(s) not listed (lowest-degree first to go)*

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*