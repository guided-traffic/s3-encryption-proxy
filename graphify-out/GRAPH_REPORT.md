# Graph Report - s3-encryption-proxy  (2026-09-10)

## Corpus Check
- Large corpus: 383 files · ~535,722 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 4013 nodes · 11662 edges · 206 communities (150 shown, 50 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 1451 edges (avg confidence: 0.85)
- Token cost: 884,039 input · 0 output

## Community Hubs (Navigation)
- Object GET Handler Tests
- Performance Harness
- Velero E2E Suite
- Request Parser Tests
- Bucket Handler Tests
- Multipart Handler Tests
- Proxy Server Tests
- Handler Test Helpers
- Bucket Sub-Resource Handlers
- Authentication and Response ADRs
- Provider Manager
- Config Env Expansion
- Object PUT Handler Tests
- Object Dispatch and Metadata Tests
- Developer Docs: Errors and Format
- Performance Ticket Baseline
- AES KEK Provider
- Segment Codec Tests
- Key Management ADRs
- Mock Backend Helpers
- Renovate Configuration
- Multipart Handler
- Bucket Handler Routing
- Performance Tier Baselines
- Performance Measurement Docs
- Handler Fixture Helpers
- Backend Error Mapping
- Demo and Performance Scripts
- Encryption-at-Rest Integration Tests
- Deployment Compose and Helm
- Bucket Sub-Resource Tests
- ListObjects Conformance Tests
- Object Sub-Resource Refusals
- Config Loading Tests
- Forward-or-Refuse ADRs
- Test Strategy Docs
- 360-Degree Singlepart Tests
- Config Structure
- DeleteObjects Batch Tests
- Multipart Conformance Tests
- Router and Middleware Setup
- Provider Mode Integration Tests
- Bucket NotImplemented Tests
- Multipart Handler Unit Tests
- Object Operations Handler
- License Tool CLI
- Upload Deficit Investigation
- Segmented Orchestration Tests
- XML Response Helpers
- Operator Documentation
- DeleteObjects Handler Tests
- Exit Provider ADRs
- Coverage and Surface Tickets
- Monitoring Server
- ListBuckets Handler Tests
- Chunked Upload Tests
- Copy Benchmarks
- Codec Streaming IO
- SigV4 Authentication Tests
- Health Handler
- Orchestration Manager
- Object Helper Functions
- Segment Codec Core
- License Logging
- License Validator Tests
- Error Response Tests
- NPM Release Tooling
- 360-Degree Multipart Tests
- Release Workflow
- Open Ticket Backlog
- MinIO Test Helper
- Monitoring Middleware
- Metrics and Main Entry
- HTTP Middleware Tests
- Velero E2E Environment
- Object Header Conformance
- Multipart Session Table
- SigV4 Signing Helper
- Multipart XML Documents
- Security Architecture Docs
- Object Handler Dispatch
- Range Conformance Tests
- CI and Helm Security
- Filename Encryption ADR
- Storage Format Ticket
- Bucket ACL Tests
- License Types
- Metadata Manager
- Metadata Manager Tests
- Segment Tamper Tests
- Authentication Integration Tests
- SigV4 Header Authentication
- Pre-Signed URL Authentication
- Encryption Validation Helper
- Bucket CRUD Tests
- Object Listing
- Performance Findings Round 1
- Upload Checksum Ticket
- Performance Benchmarks
- Config Validation Tests
- SigV4 Coverage Tests
- Ticket Lifecycle ADR
- Filename Encryption Ticket
- CORS Middleware
- Exit Provider Readback Tests
- Passthrough Operation Tests
- Range Reader
- Finding Label Index
- Response Writer Hijacking
- pprof Listener
- Helm Install Script
- Request Tracking Middleware
- Conditional Request Tests
- Breaking Change Guard
- Helm Chart Fixes Ticket
- KMS and Vault Ticket
- Segmented Object Entry Points
- Provider Selection Tests
- Sealed Part Arithmetic
- Part Codec Tests
- Bucket CORS Handler
- Documentation Conventions
- Request Flow Documentation
- Dead Configuration Findings
- License Loading
- License Validation
- Logging Middleware
- Hostile Backend Decisions
- ListBuckets Root Handler Tests
- Backend SDK Client Options
- Bucket Replication Handler
- Bucket Website Handler
- Ranged Read Hardening
- Large Multipart Tests
- Bucket ACL Handler
- Secret Exposure Surface
- Coverage Summary Script
- Bucket Notification Handler
- Bucket Versioning Handler
- Performance Baseline Suite
- Baseline Comparison Script
- Bucket Logging Handler
- Listing XML Documents
- Mock: CreateBucket
- Mock: DeleteBucket
- Mock: DeleteBucketCors
- Mock: DeleteBucketLifecycle
- Mock: DeleteBucketPolicy
- Mock: DeleteBucketTagging
- Mock: DeleteObject
- Mock: DeleteObjects
- Mock: GetBucketAccelerate
- Mock: GetBucketAcl
- Mock: GetBucketCors
- Mock: GetBucketLifecycle
- Mock: GetBucketNotification
- Mock: GetBucketPolicy
- Mock: GetBucketReplication
- Mock: GetBucketRequestPayment
- Mock: GetBucketTagging
- Mock: GetBucketVersioning
- Mock: GetBucketWebsite
- Mock: GetObject
- Mock: GetObjectTorrent
- Mock: HeadObject
- Mock: ListBuckets
- Mock: ListObjects
- Mock: ListObjectsV2
- Mock: PutBucketAcl
- Mock: PutBucketLifecycle
- Mock: PutBucketLogging
- Mock: PutBucketNotification
- Mock: PutBucketTagging
- Mock: PutObject
- Mock: UploadPart
- DEK Cache Staleness Ticket
- Breaking Change Detector
- Object Tagging Handler
- E2E Bring-Up Script
- Bucket Policy Tests
- Bucket Routing Tests
- Storage Format Decisions
- Checksum and Trailer Decisions
- AWS-Chunked Decoder
- License Runtime Monitor
- ListBuckets XML Types
- Middleware Flusher Fallback
- Monitoring Flusher Fallback
- Streaming Performance Test
- Client Identity Context
- Semantic Release Config
- Renovate Failure Assignment
- golangci-lint Configuration
- Version Dry-Run Script
- Discard Response Writer
- E2E Teardown Script
- TLS Certificate Generation
- gosec Test Exclusions
- Changelog Entry
- Go Module Root

## God Nodes (most connected - your core abstractions)
1. `EnsureMinIOAndProxyAvailable()` - 88 edges
2. `NewErrorWriter()` - 76 edges
3. `NewTestContextWithTimeout()` - 71 edges
4. `MockS3Backend` - 64 edges
5. `MockS3Backend` - 64 edges
6. `NewXMLWriter()` - 61 edges
7. `Config` - 51 edges
8. `MpuNewEnv()` - 51 edges
9. `NewParser()` - 51 edges
10. `RandomString()` - 50 edges

## Surprising Connections (you probably didn't know these)
- `Production Values Profile` --semantically_similar_to--> `AES Example Configuration`  [INFERRED] [semantically similar]
  deploy/helm/s3-encryption-proxy/values-production.yaml → config/aes-example.yaml
- `A 1.7x That Was Nearly A 1.0x` --semantically_similar_to--> `Item 2.3 readAllSized Allocates Twice`  [INFERRED] [semantically similar]
  perf-baseline/20260909T212247Z-9f3fbd1/FINDINGS.md → docs/tickets/012-performance-audit-round2.md
- `Two Measurement Bugs Found Before The Run` --semantically_similar_to--> `Measure, Then Assert`  [INFERRED] [semantically similar]
  perf-baseline/20260909T175340Z-9f3fbd1/FINDINGS.md → docs/tickets/024-coverage-round-findings.md
- `Demo Proxy Service (HTTP, container proxy)` --semantically_similar_to--> `Proxy Deployment Template`  [INFERRED] [semantically similar]
  docker-compose.demo.yml → deploy/helm/s3-encryption-proxy/templates/deployment.yaml
- `Development Values Profile` --semantically_similar_to--> `MinIO Demo Backend Service`  [INFERRED] [semantically similar]
  deploy/helm/s3-encryption-proxy/values-development.yaml → docker-compose.demo.yml

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **A major release is declared, computed and cut** — _github_workflows_breaking_change_guard_guard, _github_workflows_breaking_change_guard_release_major_label, _github_workflows_breaking_change_guard_adr_0018, _github_workflows_version_dry_run_version_dry_run, _github_workflows_release_semantic_release, changelog_v4_0_0 [EXTRACTED 1.00]
- **Rendered Kubernetes Resource Set of the Chart** — deploy_helm_s3_encryption_proxy_chart_s3_encryption_proxy_chart, deploy_helm_s3_encryption_proxy_templates_deployment_deployment, deploy_helm_s3_encryption_proxy_templates_service_service, deploy_helm_s3_encryption_proxy_templates_configmap_configmap, deploy_helm_s3_encryption_proxy_templates_ingress_ingress, deploy_helm_s3_encryption_proxy_templates_certificate_certificate, deploy_helm_s3_encryption_proxy_templates_hpa_horizontalpodautoscaler, deploy_helm_s3_encryption_proxy_templates_networkpolicy_networkpolicy, deploy_helm_s3_encryption_proxy_templates_poddisruptionbudget_poddisruptionbudget, deploy_helm_s3_encryption_proxy_templates_service_monitoring_monitoring_service, deploy_helm_s3_encryption_proxy_templates_servicemonitor_servicemonitor, deploy_helm_s3_encryption_proxy_templates_grafana_dashboard_grafana_dashboard_configmap [EXTRACTED 1.00]
- **Local Demo Stack (start-demo.sh)** — docker_compose_demo_minio, docker_compose_demo_s3_encryption_proxy, docker_compose_demo_s3_encryption_proxy_tls, docker_compose_demo_proxy_healthcheck, docker_compose_demo_s3_explorer_encrypted, docker_compose_demo_vault [EXTRACTED 1.00]
- **Tier 1 Per-Read Hot-Path Fixes and Their Baseline Hotspots** — docs_tickets_010_performance_improvements_tier1_1_inplace_ctr_xor, docs_tickets_010_performance_improvements_tier1_2_remove_per_read_mutex, docs_tickets_010_performance_improvements_tier1_3_remove_per_read_logrus, docs_tickets_010_baseline_proxy_cpu_top20_memmove, docs_tickets_010_baseline_proxy_allocs_top20_ctr_encrypt_decrypt_part, docs_tickets_010_baseline_proxy_allocs_objects_top15_logrus_withfields [EXTRACTED 1.00]
- **Copy- and Allocation-Avoidance Campaign Across Upload and Download Paths** — docs_tickets_010_baseline_proxy_allocs_top20_io_readall, docs_tickets_010_baseline_proxy_allocs_top20_processpartordered, docs_tickets_010_performance_improvements_tier2_3_stream_to_responsewriter, docs_tickets_010_performance_improvements_tier2_5_eliminate_append_build, docs_tickets_010_performance_improvements_tier3_1_gcm_copy_avoidance, docs_tickets_010_performance_improvements_tier4_2_pooled_copybuffer [INFERRED 0.85]
- **Tier 2 optimization program (2.3 / 2.4 / 2.5 / 2.6) landing on the same 1 GB benchmark** — docs_tickets_010_tier2_readme_tier_2_3_gcm_get_readall_removal, docs_tickets_010_tier2_readme_tier_2_4_parallel_uploadpart, docs_tickets_010_tier2_readme_tier_2_5_append_elimination, docs_tickets_010_tier2_readme_tier_2_6_streaming_decryption_no_per_chunk_copy, docs_tickets_010_tier2_readme_tier2_snapshot [EXTRACTED 1.00]
- **Paired client/proxy pprof artifact set captured per tier (CPU, alloc_space, alloc_objects)** — docs_tickets_010_tier2_cpu_top20_client_cpu_profile, docs_tickets_010_tier2_mem_alloc_space_client_alloc_space_profile, docs_tickets_010_tier2_mem_alloc_objects_client_alloc_objects_profile, docs_tickets_010_tier2_proxy_cpu_top20_proxy_cpu_profile, docs_tickets_010_tier2_proxy_allocs_top20_proxy_alloc_space_profile, docs_tickets_010_tier2_proxy_allocs_objects_top15_proxy_alloc_objects_profile, docs_tickets_010_tier4_1_cpu_top20_client_cpu_profile, docs_tickets_010_tier4_1_mem_alloc_space_client_alloc_space_profile, docs_tickets_010_tier4_1_mem_alloc_objects_client_alloc_objects_profile, docs_tickets_010_tier4_1_proxy_cpu_top20_proxy_cpu_profile, docs_tickets_010_tier4_1_proxy_allocs_top20_proxy_alloc_space_profile, docs_tickets_010_tier4_1_proxy_allocs_objects_top15_proxy_alloc_objects_profile [EXTRACTED 1.00]
- **Upload-side body-collection alloc hotspot spanning ReadBody, aws-chunked decoding, io.ReadAll and the Tier 3.1 target** — docs_tickets_010_tier2_readme_io_readall_hotspot, docs_tickets_010_tier2_readme_awschunkeddecoder_requireschunkeddecoding, docs_tickets_010_tier4_1_proxy_allocs_top20_readbody_alloc_path, docs_tickets_010_tier2_readme_tier_3_1_upload_side_readall_target, docs_tickets_010_tier2_proxy_allocs_top20_upload_alloc_chain [INFERRED 0.85]
- **The Velero e2e kind stack** — test_e2e_velero_kind_config_cluster, test_e2e_velero_manifests_minio_backend, test_e2e_velero_manifests_proxy_nodeport_service, test_e2e_velero_manifests_snapshotclass_csi_hostpath, test_e2e_velero_values_proxy_values, test_e2e_velero_values_velero_values [EXTRACTED 1.00]
- **Leaving the Product: the Exit Provider Mode** — readme_exit_provider, config_exit_example_configuration, security_architecture_exit_provider_analysis, security_architecture_license_expiry_and_exit, security_architecture_h11_pass_through_closed, readme_license_startup_gate [INFERRED 0.85]
- **Jobs a Release Must Pass** — _github_workflows_release_malware_scan, _github_workflows_release_unit_tests_coverage, _github_workflows_release_gosec_scan, _github_workflows_release_govulncheck, _github_workflows_release_golangci_lint_v2_pin, _github_workflows_release_integration_tests, _github_workflows_release_combined_coverage_report, _github_workflows_release_e2e_velero_gate, _github_workflows_release_semantic_release [EXTRACTED 1.00]
- **Integrity as a Property of the Storage Format** — readme_storage_format_segment_chain, readme_foreign_object_refusal, readme_ranged_read_behaviour, security_architecture_failure_surface, security_architecture_h5_tampered_object_closed, security_architecture_h6_missing_metadata_closed, claude_integrity_is_not_configurable [INFERRED 0.85]
- **The Stored Object Format and Its Invariants** — docs_adr_0003_objects_are_an_authenticated_segment_chain_authenticated_segment_chain, docs_adr_0003_objects_are_an_authenticated_segment_chain_s3ep_gcm_seg_v2, docs_adr_0003_objects_are_an_authenticated_segment_chain_per_segment_random_nonce, docs_adr_0003_objects_are_an_authenticated_segment_chain_associated_data_binds_format_key_and_index, docs_adr_0003_objects_are_an_authenticated_segment_chain_authenticated_trailer, docs_adr_0003_objects_are_an_authenticated_segment_chain_sealed_crc32c_checksum, docs_adr_0002_one_data_key_per_object_one_data_key_per_object, docs_adr_0002_one_data_key_per_object_wrapped_dek_travels_with_the_object, docs_adr_0004_one_local_key_provider_authenticated_dek_wrap [EXTRACTED 1.00]
- **Refuse Rather Than Pretend: the Product's Honesty Rule** — docs_adr_0001_the_backend_is_hostile_a_control_that_exists_only_in_configuration, docs_adr_0007_forward_it_or_refuse_it_forward_it_or_refuse_it, docs_adr_0003_objects_are_an_authenticated_segment_chain_invalidobjectstate_refusal, docs_adr_0009_the_metadata_prefix_is_the_proxys_namespace_client_write_into_the_namespace_refused, docs_adr_0011_the_proxy_owns_the_part_layout_server_side_copy_refused, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_unworkable_configuration_refuses_to_start, docs_adr_0008_every_response_describes_the_proxy_every_failure_is_an_s3_error_document [INFERRED 0.85]
- **Reporting the Plaintext Size Without a Round Trip** — docs_adr_0003_objects_are_an_authenticated_segment_chain_plaintext_size_is_a_pure_function_of_stored_size, docs_adr_0010_sizes_and_listings_describe_the_plaintext_reported_size_is_the_plaintext_size, docs_adr_0010_sizes_and_listings_describe_the_plaintext_listing_size_by_arithmetic_no_round_trip, docs_adr_0010_sizes_and_listings_describe_the_plaintext_etag_describes_the_stored_bytes, docs_adr_0002_one_data_key_per_object_one_unwrap_per_read [INFERRED 0.85]
- **Decision, work list and developer page have separate lifetimes** — docs_adr_0022_tickets_are_work_lists_that_get_deleted_decisions_live_in_adrs, docs_adr_0022_tickets_are_work_lists_that_get_deleted_a_ticket_is_closed_by_deleting_it, docs_adr_0022_tickets_are_work_lists_that_get_deleted_adr_carries_no_code_references, docs_developer_readme_where_a_durable_insight_belongs [EXTRACTED 1.00]
- **The overlapped upload pipeline** — docs_adr_0024_an_upload_forwards_while_it_receives_upload_forwards_while_it_receives, docs_adr_0024_an_upload_forwards_while_it_receives_bounded_in_flight_memory, docs_developer_multipart_internal_producer, docs_developer_request_paths_route_on_the_plaintext_length, docs_developer_storage_format_parts_are_segment_aligned [INFERRED 0.85]
- **The exit provider across write, read and multipart** — docs_adr_0025_leaving_is_a_supported_mode_exit_provider, docs_adr_0025_leaving_is_a_supported_mode_the_decision_is_per_object, docs_developer_request_paths_exit_provider_pass_through_routing, docs_developer_multipart_exit_provider_has_no_session, docs_developer_storage_format_four_metadata_keys [EXTRACTED 1.00]
- **The 5.0.0 Release Bundle** — docs_tickets_023_major_v5_minimum_scope_table, docs_tickets_013_storage_format_v2_ticket, docs_tickets_014_upload_checksum_verification_ticket, docs_tickets_015_configuration_hygiene_ticket, docs_tickets_018_listobjectsv2_document_ticket, docs_tickets_022_s3_surface_fidelity_ticket [EXTRACTED 1.00]
- **The Upload Deficit Investigation** — perf_baseline_20260909t175340z_9f3fbd1_findings_upload_cliff_at_threshold, perf_baseline_20260910t062529z_9f3fbd1_findings_self_copy_is_not_the_cause, perf_baseline_20260910t062529z_9f3fbd1_findings_streaming_path_faster_than_backend, perf_baseline_20260910t090543z_530472c_findings_deficit_is_per_byte, docs_tickets_012_performance_audit_round2_item_2_0_auto_multipart_producer, docs_tickets_013_storage_format_v2_item_15_after_column [EXTRACTED 1.00]
- **The Silent Success Defect Family** — docs_tickets_022_s3_surface_fidelity_silent_200_defect_class, docs_tickets_readme_n_1_fail_open_pass_through_read, docs_tickets_readme_s_8_put_drops_storage_headers, docs_tickets_readme_p_7_listparts_fabricated, docs_tickets_024_coverage_round_findings_x_3_writexml_commits_before_marshal, docs_tickets_024_coverage_round_findings_h_7_residue_sub_resource_documents, docs_tickets_016_helm_chart_fixes_item_1_checksum_config_annotation [INFERRED 0.85]

## Communities (206 total, 50 thin omitted)

### Community 0 - "Object GET Handler Tests"
Cohesion: 0.06
Nodes (106): Handler, MockS3Backend, ObjGetdigest(), ObjGetdo(), ObjGetgetOutput(), ObjGetmutateMetadata(), ObjGetnewExitHandler(), ObjGetnewHandler() (+98 more)

### Community 1 - "Performance Harness"
Cohesion: 0.05
Nodes (82): crypto/cipher.AEAD, net/http.Client, strings.Builder, testing.M, GitInfo, Hardware, InstrumentStatus, leg (+74 more)

### Community 2 - "Velero E2E Suite"
Cohesion: 0.09
Nodes (80): time.Duration, backendClient(), caTrustingHTTPClient(), hasEncryptionMetadata(), listBackendObjects(), metadataValue(), proxyClient(), readBackendObject() (+72 more)

### Community 3 - "Request Parser Tests"
Cohesion: 0.05
Nodes (72): bytes.Reader, NewChunkedDecoderBase(), newChunkedRequest(), writeChunks(), newTestRequest(), ReqbuildHTTPChunked(), ReqnewTransferChunkedRequest(), TestReqHTTPChunkedDecoder_ImplementsInterface() (+64 more)

### Community 4 - "Bucket Handler Tests"
Cohesion: 0.07
Nodes (76): BktclosingBody, BktfailingReader, BktfailingWriter, BktforeignHits, errBkt, net/http.HandlerFunc, strings.Reader, BktassertIsListBucketResult() (+68 more)

### Community 5 - "Multipart Handler Tests"
Cohesion: 0.10
Nodes (65): MockS3Backend, MpuAPIError(), MpuChain(), MpuCompleteBody(), MpuDigest(), MpuNewEnv(), MpuNewEnvWithProvider(), MpuNewExitEnv() (+57 more)

### Community 6 - "Proxy Server Tests"
Cohesion: 0.06
Nodes (58): bytes.Buffer, net.Addr, backendClientOptions(), RtPxconfig(), RtPxnewFailingListener(), RtPxstringPtr(), TestRtPxHealthReportsShutdownState(), TestRtPxMetadataPrefixResolution() (+50 more)

### Community 7 - "Handler Test Helpers"
Cohesion: 0.04
Nodes (36): MockS3Backend, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectLegalHoldInput (+28 more)

### Community 8 - "Bucket Sub-Resource Handlers"
Cohesion: 0.06
Nodes (11): LifecycleHandler, LoggingHandler, NotificationHandler, ReplicationHandler, TaggingHandler, WebsiteHandler, net/http.Request, net/http.ResponseWriter (+3 more)

### Community 9 - "Authentication and Response ADRs"
Cohesion: 0.07
Nodes (65): ADR 0001: The S3 Backend Is Hostile, Out of Scope: Denial of Service, Client Leg, Host Compromise (D9), Rollback and Deletion Are Undefended by Construction, The Bucket Is Not in the Associated Data (D5), ADR 0005: A KMS-Backed KEK Is a Provider, Not a Mode, A KMS-Held KEK Is a Provider Type of Its Own (D1), Every KMS Call Carries an Explicit Timeout (D7), HashiCorp Vault Transit Is the First Backend (D4) (+57 more)

### Community 10 - "Provider Manager"
Cohesion: 0.07
Nodes (45): container/list.Element, container/list.List, sync/atomic.Int64, sync.RWMutex, buildDEKCacheKey(), OrcMetaAESProvider(), OrcMetaCachingManager(), OrcMetaNewProviderManager() (+37 more)

### Community 11 - "Config Env Expansion"
Cohesion: 0.06
Nodes (55): testing.T, TestCfgGetActiveProviderErrorPaths(), TestCfgGetActiveProviderReturnsLivePointer(), TestCfgGetAllProvidersReflectsSlice(), TestCfgIsValidProviderType(), TestCfgStreamingAccessors(), TestCfgExpandConfigEnvVarsErrorPerField(), TestCfgExpandConfigEnvVarsExpandsEveryField() (+47 more)

### Community 12 - "Object PUT Handler Tests"
Cohesion: 0.13
Nodes (58): github.com/stretchr/testify/mock.Call, Handler, MockS3Backend, ObjPutcapturePut(), ObjPutchunked(), ObjPutdigest(), ObjPutdo(), ObjPutdropCall() (+50 more)

### Community 13 - "Object Dispatch and Metadata Tests"
Cohesion: 0.08
Nodes (56): net/http/httptest.ResponseRecorder, TestObjMiscDeleteObjectsBackendErrorsAreMapped(), TestObjMiscDeleteObjectsBodyReadErrorIsRefused(), TestObjMiscDeleteObjectsEmptyBodyIsMalformed(), TestObjMiscDeleteObjectsMalformedXMLIsRefused(), TestObjMiscDeleteObjectsReadsTheWholeBodyUnbounded(), TestObjMiscDeleteObjectsWithoutMuxVars(), TestObjMiscDeletePathsDropEveryAWSRequestHeader() (+48 more)

### Community 14 - "Developer Docs: Errors and Format"
Cohesion: 0.06
Nodes (59): DEK Cache Keyed by a Digest of the Wrapped Key (D9), ADR 0003: Objects Are an Authenticated Segment Chain, AAD Binds Format ID, Object Key and Segment Index (D4), The Trailer Authenticates the Plaintext Length and Checksum (D6), Each Segment Carries Its Own Random 96-Bit Nonce (D3), Format Identifier s3ep-gcm-seg-v2, 65536-Byte Segment Is a Constant of the Format, Not Configuration (D2), The DEK Cache Is Load-Bearing for a KMS Provider (D10) (+51 more)

### Community 15 - "Performance Ticket Baseline"
Cohesion: 0.05
Nodes (59): Baseline Client CPU Top-20 Profile, Client v4 Chunked SHA-256 Signing Cost (28% CPU), Baseline Client alloc_objects Profile, Baseline Client alloc_space Profile, Client io.ReadAll of the 1 GB GET Body (2.56 GB, 71%), Baseline Proxy alloc_objects Top-15, decryptionReader.Read Object-Alloc Hotspot (16.2%, rank 2), logrus Entry.WithFields Object-Alloc Hotspot (23.0%, rank 1) (+51 more)

### Community 16 - "AES KEK Provider"
Cohesion: 0.07
Nodes (36): KeyEncryptionType, AESProvider, ExitProvider, FacFactoryWithAES(), TestFacCreateAESKeyEncryptorKEKPathMatchesBase64Path(), TestFacCreateKeyEncryptorFromConfigTypes(), TestFacGetKeyEncryptor(), TestFacKeyEncryptionTypeConstants() (+28 more)

### Community 17 - "Segment Codec Tests"
Cohesion: 0.09
Nodes (48): errAfterReader, errReader, CiphertextSize(), TestSegEncryptReaderChecksum(), TestSegEncryptReaderMatchesWriter(), TestSegEncryptReaderPropagatesSourceError(), TestSegEncryptReaderRoundTrip(), TestSegEncryptReaderStaysFailedAfterAnError() (+40 more)

### Community 18 - "Key Management ADRs"
Cohesion: 0.05
Nodes (51): Fail Closed on Foreign Objects (D5), ADR 0002: One Data Key per Object, Envelope Encryption: the KEK Wraps Data Keys Only (D2), The Key Layer Fails Closed (D11), Key Rotation Is a Configuration Procedure, Not an Operation (D7), A Read Performs at Most One Unwrap (D10), Provider Selection by s3ep-kek-fingerprint (D4, D5), The Key Encryption Key Is the Single Point of Total Loss (+43 more)

### Community 19 - "Mock Backend Helpers"
Cohesion: 0.08
Nodes (17): context.Context, github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketReplicationOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLoggingInput (+9 more)

### Community 20 - "Renovate Configuration"
Cohesion: 0.04
Nodes (46): :automergeDigest, config:recommended, :dependencyDashboard, docker:enableMajor, :semanticCommits, assignAutomerge, automerge, automergeType (+38 more)

### Community 21 - "Multipart Handler"
Cohesion: 0.15
Nodes (25): github.com/sirupsen/logrus.Entry, sync.WaitGroup, Manager, NewAbortHandler(), NewCompleteHandler(), NewCopyHandler(), NewHandler(), NewListHandler() (+17 more)

### Community 22 - "Bucket Handler Routing"
Cohesion: 0.08
Nodes (11): AccelerateHandler, BaseSubResourceHandler, LocationHandler, PolicyHandler, RequestPaymentHandler, VersioningHandler, ACLHandler, Handler (+3 more)

### Community 23 - "Performance Tier Baselines"
Cohesion: 0.06
Nodes (40): Tier 2 client CPU profile (performance-test.test, 23.97 s / 4.53 s samples), Client-side SHA-256 verification cost (crypto/sha256.Sum256, 17.88 % cum), Tier 2 client alloc_objects profile (204 319 objects, AWS SDK middleware dominated), Tier 2 client alloc_space profile (3.59 GB, io.ReadAll 71.29 % inside runPerformanceTest), performance-test runPerformanceTest (test harness allocating the 1 GB payload), Tier 2 proxy alloc_objects profile (465 597 objects, HTTP/TLS plumbing on top), Middleware chain alloc pass-through (gorilla/mux → monitoring.HTTPMiddleware → cors → logging → requestTracking → s3Auth, ~99.6 % cum), Tier 2 proxy alloc_space profile (10 007.86 MB total) (+32 more)

### Community 24 - "Performance Measurement Docs"
Cohesion: 0.07
Nodes (38): No environment switch disarms an assertion (D4), Absolute thresholds measure the runner, not the code, A performance change carries a before and an after (D1), A request-path benchmark is born with a direct leg (D12), GOMEMLIMIT is set explicitly, about 80% of the container limit (D15), The local baseline suite with its own build tag (D18), One machine-readable record and one human summary (D20), A run records the machine it ran on (D19) (+30 more)

### Community 25 - "Handler Fixture Helpers"
Cohesion: 0.08
Nodes (14): github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput, github.com/aws/aws-sdk-go-v2/service/s3.PutBucketCorsInput, github.com/aws/aws-sdk-go-v2/service/s3.PutBucketCorsOutput (+6 more)

### Community 26 - "Backend Error Mapping"
Cohesion: 0.12
Nodes (33): codeForStatus(), RespAPIErrorNoResponse(), RespStatusOnlyError(), RespWrapMarker(), TestRespMapErrorBackend5xxKeepsReasonPhrase(), TestRespMapErrorCodeForStatusFallback(), TestRespMapErrorCodeStatusTableMatchesAWS(), TestRespMapErrorEmptyCodeWithoutResponseStaysOpaque() (+25 more)

### Community 27 - "Demo and Performance Scripts"
Cohesion: 0.16
Nodes (32): build_project(), check_dependencies(), check_services(), cleanup(), generate_markdown_report(), get_iso_timestamp(), get_timestamp(), log_error() (+24 more)

### Community 28 - "Encryption-at-Rest Integration Tests"
Cohesion: 0.24
Nodes (33): github.com/aws/smithy-go/middleware.Stack, EncObjectView, EncStored, NewProxyTLSClient(), RandomString(), EncAPICode(), EncAssertBodyIsCiphertext(), EncAssertEncryptedAtRest() (+25 more)

### Community 29 - "Deployment Compose and Helm"
Cohesion: 0.08
Nodes (33): s3-encryption-proxy Helm Chart, cert-manager Certificate Template, Proxy ConfigMap Template, Proxy Deployment Template, License JWT Volume Mount, Grafana Dashboard ConfigMap Template, HorizontalPodAutoscaler Template, Ingress Template (+25 more)

### Community 30 - "Bucket Sub-Resource Tests"
Cohesion: 0.09
Nodes (29): TestHandleBucketCORS_GET_NoClient(), TestBucketLocationErrorHandling(), TestBucketLocationMethodHandling(), TestBucketLocationRegionMapping(), TestBucketLocationSecurityScenarios(), TestBucketLocationXMLFormat(), TestBucketLocationXMLValidation(), TestHandleBucketLocation_GET_NoClient() (+21 more)

### Community 31 - "ListObjects Conformance Tests"
Cohesion: 0.16
Nodes (31): github.com/aws/aws-sdk-go-v2/service/s3/types.CommonPrefix, github.com/aws/aws-sdk-go-v2/service/s3/types.Object, lstBulkFixture, lstRefFixture, lstAssertElementOrder(), lstBody(), lstBulkKeys(), lstChildElements() (+23 more)

### Community 32 - "Object Sub-Resource Refusals"
Cohesion: 0.16
Nodes (26): TestRangeReadErrors(), TestRangeReadsOnEncryptedObjects(), EnsureMinIOAndProxyAvailable(), TestContext, NewTestContextWithTimeout(), apiCodeOf(), apiMessageOf(), errorsAs() (+18 more)

### Community 33 - "Config Loading Tests"
Cohesion: 0.20
Nodes (30): InitConfig(), Load(), LoadAndStartLicense(), setDefaults(), TestLoad_MissingTargetEndpoint(), TestLoad_ValidExitConfig(), CfgNoLicense(), CfgResetViper() (+22 more)

### Community 34 - "Forward-or-Refuse ADRs"
Cohesion: 0.07
Nodes (31): A Control That Exists Only in Configuration Is Worse Than None (D6), What the Backend Learns Anyway (D8), All Three Write Paths Produce the Identical Byte Layout (D11), Compatibility Is Argued from S3 Semantics, Never from One Client (D2, D3), Support Is Claimed Only As Far As It Is Exercised (D7), A Refusal Says What Is True (D8), PUT ?acl and PUT ?cors Carry Their Document in Full (D5), ADR 0007: Forward It or Refuse It, Never Silently Drop It (+23 more)

### Community 35 - "Test Strategy Docs"
Cohesion: 0.08
Nodes (31): The upgrade is rehearsed on a running stack (D6), Breaking Changes Collect on One Long-Lived Branch, Release Dry Run Compared Against the Label, A Major Release Is Declared by the release:major Label, Both the plain-HTTP and the TLS run must be green (D5), Unit coverage is a floor, not a goal (D13), Denominator correction in coverage reporting, Every test is shown to fail without its change (D11) (+23 more)

### Community 36 - "360-Degree Singlepart Tests"
Cohesion: 0.18
Nodes (28): PerformanceMetrics, github.com/aws/aws-sdk-go-v2/service/s3.Client, verifyMinIODirectAccess(), calculateThroughput(), cleanupSinglePartTestFile(), downloadSinglePartFile(), downloadSinglePartFileWithMetrics(), formatDataSize() (+20 more)

### Community 37 - "Config Structure"
Cohesion: 0.14
Nodes (26): EncryptionConfig, MonitoringConfig, OptimizationsConfig, S3BackendConfig, S3SecurityConfig, TLSConfig, aesKeyError(), createProviderFromProviderMap() (+18 more)

### Community 38 - "DeleteObjects Batch Tests"
Cohesion: 0.24
Nodes (29): DelDeletedEntry, DelErrorDoc, DelErrorEntry, DelRequestDoc, DelRequestObject, DelResponse, DelResultDoc, DelBuildDoc() (+21 more)

### Community 39 - "Multipart Conformance Tests"
Cohesion: 0.29
Nodes (27): github.com/aws/aws-sdk-go-v2/service/s3/types.CompletedPart, MpuShape, MpuTarget, MpuAbortQuiet(), MpuComplete(), MpuCreate(), MpuDigest(), MpuEncryptionMeta() (+19 more)

### Community 40 - "Router and Middleware Setup"
Cohesion: 0.14
Nodes (27): github.com/gorilla/mux.RouteMatch, github.com/gorilla/mux.Router, Server, RtPxauthHeader(), RtPxserver(), RtPxsignedRequest(), TestRtPxDetermineErrorCodeMapping(), TestRtPxMiddlewareChainStreamsBodyUnchanged() (+19 more)

### Community 41 - "Provider Mode Integration Tests"
Cohesion: 0.22
Nodes (24): AESProxyTestInstance, ExitProxyTestInstance, context.CancelFunc, getKeys(), IsAESProviderActive(), StartAESProviderProxyInstance(), TestAESProvider_LargeFile(), TestAESProvider_MetadataHandling() (+16 more)

### Community 42 - "Bucket NotImplemented Tests"
Cohesion: 0.20
Nodes (24): NewAccelerateHandler(), TestAccelerateHandler_AccelerateStatuses(), TestAccelerateHandler_AccelerationBenefits(), TestAccelerateHandler_BucketNamingRequirements(), TestAccelerateHandler_ContentTypeHandling(), TestAccelerateHandler_Handle(), TestAccelerateHandler_HandleErrors(), TestAccelerateHandler_XMLValidation() (+16 more)

### Community 43 - "Multipart Handler Unit Tests"
Cohesion: 0.21
Nodes (23): github.com/stretchr/testify/mock.Arguments, NewCreateHandler(), alignedPlaintext(), assertDetachedContext(), setupMultipartTestEnv(), TestAbortHandler_AbortSurvivesCancelledRequestContext(), TestAbortHandler_Handle(), TestCompleteHandler_AbortSurvivesClientDisconnect() (+15 more)

### Community 44 - "Object Operations Handler"
Cohesion: 0.16
Nodes (7): PlaintextSize(), copyWithPooledBuffer(), objectVersionID(), writeEntityHeaders(), writeVersionHeaders(), Handler, Handler

### Community 45 - "License Tool CLI"
Cohesion: 0.18
Nodes (24): collectLicenseInfo(), LicTcaptureStdout(), LicTextractToken(), LicTkey(), LicTwithStdin(), LicTwritePEM(), TestLicTCollectLicenseInfo(), TestLicTEndToEnd() (+16 more)

### Community 46 - "Upload Deficit Investigation"
Cohesion: 0.12
Nodes (26): Item 2.0 Auto-Multipart Producer Measurement, Item 2.1 Stream The Client-Driven UploadPart, Item 2.2 HTTP Transfer-Encoding Decoder Dead Branch, Item 2.3 readAllSized Allocates Twice, Item 4.1 Discarded SDK Transport Defaults, Item 4.2 Fill The Pooled Buffer Before Writing, Item 6.4 Block And Mutex Profiles, Item 6.5 Part-Size By Concurrency Sweep (+18 more)

### Community 47 - "Segmented Orchestration Tests"
Cohesion: 0.20
Nodes (24): assembleSession(), Manager, segRegisteredSession(), TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst(), TestSegmentedSessionLifecycle(), TestSegmentedSessionPartReupload(), TestSegmentedSessionRefusesABufferAboveTheLimit(), TestSegmentedSessionRefusesALayoutItCannotStore() (+16 more)

### Community 48 - "XML Response Helpers"
Cohesion: 0.17
Nodes (21): RespCapturingLogger(), RespFindEntry(), RespNewFailingWriter(), TestRespWriteErrorDocumentSurvivesFailedWrite(), TestRespWriteS3ErrorLogLevels(), TestRespWriteS3ErrorNilErrorLogsNoDetail(), TestRespWriteS3ErrorSurvivesFailedWrite(), TestRespNewXMLWriter() (+13 more)

### Community 49 - "Operator Documentation"
Cohesion: 0.12
Nodes (25): No Backward Compatibility for Stored Data, AES Example Configuration, AES TLS Example Configuration, Exit Provider Example Configuration, Exit Configuration Starts Without a License, Multi-Provider Rotation Example Configuration, Contributing Guide, config Is One String, Not a Map (+17 more)

### Community 50 - "DeleteObjects Handler Tests"
Cohesion: 0.14
Nodes (19): Handler, ObjMiscdeleteObjects(), ObjMiscnewFailWriter(), ObjMiscparseDeleteResult(), TestObjMiscDeleteObjectsAcceptsAnObjectWithoutAKey(), TestObjMiscDeleteObjectsDoesNotEnforceTheThousandKeyLimit(), TestObjMiscDeleteObjectsEmptyDocumentReachesTheBackend(), TestObjMiscDeleteObjectsEscapesKeysInTheResponse() (+11 more)

### Community 51 - "Exit Provider ADRs"
Cohesion: 0.11
Nodes (24): ADR 0017: Stored Data Compatibility Is Not Owed, Backward-compatibility code is deleted, not carried (D9), An unworkable configuration value refuses startup (D8), No compatibility is owed for data at rest (D1), There is no migration: re-upload from source (D3), One major release costs one migration (D10), A removed configuration key is removed, silently (D7), Stated precondition and the read-only fallback (D2) (+16 more)

### Community 52 - "Coverage and Surface Tickets"
Cohesion: 0.13
Nodes (24): Item 10 ListParts From The Session Part Table, Explicit ListBucketResult Document, One Shared Backend Mock, Skips That Assert Nothing, The Test Tree Is Not Linted, Ticket 019 Test-Suite Hygiene, Item 1 Forward The Storage Headers, Refuse SSE-C, Item 23 Refuse A Semicolon In The Raw Query (+16 more)

### Community 53 - "Monitoring Server"
Cohesion: 0.16
Nodes (17): net.Listener, Server, MonfreeAddr(), Monserve(), TestMonNewServerConfiguration(), TestMonServerEndpointsSurviveWriteFailures(), TestMonServerHealthEndpoint(), TestMonServerInfoEndpoint() (+9 more)

### Community 54 - "ListBuckets Handler Tests"
Cohesion: 0.17
Nodes (19): Handler, MockS3Backend, RtPxdoListBuckets(), RtPxlistBuckets(), RtPxnewHandler(), TestRtPxListBucketsBackendErrors(), TestRtPxListBucketsClientDisconnect(), TestRtPxListBucketsDocumentShape() (+11 more)

### Community 55 - "Chunked Upload Tests"
Cohesion: 0.18
Nodes (20): ChunkedReader, createAWSChunkedDataMultiChunk(), createAWSChunkedEncodedBody(), downloadObjectSimple(), generateTestData(), NewChunkedReader(), parseChunkedDataManually(), TestChunkedEncodingCornerCases() (+12 more)

### Community 56 - "Copy Benchmarks"
Cohesion: 0.13
Nodes (12): io.Reader, io.Writer, benchGetResponse(), BenchmarkGetResponseCopy(), copyWithSize(), benchReader, forwardingWriter, hidingWriter (+4 more)

### Community 57 - "Codec Streaming IO"
Cohesion: 0.15
Nodes (5): reader, sealSink, Writer, Codec, EncryptReader

### Community 58 - "SigV4 Authentication Tests"
Cohesion: 0.19
Nodes (20): TestMwPresignedRejections(), S3AuthenticationService, requireAuthErr(), signWithSDK(), TestAuthenticateRequest_ClockSkew(), TestAuthenticateRequest_HeaderTampering(), TestAuthenticateRequest_MalformedHeaders(), TestAuthenticateRequest_SDKSignedHeaders() (+12 more)

### Community 59 - "Health Handler"
Cohesion: 0.21
Nodes (17): HlthfailingWriter, HlthrecordingWriter, HlthnewFailingWriter(), HlthnewTestLogger(), TestHlthHealthHealthyResponse(), TestHlthHealthShutdownStateHandlerVariants(), TestHlthHealthShutdownStateIsReEvaluatedPerRequest(), TestHlthLogHealthRequests() (+9 more)

### Community 60 - "Orchestration Manager"
Cohesion: 0.19
Nodes (18): Manager, OrcMgrAESConfig(), OrcMgrNewManager(), orcMgrOpenSession(), OrcMgrPrefixPtr(), orcMgrSessionCount(), TestOrcMgrAccessorsAndMetadataFiltering(), TestOrcMgrBackgroundCleanupRemovesExpiredSessions() (+10 more)

### Community 61 - "Object Helper Functions"
Cohesion: 0.11
Nodes (6): StripAWSChunked(), TestStripAWSChunked(), Handler, CleanupContext(), CompletedPart, CompleteMultipartUpload

### Community 62 - "Segment Codec Core"
Cohesion: 0.17
Nodes (6): Codec, crc32Combine(), gf2MatrixSquare(), gf2MatrixTimes(), Checksum, Codec

### Community 63 - "License Logging"
Cohesion: 0.20
Nodes (19): github.com/sirupsen/logrus/hooks/test.Hook, github.com/sirupsen/logrus.Level, LiclevelOf(), TestLicFormatTimeRemainingSubHour(), TestLicLogLicenseInfoExhaustedTimeRemaining(), TestLicLogLicenseInfoExpiringSoon(), TestLicLogLicenseInfoFullDetails(), TestLicLogLicenseInfoInvalidResult() (+11 more)

### Community 64 - "License Validator Tests"
Cohesion: 0.14
Nodes (20): LicenseClaims, LicenseValidator, LicclaimsFor(), LicclearLicenseEnv(), LicforeignKey(), LicrequireStopReturns(), LicsignWith(), LictamperPayload() (+12 more)

### Community 65 - "Error Response Tests"
Cohesion: 0.16
Nodes (17): TestCopyHandler_NotSupportedWithEncryption(), TestHandler_CopyObjectHeaderDetection(), TestHandler_CopyObjectNotSupported(), TestHandleDeleteObject_InputValidation(), TestHandleDeleteObject_S3Error(), TestHandleDeleteObject_Success(), TestHandleDeleteObject_VersionID(), TestHandleDeleteObjectIntegration_BaseObjectOperations() (+9 more)

### Community 66 - "NPM Release Tooling"
Cohesion: 0.10
Nodes (20): author, description, devDependencies, conventional-changelog-conventionalcommits, semantic-release, @semantic-release/changelog, @semantic-release/git, @semantic-release/github (+12 more)

### Community 67 - "360-Degree Multipart Tests"
Cohesion: 0.20
Nodes (15): StreamingReader, cleanupTestFile(), downloadLargeFile(), generateLargeFileTestData(), NewStreamingReader(), TestComprehensiveMultipartUpload(), TestMultipartUploadCorruption(), TestStreamingMultipartUpload() (+7 more)

### Community 68 - "Release Workflow"
Cohesion: 0.12
Nodes (20): Combined Unit and Integration Coverage, Coverage Badge Committed by semantic-release, Velero E2E as a Release Gate, golangci-lint v2 Module Path Pin, GoSec Security Scan Job, govulncheck Vulnerability Job, GOCOVER Instrumented Proxy Build, Integration Tests Against the Demo Stack (+12 more)

### Community 69 - "Open Ticket Backlog"
Cohesion: 0.14
Nodes (20): Item 12 Configuration Remainders, Precondition: No Production Users, No Migration Path, Item 2 Clock Skew On The Header-Signed Path, Item 4 max_presign_expiry_seconds, Ticket 015 Configuration Hygiene, The Cancelled CI Threshold Gate, Rename The Published Encryption Overhead Summary, Ticket 021 Local Performance Baseline (+12 more)

### Community 70 - "MinIO Test Helper"
Cohesion: 0.16
Nodes (18): crypto/x509.CertPool, CleanupTestBucket(), CompareObjectData(), contains(), createMinIOClient(), createProxyClient(), CreateProxyClientWithEndpoint(), findInString() (+10 more)

### Community 71 - "Monitoring Middleware"
Cohesion: 0.17
Nodes (11): MonrequestMetric(), TestMonHTTPMiddlewareDefaultsToStatus200(), TestMonHTTPMiddlewareRecordsRoutedRequest(), TestMonHTTPMiddlewareTracksActiveConnections(), TestMonHTTPMiddlewareUnknownEndpoint(), TestMonResponseWriterCapturesStatusCode(), TestMonResponseWriterForwardsToTheLiveWriter(), TestMonResponseWriterKeepsTheWriterCapabilities() (+3 more)

### Community 72 - "Metrics and Main Entry"
Cohesion: 0.15
Nodes (14): initConfig(), runProxy(), github.com/prometheus/client_golang/prometheus.Gatherer, github.com/prometheus/client_golang/prometheus.Labels, github.com/spf13/cobra.Command, MondefaultMetric(), MongatherMetric(), TestMonGetKubernetesLabels() (+6 more)

### Community 73 - "HTTP Middleware Tests"
Cohesion: 0.20
Nodes (10): MwechoHandler(), MwtestLogger(), TestMwCORSMiddleware(), TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader(), TestMwLoggerMiddleware(), TestMwRequestTracker(), TestMwResponseWriterForwardsToTheLiveWriter(), TestMwResponseWriterKeepsTheWriterCapabilities() (+2 more)

### Community 74 - "Velero E2E Environment"
Cohesion: 0.13
Nodes (18): Testing Strategy and Layers, Velero E2E Suite in kind, Pod TLS Is Not a Chart Feature, kind cluster s3ep-e2e, Host port mappings 30443 (proxy HTTPS) and 30900 (MinIO S3), In-cluster MinIO backend over HTTPS, emptyDir data volume so the backend does not depend on the CSI driver under test, minio-mkbucket Job creating the velero bucket (+10 more)

### Community 75 - "Object Header Conformance"
Cohesion: 0.34
Nodes (17): github.com/aws/aws-sdk-go-v2/service/s3.Options, net/http.Header, HdrCaptureResponseBody(), HdrCaptureResponseHeaders(), HdrCleanupBucket(), HdrGetHeaders(), HdrHeadHeaders(), HdrIsObjectHeader() (+9 more)

### Community 76 - "Multipart Session Table"
Cohesion: 0.14
Nodes (5): sync.Mutex, Manager, SegmentedSession, FinalPart, sessionPart

### Community 77 - "SigV4 Signing Helper"
Cohesion: 0.22
Nodes (5): time.Time, Handler, AWSV4Signer, NewAWSV4Signer(), SignHTTPRequestForS3()

### Community 78 - "Multipart XML Documents"
Cohesion: 0.13
Nodes (16): BkterrorDoc, encoding/xml.Name, completeMultipartUploadResult, completeResultDoc, initiateMultipartUploadResult, initiateResultDoc, listPartsResult, listPartsResultDoc (+8 more)

### Community 79 - "Security Architecture Docs"
Cohesion: 0.15
Nodes (17): KEK/DEK Envelope Architecture, Annotated Repository Layout, HeadBucket Region Is the Proxy's Statement, Listing Parameter Behaviour, No Request Rate Limiting, Sizes and Listings Describe the Plaintext, Storage Format s3ep-gcm-seg-v2, Operations the Proxy Does Not Implement (+9 more)

### Community 80 - "Object Handler Dispatch"
Cohesion: 0.14
Nodes (5): ACLHandler, Handler, TaggingHandler, IsAWSProtocolQueryParam(), TestReqIsAWSProtocolQueryParam()

### Community 81 - "Range Conformance Tests"
Cohesion: 0.36
Nodes (14): rngCase, rngFixture, rngObserved, rngCasesFor(), rngNewFixture(), rngPayload(), rngRawGet(), rngViaMinIO() (+6 more)

### Community 82 - "CI and Helm Security"
Cohesion: 0.13
Nodes (16): Docker Image Release Workflow, Helm Chart Release to GitHub Pages, Plain Push to gh-pages, SBOM, Provenance and Docker Scout Scan, S3 Encryption Proxy Helm Chart, A Configuration Change Does Not Restart Pods, S3EP_AES_KEY from an External Secret, nginx Body Buffering Turned Off (+8 more)

### Community 83 - "Filename Encryption ADR"
Cohesion: 0.17
Nodes (16): Local key material is generated on demand (D2), S3EP_AES_KEY is the one name for the local key (D3), AES-SIV-CMAC (RFC 5297) with parent-chain associated data (D4), The transform is applied at exactly one boundary (D8), Backend order is returned, never re-sorted (D12), Segment ciphertext is base64url without padding (D5), The transform is deterministic, keyed and stateless (D3), Only directory segments are encrypted, the leaf stays clear (D2) (+8 more)

### Community 84 - "Storage Format Ticket"
Cohesion: 0.21
Nodes (16): Associated Data: formatID, Object Key, Index, Four Encryption Metadata Keys, Item 16 Documentation Remainder, Item 2d Sealed Checksum Read Side And Tail-First Read, Random Inline Nonces Per Segment, Rejected: AES-CTR Plus Per-Segment HMAC, Rejected: Storing A Per-Object Part Layout, Rejected: Tink AES-GCM-HKDF Derived Nonces (+8 more)

### Community 85 - "Bucket ACL Tests"
Cohesion: 0.17
Nodes (14): github.com/aws/aws-sdk-go-v2/service/s3/types.AccessControlPolicy, github.com/aws/aws-sdk-go-v2/service/s3/types.BucketCannedACL, mapCannedACLForBucket(), parseACLXMLForTest(), TestACLXMLParsing(), TestCannedACLMapping(), TestHandleBucketACL_GET_NoClient(), parseACLXML() (+6 more)

### Community 86 - "License Types"
Cohesion: 0.17
Nodes (14): sync/atomic.Bool, sync.Once, jwt.RegisteredClaims, LicenseValidator, calculateTimeRemaining(), checkClaims(), TestLicCalculateTimeRemainingBoundaries(), TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim() (+6 more)

### Community 87 - "Metadata Manager"
Cohesion: 0.22
Nodes (9): NewMetadataManager(), createTestConfigForMetadata(), createTestConfigWithoutPrefix(), TestGetAlgorithm(), TestGetEncryptedDEK(), TestGetFingerprint(), TestGetMetadataPrefix(), TestNewMetadataManager() (+1 more)

### Community 88 - "Metadata Manager Tests"
Cohesion: 0.31
Nodes (15): Manager, OrcMetaAssertOnlyAllowedKeys(), OrcMetaConfig(), OrcMetaNewManager(), OrcMetaPrefixedKeys(), OrcMetaPrefixPtr(), OrcMetaSHA256(), TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten() (+7 more)

### Community 89 - "Segment Tamper Tests"
Cohesion: 0.35
Nodes (9): TamEnv, TamShape, TamAssertRefused(), TamDigest(), TamInspect(), TamSetup(), TestSegmentChainRefusesTamperedBytes(), TestSegmentChainRefusesTamperedMetadata() (+1 more)

### Community 90 - "Authentication Integration Tests"
Cohesion: 0.25
Nodes (13): SimpleTestContext, createValidAWS4Signature(), hmacSHA256(), NewSimpleTestContext(), TestAuthentication(), testClockSkewProtection(), testEnterpriseSecurityConfiguration(), testRateLimiting() (+5 more)

### Community 91 - "SigV4 Header Authentication"
Cohesion: 0.26
Nodes (4): github.com/sirupsen/logrus.Logger, S3AuthenticationService, NewS3AuthenticationService(), SignatureInfo

### Community 92 - "Pre-Signed URL Authentication"
Cohesion: 0.20
Nodes (10): net/url.Values, canonicalQueryString(), canonicalURI(), S3AuthenticationService, isPresignedRequest(), parseCredentialScope(), TestCanonicalQueryString(), TestCanonicalURI() (+2 more)

### Community 93 - "Encryption Validation Helper"
Cohesion: 0.30
Nodes (13): EncryptionValidationConfig, EncryptionValidationResult, AssertDataIsEncrypted(), AssertDataIsNotEncrypted(), calculateShannonEntropy(), CompareEncryptionStrength(), ConfigForDataSize(), containsForbiddenPatterns() (+5 more)

### Community 94 - "Bucket CRUD Tests"
Cohesion: 0.18
Nodes (10): TestBucketHandle_BaseOperationsStillReachTheBackend(), TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed(), TestBucketHandle_UnroutedSubResourceIsNotABaseOperation(), TestHandleCreateBucket(), TestHandleDeleteBucket(), NewHandler(), TestMainBucketHandler_NewHandlers(), NewLifecycleHandler() (+2 more)

### Community 95 - "Object Listing"
Cohesion: 0.31
Nodes (7): callerOwner(), formatLastModified(), Handler, clientWantsURLEncoding(), decodeBackendValue(), encodeForClient(), parseMaxKeys()

### Community 96 - "Performance Findings Round 1"
Cohesion: 0.14
Nodes (14): Item 4.3 GOMEMLIMIT, Item 6.1 Baseline Without Backend TLS, Item 6.3 Small-Object Request-Rate Ceiling, Item 5 Refuse A Plain-HTTP Backend Under An Encrypting Provider, P-11 Plain-HTTP Backend Cannot Take A Streaming Upload, The HMAC Is The Entire Difference, The Container Memory Limit Is Nowhere Near Reached, pre-v2 Baseline Findings (+6 more)

### Community 97 - "Upload Checksum Ticket"
Cohesion: 0.19
Nodes (14): Published Checksum Cost Table, The Unprotected Client-To-Proxy Leg, CRC64NVME Slicing-By-8 Rebuild Trap, DeleteObjects Requires And Verifies A Digest, Never Forwarded, Never Stored, Never Echoed, Ticket 014 Verify Client Upload Checksums, aws-chunked Trailer Capture, verifyingReader (+6 more)

### Community 98 - "Performance Benchmarks"
Cohesion: 0.32
Nodes (13): testing.B, ComparisonResult, PerformanceResult, BenchmarkStreamingDownload(), BenchmarkStreamingUpload(), cleanupBenchmarkBucket(), clearPerformanceTestBucket(), EnsureBenchmarkEnvironment() (+5 more)

### Community 99 - "Config Validation Tests"
Cohesion: 0.24
Nodes (13): CfgExitProviderConfig(), CfgValidClients(), Config, TestCfgValidateEncryptionProviderList(), TestCfgValidateLicenseAndEncryption(), TestCfgValidateMonitoringPprofBindAddress(), TestCfgValidateOptimizationsBoundaries(), TestCfgValidatePropagatesSubValidatorErrors() (+5 more)

### Community 100 - "SigV4 Coverage Tests"
Cohesion: 0.26
Nodes (13): S3AuthenticationService, MwauthService(), MwhmacSHA256(), MwsignDateHeaderRequest(), TestMwAuthenticateRequestDateHeaderPath(), TestMwAuthenticateRequestRejections(), TestMwAuthErrorsCarryTheS3ErrorCodeMarkers(), TestMwBuildCanonicalHeaders() (+5 more)

### Community 101 - "Ticket Lifecycle ADR"
Cohesion: 0.22
Nodes (13): In-source marker for a test pinning replaced behaviour (D16), A ticket is a work list and nothing else (D3), A ticket is closed by deleting the file (D4), ADR 0022: Tickets Are Work Lists That Get Deleted, An ADR carries no references into the code (D8), The ADR is written in the session the decision is taken (D2), A changed decision amends its ADR in place (D9), Every durable decision is an ADR (D1) (+5 more)

### Community 102 - "Filename Encryption Ticket"
Cohesion: 0.23
Nodes (13): The boundary decorator between the proxy and the backend SDK client, Object keys leak namespace, backup and restore names in cleartext, The leaf name stays clear so prefix listings survive, A mapping index in the bucket is rejected, K_name: a 64-byte name key wrapped by the active KEK, AES-SIV-CMAC per directory segment with a chained AAD, Ticket 017: Filename encryption, directory segments only, Outstanding Listing Benchmark (+5 more)

### Community 103 - "CORS Middleware"
Cohesion: 0.29
Nodes (4): net/http.Handler, CORS, NewCORS(), Server

### Community 104 - "Exit Provider Readback Tests"
Cohesion: 0.41
Nodes (11): assertStoredEncrypted(), assertStoredPlaintext(), getViaClient(), randomPayload(), storedObject(), TestExitProvider_ClientDrivenMultipart(), TestExitProvider_ReadsBackAMultipartObject(), TestExitProvider_ReadsBackAnEncryptedObject() (+3 more)

### Community 105 - "Passthrough Operation Tests"
Cohesion: 0.22
Nodes (10): NewTestContext(), TestStreamingMultipartUpload(), TestDeleteObjectFunctionality(), TestListBucketsOperation(), TestListBucketsPassthrough(), TestPassthroughOperations_DeleteObjects(), TestPassthroughOperations_GetObjectTorrent(), TestPassthroughOperations_LegalHold() (+2 more)

### Community 106 - "Range Reader"
Cohesion: 0.21
Nodes (6): rangeReader, Codec, Codec, Window, segmentStoredLen(), segmentCount()

### Community 107 - "Finding Label Index"
Cohesion: 0.18
Nodes (12): Item 1.2 Blanket 30s Read/Write Timeouts, F-Series Fixes, Finding Label Index, N-10 Published Helm Chart KEK, N-1 Fail-Open Pass-Through Read, N-5 Dead Rate-Limiting Knobs, N-6 Client Checksums Dropped, N-8 Thirty-Second Listener Timeouts (+4 more)

### Community 108 - "Response Writer Hijacking"
Cohesion: 0.23
Nodes (3): bufio.ReadWriter, net.Conn, responseWriter

### Community 109 - "pprof Listener"
Cohesion: 0.23
Nodes (8): net/http.Server, TestPprofNewServerConfiguration(), TestPprofServerReportsItsFailures(), TestPprofServerServesOnlyProfiling(), TestPprofServerStartServesAndShutsDownOnContextCancel(), NewPprofServer(), PprofServer, Server

### Community 110 - "Helm Install Script"
Cohesion: 0.40
Nodes (10): check_prerequisites(), create_namespace(), get_version(), install_chart(), log_error(), log_info(), log_warn(), main() (+2 more)

### Community 111 - "Request Tracking Middleware"
Cohesion: 0.22
Nodes (3): RequestTracker, NewRequestTracker(), Server

### Community 112 - "Conditional Request Tests"
Cohesion: 0.45
Nodes (10): condOutcome, condPrecondition, condCodeOf(), condGet(), condHead(), condPayload(), condPutObject(), condStatusOf() (+2 more)

### Community 113 - "Breaking Change Guard"
Cohesion: 0.24
Nodes (10): ADR 0018: a major release is declared by a label, check-breaking-changes.sh detector, Breaking Change Guard, Pull-request title and body inspection, release:major label, npm clean-install --ignore-scripts under a write token, Version Dry Run job, BREAKING: metadata_key_prefix must match ^[a-z0-9-]+$ (+2 more)

### Community 114 - "Helm Chart Fixes Ticket"
Cohesion: 0.24
Nodes (10): Item 4a Refuse A Client Key Inside The Prefix, Item 14 Metadata Prefix Shape, Item 10 e2e Runs kopia With The Published Default Password, Item 1 Missing checksum/config Annotation, Item 2 Values Files That Cannot Be Rendered, Item 3 Probes Ignore tls.enabled, Item 6 Moving metadata_key_prefix Is Breaking, Item 7 The Chart Is Never Rendered In CI (+2 more)

### Community 115 - "KMS and Vault Ticket"
Cohesion: 0.31
Nodes (10): The DEK Cache Lifetime Becomes A Security Parameter, Demo Vault Defects, Key Custody Is What This Buys, And Only That, Five Decisions Before Any Vault Code, A Rewrap Campaign Is Not A Metadata Edit, Three Rotation Mechanisms, Vault As A Key Provider (Parked), Vault Availability Becomes Proxy Availability (+2 more)

### Community 116 - "Segmented Object Entry Points"
Cohesion: 0.33
Nodes (3): io.ReadCloser, Manager, SegmentedWrite

### Community 117 - "Provider Selection Tests"
Cohesion: 0.27
Nodes (9): TestGetActiveProvider(), TestGetActiveProvider_NoAlias(), TestGetActiveProvider_NotFound(), TestGetAllProviders(), TestValidateEncryption_MissingActiveProvider(), TestValidateEncryption_MissingAESKey(), TestValidateEncryption_UnsupportedType(), TestValidateEncryption_ValidAES() (+1 more)

### Community 118 - "Sealed Part Arithmetic"
Cohesion: 0.29
Nodes (4): PartStoredLen(), PlanRange(), SealedPart, SegmentedUpload

### Community 119 - "Part Codec Tests"
Cohesion: 0.40
Nodes (9): Codec, partCodec(), sealInParts(), TestSegOpenTrailerRejectsTampering(), TestSegPartWriterOffsetIsAuthenticated(), TestSegPartWriterRefusesShortMiddlePart(), TestSegPartWriterRefusesUnalignedOffset(), TestSegPartWriterRoundTrip() (+1 more)

### Community 121 - "Documentation Conventions"
Cohesion: 0.33
Nodes (9): Decisions Live in ADRs, Start with the Graphify Knowledge Graph, S3 Encryption Proxy Coding Instructions, A Ticket Is a Work List That Gets Deleted, Where Durable Documentation Belongs, The Configuration Is a ConfigMap, The Chart Has No Key for the Master Key, S3 Encryption Proxy (+1 more)

### Community 122 - "Request Flow Documentation"
Cohesion: 0.22
Nodes (9): Client-Driven Multipart Session Flow, GET Request Data Flow, The Honest Gap: One Forward Pass, No Tail-First Read, Exactly Four Metadata Keys, PUT Request Data Flow, 64 KiB-Multiple Part Rule, Session Expiry Drops Proxy State, Not the Backend Upload, Where the Failure Surfaces (+1 more)

### Community 123 - "Dead Configuration Findings"
Cohesion: 0.22
Nodes (9): Integrity Is Not Configurable, Values Nothing Reads, Two Request Metrics Never Reach /metrics, H-10 Three Configuration Decisions Specified and Not Built, H-5 A Tampered Object Is Delivered — closed, H-7 Dead Security Configuration Knobs — closed, ListParts Still Pretends, Transport on Both Legs (+1 more)

### Community 124 - "License Loading"
Cohesion: 0.28
Nodes (8): crypto/rsa.PublicKey, TestLicLoadLicenseFromFile(), LoadLicense(), LoadLicenseFromEnv(), LoadLicenseFromFile(), parseEmbeddedPublicKey(), TestLoadLicenseFromEnv(), TestParseEmbeddedPublicKey()

### Community 125 - "License Validation"
Cohesion: 0.33
Nodes (8): LicenseValidator, NewValidator(), TestLicenseClaims(), TestNewValidator(), TestValidateLicense_EmptyToken(), TestValidateLicense_InvalidToken(), TestValidateProviderType_NoLicense(), TestValidateProviderType_WithLicense()

### Community 126 - "Logging Middleware"
Cohesion: 0.28
Nodes (3): Logger, NewLogger(), responseWriter

### Community 127 - "Hostile Backend Decisions"
Cohesion: 0.25
Nodes (8): The Backend Is an Adversary (D1, D2), Verification at Read Granularity (D3), Plaintext Length Is a Pure Function of the Stored Length (D12, D12a), A Ranged Read Fetches Only the Segments It Covers (D9), Every Response Is Composed by the Proxy (D1), Every Key Inside the Namespace Is Removed from Every Response (D7), A Listing Response Is a Real S3 Document, Built Explicitly (D4), A Listing Size Is Computed by Arithmetic, With No Per-Key Request (D2, D3)

### Community 128 - "ListBuckets Root Handler Tests"
Cohesion: 0.36
Nodes (7): github.com/sirupsen/logrus.FieldLogger, NewHandler(), TestHandleListBuckets(), TestHandleListBucketsError(), TestHandleListBucketsMultipleBuckets(), TestNewHandler(), TestRtPxNewHandlerIsUsableImmediately()

### Community 129 - "Backend SDK Client Options"
Cohesion: 0.39
Nodes (6): backendOptions(), TestBackendClientOptions_ChecksumsOnlyWhenRequired(), TestBackendClientOptions_InsecureSkipVerify(), TestBackendClientOptions_NoEndpointLeavesDefaults(), TestBackendClientOptions_PathStyleAndEndpoint(), discardWriter

### Community 130 - "Bucket Replication Handler"
Cohesion: 0.39
Nodes (6): NewReplicationHandler(), TestReplicationHandler_ComplexConfigurations(), TestReplicationHandler_Handle(), TestReplicationHandler_HandleErrors(), TestReplicationHandler_ReplicationMetrics(), TestReplicationHandler_XMLValidation()

### Community 131 - "Bucket Website Handler"
Cohesion: 0.43
Nodes (7): NewWebsiteHandler(), TestWebsiteHandler_ComplexConfigurations(), TestWebsiteHandler_DocumentSuffixValidation(), TestWebsiteHandler_Handle(), TestWebsiteHandler_HandleErrors(), TestWebsiteHandler_RoutingRuleTypes(), TestWebsiteHandler_XMLValidation()

### Community 132 - "Ranged Read Hardening"
Cohesion: 0.29
Nodes (8): kopia Repository Password Must Be Set First, Pre-Signed URL Validation, Ranged Reads, Velero Deployment Notes, The Clock-Skew Knob Governs Half of What Its Name Says, H-1 Ranged Reads Are Not Verified — closed, H-4 Velero kopia Repositories Default to a Published Password, SigV4 Validation, Header and Pre-Signed

### Community 133 - "Large Multipart Tests"
Cohesion: 0.38
Nodes (4): simplePRNG, TestLargeMultipart500MB(), generateDeterministicData(), newSimplePRNG()

### Community 135 - "Secret Exposure Surface"
Cohesion: 0.33
Nodes (7): pprof on Its Own Loopback Listener, Client Checksums Are Neither Forwarded Nor Verified, Bounded DEK LRU Cache, H-2 Per-Chunk Signatures Are Never Verified, pprof Must Bind Loopback or Startup Fails, An Attacker Who Takes the Proxy Gets Everything, What Is NOT Verified

### Community 136 - "Coverage Summary Script"
Cohesion: 0.43
Nodes (6): main(), module_path(), percent(), Per-package coverage table for the CI report. Reads the text profiles that…, {location: (statements, count)} for one text-format profile., read_profile()

### Community 137 - "Bucket Notification Handler"
Cohesion: 0.48
Nodes (6): NewNotificationHandler(), TestNotificationHandler_ComplexConfigurations(), TestNotificationHandler_EventTypes(), TestNotificationHandler_Handle(), TestNotificationHandler_HandleErrors(), TestNotificationHandler_XMLValidation()

### Community 138 - "Bucket Versioning Handler"
Cohesion: 0.43
Nodes (5): NewVersioningHandler(), TestVersioningHandler_Handle(), TestVersioningHandler_HandleErrors(), TestVersioningHandler_MFAValidation(), TestVersioningHandler_XMLParsing()

### Community 139 - "Performance Baseline Suite"
Cohesion: 0.43
Nodes (7): streaming_segment_size Must Be a 64 KiB Multiple, Three Write Paths, Identical Bytes, The Backend Refuses an aws-chunked Chunk Above 16 MiB, Local Performance Baseline Suite, Uniform Measurement Record Schema, How Big a Change Has to Be to Be Real, The Second Proxy uploadpath Needs

### Community 140 - "Baseline Comparison Script"
Cohesion: 0.48
Nodes (6): human(), key(), load(), machine_line(), main(), Compare two performance baseline runs. ./test/perf/compare.py perf-…

### Community 141 - "Bucket Logging Handler"
Cohesion: 0.53
Nodes (5): BucketLoggingStatus, Grantee, LoggingEnabled, TargetGrant, NewLoggingHandler()

### Community 142 - "Listing XML Documents"
Cohesion: 0.67
Nodes (5): commonPrefix, listBucketResultV1, listBucketResultV2, objectEntry, ownerEntry

### Community 175 - "DEK Cache Staleness Ticket"
Cohesion: 0.47
Nodes (6): DEK cache key (fingerprint:objectKey), Option A: include encryptedDEK digest in the cache key, Option B: invalidate the DEK cache on write, Option C: key the cache by encryptedDEK only, TestLargeMultipart500MB reproduction, Ticket 011: DEK cache returns stale DEK after re-upload

### Community 176 - "Breaking Change Detector"
Cohesion: 0.47
Nodes (5): add_message(), die(), FOOTER_PATTERN, HEADER_PATTERN, check-breaking-changes.sh script

### Community 178 - "E2E Bring-Up Script"
Cohesion: 0.53
Nodes (5): k(), KUBECONFIG, log(), need(), e2e-up.sh script

### Community 179 - "Bucket Policy Tests"
Cohesion: 0.60
Nodes (5): analyzePolicySecurity(), TestBucketPolicyComplexStructures(), TestBucketPolicySecurityAnalysis(), TestBucketPolicyValidation(), validatePolicyJSON()

### Community 180 - "Bucket Routing Tests"
Cohesion: 0.50
Nodes (3): testTrackingHandler, Handler, TestBucketListingWithQueryParameters()

### Community 181 - "Storage Format Decisions"
Cohesion: 0.40
Nodes (5): Integrity Is Not Separable from Decryption (D4), One 256-Bit Data Key per Object (D1), AES-256-GCM Segment Chain plus Trailer (D1), Uniform, Segment-Aligned Parts Checked Against the Part Table (D2, D3), The Verdict Lands Before Anything Is Committed (D7)

### Community 182 - "Checksum and Trailer Decisions"
Cohesion: 0.40
Nodes (5): A Failed Whole-Object Read Reaches the Client as a Short Body, A CRC32C over the Plaintext, Sealed in the Trailer (D13), The Tail-First Read and the Served Checksum (D14, not built), No Plaintext Checksum in Object Metadata: It Is a Confirmation Oracle (D9), The Proxy Serves Its Own Sealed CRC32C on a Whole-Object Read (D10, D10a)

### Community 185 - "ListBuckets XML Types"
Cohesion: 0.70
Nodes (4): ListAllMyBucketsResult, S3Bucket, S3Buckets, S3Owner

### Community 188 - "Streaming Performance Test"
Cohesion: 0.83
Nodes (3): downloadAndVerifyWithSDK(), performMultipartUploadWithSDK(), TestStreamingVsStandardPerformance()

## Ambiguous Edges - Review These
- `Proxy ConfigMap Template` → `Development Values Profile`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/values-development.yaml · relation: shares_data_with
- `Proxy ConfigMap Template` → `Monitoring Values Profile`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/values-monitoring.yaml · relation: shares_data_with
- `Helm Unittest Deployment Suite` → `Default Chart Values`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml · relation: references
- `Tier 2 proxy CPU profile (15 s, 5.48 s samples, crypto + syscalls dominant)` → `runtime.memclrNoHeapPointers at 11.71 % of proxy CPU in Tier 4.1 (3.28 % in Tier 2)`  [AMBIGUOUS]
  docs/tickets/010-tier4.1/proxy-cpu-top20.txt · relation: references
- `HeadBucket Region Is the Proxy's Statement` → `Backend Privilege Footprint`  [AMBIGUOUS]
  SECURITY_ARCHITECTURE.md · relation: conceptually_related_to

## Knowledge Gaps
- **161 isolated node(s):** `HEADER_PATTERN`, `FOOTER_PATTERN`, `version-dry-run.sh script`, `github.com/guided-traffic/s3-encryption-proxy`, `dekCacheEntry` (+156 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 391 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **50 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Proxy ConfigMap Template` and `Development Values Profile`?**
  _Edge tagged AMBIGUOUS (relation: shares_data_with) - confidence is low._
- **What is the exact relationship between `Proxy ConfigMap Template` and `Monitoring Values Profile`?**
  _Edge tagged AMBIGUOUS (relation: shares_data_with) - confidence is low._
- **What is the exact relationship between `Helm Unittest Deployment Suite` and `Default Chart Values`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `Tier 2 proxy CPU profile (15 s, 5.48 s samples, crypto + syscalls dominant)` and `runtime.memclrNoHeapPointers at 11.71 % of proxy CPU in Tier 4.1 (3.28 % in Tier 2)`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `HeadBucket Region Is the Proxy's Statement` and `Backend Privilege Footprint`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `Manager` connect `Multipart Handler` to `Config Structure`, `Multipart Handler Tests`, `Provider Mode Integration Tests`, `Provider Manager`, `Multipart Handler Unit Tests`, `Multipart Session Table`, `Request Tracking Middleware`, `Object Handler Dispatch`, `Mock Backend Helpers`, `Bucket Handler Routing`, `Metadata Manager`, `Orchestration Manager`, `Bucket CRUD Tests`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **Why does `parseChunkedDataManually()` connect `Chunked Upload Tests` to `Copy Benchmarks`, `Config Env Expansion`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._