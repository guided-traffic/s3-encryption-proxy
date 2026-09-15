# Graph Report - s3-encryption-proxy  (2026-09-15)

## Corpus Check
- Large corpus: 447 files · ~765,359 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 5374 nodes · 15628 edges · 249 communities (188 shown, 58 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 2121 edges (avg confidence: 0.86)
- Token cost: 1,554,452 input · 0 output

## Community Hubs (Navigation)
- Object GET Coverage Tests
- Chunked Streaming Test Harness
- Velero E2E Backup Suite
- Bucket Handler Error Fixtures
- Multipart Handler Coverage Tests
- Contributor Guide and KMS Provider ADR
- DeleteObjects Handler Tests
- Proxy-Owned Part Layout
- Checksum and ETag Echo Tests
- KEK Providers and Key Rotation
- DEK Cache and Provider Manager
- Keygen and KEK Factory
- Multipart Semantics and ETag Marker
- Multipart Handler Constructors
- Response Composition Rules
- Config Accessors and Dashboard Contract
- Release 5.0.0 Breaking Changes
- Forward-or-Refuse and CI Gates
- Bucket Sub-Resource Handlers
- Any-S3-Client Scope and E2E Rules
- Response Header Helpers
- MockS3Backend Bucket Operations
- Integration Corpus Seed and Budget
- Authentication Integration Tests
- Configuration Loading and Upload Sweeper
- Documentation and Release Process Rules
- PUT Routing and Short-Part Budget
- Renovate Dependency Configuration
- Replication and ACL Handlers
- Request Parser and Framing Tests
- Bucket Handler Dispatch
- MockS3Backend Object Operations
- S3 Method Error Mapping Tests
- ListBuckets Root Handler
- Segmented Session Tests
- Segmented Manager Streaming IO
- Proxy Server Lifecycle Tests
- Hostile Backend Threat Model
- KEK Fingerprint and Client Checksums
- ACL, CORS and Lifecycle Handlers
- Configuration Struct and Accessors
- Bucket Website and Create/Delete
- Segmented GCM Reader and Writer
- HTTP Middleware Coverage Tests
- Performance Harness Shell Script
- Segment Encrypt Reader Tests
- Large Multipart and DEK Cache Tests
- Multipart Conformance Suite
- Segmented Session Lifecycle
- MockS3Backend Multipart Operations
- Network Boundary and HA Store
- ListObjects Conformance Fixtures
- Config Loading Coverage Tests
- Bucket XML Document Types
- Encryption-at-Rest Assertions
- Ranged Read and Passthrough Tests
- Bucket Location and Logging Tests
- XML Document Marshalling
- S3 Error Mapping
- Vault Transit KEK Provider (parked)
- Monitoring HTTP Server
- Checksum Verifier Tests
- Ranged GET Path and Window
- DeleteObjects Batch Documents
- Semantic Release Toolchain
- Health Probe Handler
- Orchestration Manager Coverage
- SigV4 Authentication Rules
- Error Mapping Coverage Tests
- License Tool
- CORS Middleware and SSE-C Stripping
- Config Env Var Expansion
- s3cmd E2E Suite
- Streaming Upload and Sealed Checksum
- Monitoring Middleware Tests
- Metadata Manager Coverage
- MockS3Backend Attribute Operations
- Config Defaults and Provider Loading
- rclone E2E Suite
- MockS3Backend Tagging and Policy
- Segmented GCM Range Reader
- Performance Test Client
- Performance Baselines and Findings
- SigV4 Header and Presign Tests
- aws-chunked Streaming Decoder
- S3 Error Document Writer
- Client E2E Verdicts
- Backend Call Observation
- Copy and Delete Object Handlers
- Object Listing Handler
- Segment Seal and Open Internals
- Shutdown Order and Probes
- SigV4 Service Coverage Tests
- Monitoring Status Endpoint
- ETag Marker Codec
- Values Proxy
- Main
- Hardening History
- Integrity
- Exec
- Backend
- Logger
- Subresource Documents
- Testing
- Monitoring
- Configuration
- Monitoring
- Checksum
- Validator
- Golangci
- Segmented GCM
- S3auth Presigned
- Performance
- Multipart
- Harness
- Range Conformance
- Conformance Run
- Segment Tamper
- Backend Client
- Validation
- Scenarios Atrest
- Subresource Documents
- Shutdown
- Types
- Bucket Crud
- S3auth Robust
- Crc64nvme
- Subresource Documents
- Complete
- Metrics
- Report
- S3 Signing Helper
- Validator
- Readme
- Conditional Requests
- Compare
- Pipeline
- Configmap
- Subresource Chunked Body
- Throughput
- Docker Compose Demo
- Install
- Cryptofloor
- Validator
- Requestid
- Backend
- Deployment
- Router
- List
- Segmented GCM Vector
- Segmented GCM Part
- Subresource Documents
- AES Example
- Prometheusrule
- Integrity
- Streaming Aws Decoder
- Server
- Harness
- Pprof
- Smallobject
- ACL
- Listing Document
- Logging
- 027 Whole Object Read
- Scenarios Read
- Default Config
- Metadata
- Main
- Scenarios Read
- Default
- Helpers
- Summary
- Rclone
- E2e Up
- Conformance Paid
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Helpers
- Check Breaking Changes
- Server
- Validator
- Middleware
- Etag Marker
- Rangeread
- Stored
- E2e Up
- E2e Up
- Values Velero
- Bucket Policy
- Constants
- Subresource Documents
- Values
- Checksum
- Push
- S3 API
- Gen Keys
- Renovate Assign On Failure
- Checksum
- Backend
- Multipart
- Chart
- Version Dry Run
- Multipart
- Multipart
- E2e Down
- E2e Down
- E2e Down
- Kind Config
- Gen Certs
- Pipeline
- Pipeline
- Pipeline
- Pipeline
- Certificate
- Grafana Dashboard
- S3 API
- Go

## God Nodes (most connected - your core abstractions)
1. `EnsureMinIOAndProxyAvailable()` - 122 edges
2. `NewTestContextWithTimeout()` - 93 edges
3. `NewErrorWriter()` - 91 edges
4. `RandomString()` - 80 edges
5. `MpuNewEnv()` - 71 edges
6. `ObjGetdo()` - 67 edges
7. `MockS3Backend` - 64 edges
8. `MockS3Backend` - 64 edges
9. `ObjGetpayload()` - 60 edges
10. `ExpectedBucketOwner()` - 60 edges

## Surprising Connections (you probably didn't know these)
- `Package Map` --references--> `main()`  [EXTRACTED]
  docs/developer/package-map.md → cmd/s3-encryption-proxy/main.go
- `reportedSize` --calls--> `PlaintextSize()`  [EXTRACTED]
  docs/developer/request-paths.md → pkg/encryption/dataencryption/segmented_gcm.go
- `A control that exists only in configuration is worse than no control` --semantically_similar_to--> `ADR 0013 A configuration key exists only if code reads it`  [INFERRED] [semantically similar]
  SECURITY_ARCHITECTURE.md → README.md
- `Documentation updated in the same change, in the right place` --semantically_similar_to--> `Documentation has five homes, a statement goes to exactly one`  [INFERRED] [semantically similar]
  CONTRIBUTING.md → CLAUDE.md
- `Configuration: Where a Value Comes From` --references--> `InitConfig()`  [EXTRACTED]
  docs/developer/configuration.md → internal/config/config.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **The Upload Deficit Investigation** — perf_baseline_20260909t175340z_9f3fbd1_findings_upload_cliff_at_threshold, perf_baseline_20260910t062529z_9f3fbd1_findings_self_copy_is_not_the_cause, perf_baseline_20260910t062529z_9f3fbd1_findings_streaming_path_faster_than_backend, perf_baseline_20260910t090543z_530472c_findings_deficit_is_per_byte [EXTRACTED 1.00]
- **The Velero e2e kind stack** — test_e2e_velero_kind_config_cluster, test_e2e_velero_manifests_snapshotclass_csi_hostpath, test_e2e_velero_values_velero_values [EXTRACTED 1.00]
- **What makes the stored object authenticated** — readme_s3ep_gcm_seg_v2, security_architecture_four_metadata_keys, security_architecture_key_hierarchy, security_architecture_sealed_trailer, security_architecture_segment_additional_data [EXTRACTED 1.00]
- **What gates a release** — claude_one_tool_one_suite_one_job, contributing_breaking_change_label, contributing_suites_are_not_optional, developer_ci_pipeline, developer_required_checks, developer_semantic_release_dry_run [EXTRACTED 1.00]
- **Leaving the product with your data readable** — readme_exit_provider, readme_license_startup_gate, security_architecture_exit_fingerprint_is_not_a_key, security_architecture_exit_provider_analysis, security_architecture_license_expiry_shutdown [EXTRACTED 1.00]
- **The demo stack: MinIO, two proxy listeners, a probe sidecar and an explorer** — docker_compose_demo_minio, docker_compose_demo_proxy_healthcheck, docker_compose_demo_s3_encryption_proxy, docker_compose_demo_s3_encryption_proxy_tls, docker_compose_demo_s3_explorer_encrypted [EXTRACTED 1.00]
- **The graceful drain: /readyz, the preStop sleep and the derived grace period** — deploy_helm_s3_encryption_proxy_templates_deployment_prestop_sleep_hook, deploy_helm_s3_encryption_proxy_values_prestopsleepseconds, deploy_helm_s3_encryption_proxy_values_readinessprobe, deploy_helm_s3_encryption_proxy_values_terminationgraceperiodseconds [EXTRACTED 1.00]
- **Release gates: every e2e client suite plus conformance must pass before a tag is cut** — _github_workflows_test_pipeline_conformance, _github_workflows_test_pipeline_e2e_rclone, _github_workflows_test_pipeline_e2e_s3cmd, _github_workflows_test_pipeline_e2e_velero, _github_workflows_test_pipeline_semantic_release [EXTRACTED 1.00]
- **The accept-discard-report-success prohibition** — docs_adr_0007_forward_it_or_refuse_it_d1, docs_adr_0007_forward_it_or_refuse_it_silent_drop_with_200, docs_adr_0008_every_response_describes_the_proxy_d7, docs_adr_0009_the_metadata_prefix_is_the_proxys_namespace_d6, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_d1 [INFERRED 0.85]
- **Every answer describes the plaintext, never the stored bytes** — docs_adr_0008_every_response_describes_the_proxy_d13, docs_adr_0010_sizes_and_listings_describe_the_plaintext_d1, docs_adr_0010_sizes_and_listings_describe_the_plaintext_etag_of_the_stored_bytes, docs_adr_0010_sizes_and_listings_describe_the_plaintext_plaintext_size_arithmetic, docs_adr_0012_client_checksums_are_verified_never_forwarded_d10 [INFERRED 0.85]
- **An unworkable configuration refuses to start** — docs_adr_0004_one_local_key_provider_d4, docs_adr_0009_the_metadata_prefix_is_the_proxys_namespace_d2, docs_adr_0011_the_proxy_owns_the_part_layout_d7, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_d7, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_exact_mode_decoding [INFERRED 0.85]
- **What a release has to clear before it is cut** — docs_adr_0016_the_license_is_a_startup_gate_expiry_check_fails_early, docs_adr_0018_a_major_release_is_declared_by_a_label_release_major_label, docs_adr_0018_a_major_release_is_declared_by_a_label_semantic_release_dry_run, docs_adr_0019_integration_and_e2e_tests_are_the_product_e2e_gates_the_release, docs_adr_0020_performance_is_measured_before_and_after_no_measurement_fails_a_build [INFERRED 0.75]
- **The dead-control principle across the ADR family** — docs_adr_0014_authentication_is_sigv4_no_rate_limiting_control_only_in_configuration, docs_adr_0014_authentication_is_sigv4_no_rate_limiting_dead_configuration_key, docs_adr_0017_stored_data_compatibility_is_not_owed_removed_key_is_removed, docs_adr_0019_integration_and_e2e_tests_are_the_product_no_switch_disarms_an_assertion, docs_adr_0021_key_material_is_generated_never_committed_no_document_prints_a_key, docs_adr_0026_the_proxy_terminates_tls_at_its_own_service_render_time_refusals [INFERRED 0.85]
- **Every secret the deployment holds, and how it arrives** — docs_adr_0016_the_license_is_a_startup_gate_s3ep_license_token, docs_adr_0021_key_material_is_generated_never_committed_generated_on_demand, docs_adr_0021_key_material_is_generated_never_committed_s3ep_aes_key, docs_adr_0021_key_material_is_generated_never_committed_signing_key_custody, docs_adr_0023_filename_encryption_encrypts_directory_segments_name_key [INFERRED 0.75]
- **Graceful Shutdown of a Process That Holds Its Uploads** — docs_adr_0028_an_abandoned_upload_is_ended_not_forgotten_sweeper_aborts_at_backend, docs_adr_0029_the_shutdown_budget_finishes_work_and_sweeps_what_cannot_be_finished_shutdown_order, docs_adr_0033_a_proxy_instance_holds_its_uploads_single_replica_chart, docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_readyz_endpoint, docs_developer_multipart_shutdown_ends_what_it_holds, internal_orchestration_manager_abandonallsessions [EXTRACTED 0.95]
- **The Tail-First Whole-Object Read** — docs_developer_errors_invalid_object_state_refusals, docs_developer_performance_tail_first_second_request_cost, docs_developer_request_paths_tail_first_get, docs_developer_storage_format_sealed_trailer, internal_proxy_handlers_object_tail_fetchobjecttail [EXTRACTED 0.95]
- **The Entity Tag Marker and Its Inverse Across Every Emission Site** — docs_adr_0032_the_entity_tag_is_a_change_token_never_a_content_digest_entity_tag_marker, docs_adr_0032_the_entity_tag_is_a_change_token_never_a_content_digest_marker_is_invertible, docs_developer_multipart_part_table_is_the_authority, docs_developer_request_paths_entity_tag_gates, internal_proxy_etag_mark, internal_proxy_etag_unmarklist [EXTRACTED 0.90]
- **The tail-first whole-object read** — docs_operations_integrity_s3ep_gcm_seg_v2, docs_operations_integrity_x_amz_checksum_crc32c, docs_operations_s3_api_what_a_read_costs, docs_tickets_027_whole_object_read_first_window_evaluation, internal_proxy_handlers_object_tail_fetchobjecttail [EXTRACTED 1.00]
- **The entity-tag marker and the clients it exists for** — docs_operations_clients_rclone_use_multipart_etag, docs_operations_clients_s3cmd_s3cmd, docs_operations_integrity_entity_tag_marker, docs_operations_s3_api_conditional_requests [EXTRACTED 1.00]
- **Refusing an object this proxy did not write** — docs_operations_integrity_foreign_object_refusal, docs_operations_integrity_metadata_kek_fingerprint, docs_operations_monitoring_s3ep_object_integrity_failures_total, docs_operations_upgrading_old_objects_unreadable, docs_security_hardening_history_h_6 [INFERRED 0.85]
- **The Valkey Coordination Design Of Ticket 036** — docs_tickets_036_high_availability_held_short_part_stays_in_owner_memory, docs_tickets_036_high_availability_pinned_part_size, docs_tickets_036_high_availability_session_store_interface, docs_tickets_036_high_availability_shared_session_table_in_valkey_with_sentinel, docs_tickets_036_high_availability_three_deployment_forms [INFERRED 0.85]
- **The Destruction Paths Of The Rewrap Pass** — docs_tickets_040_managed_buckets_copysourceifmatch_compare_and_swap, docs_tickets_040_managed_buckets_five_gib_copyobject_cliff, docs_tickets_040_managed_buckets_renamed_metadata_key_prefix, docs_tickets_040_managed_buckets_self_copyobject_full_rewrite, docs_tickets_040_managed_buckets_worm_state_stripped_by_a_self_copy [INFERRED 0.85]
- **Whether Readiness May Depend On Something Outside The Process** — docs_tickets_036_high_availability_coordination_store_never_behind_readiness, docs_tickets_038_s3_encryption_operator_is_a_custom_resource_a_tenant, docs_tickets_039_backend_certificate_verification_failure_is_named_no_backend_probe_before_ready, docs_tickets_040_managed_buckets_readiness_switch_during_the_scan [INFERRED 0.75]
- **Three Runs of One Hour Establish the Between-Run Spread** — perf_baseline_20260911t101344z_cc62c05_report_post_v2_wave5_run, perf_baseline_20260911t102319z_cc62c05_report_post_v2_wave5_drained_run, perf_baseline_20260911t103132z_cc62c05_findings_between_run_spread, perf_baseline_20260911t103132z_cc62c05_report_post_v2_wave5_record_run [EXTRACTED 1.00]
- **The ADR 0020 D17 Instrument Set** — test_perf_readme_cryptofloor_instrument, test_perf_readme_local_performance_baseline, test_perf_readme_memory_instrument, test_perf_readme_rangeread_instrument, test_perf_readme_smallobject_instrument, test_perf_readme_throughput_instrument, test_perf_readme_unwrap_instrument, test_perf_readme_uploadpath_instrument [EXTRACTED 1.00]
- **The Velero e2e TLS Chain — Listener, Backend CA, Backend Certificate** — test_e2e_velero_manifests_minio_tls_secret, test_e2e_velero_manifests_minio_unsigned_payload_needs_tls, test_e2e_velero_values_proxy_backend_ca_ssl_cert_file, test_e2e_velero_values_proxy_service_tls_byo_cert [INFERRED 0.85]

## Communities (249 total, 58 thin omitted)

### Community 0 - "Object GET Coverage Tests"
Cohesion: 0.06
Nodes (135): github.com/sirupsen/logrus/hooks/test.Hook, github.com/sirupsen/logrus.Level, TestObjCrcARangedReadStatesNoChecksum(), TestObjCrcAWriteAndAReadAgreeOnTheChecksum(), TestObjTagAProxyPinNeverCarriesTheMarker(), TestObjTagPreconditionsAreUnmarkedOnTheWayOut(), TestObjTagTheInternalPinIsNeverMarked(), Handler (+127 more)

### Community 1 - "Chunked Streaming Test Harness"
Cohesion: 0.05
Nodes (99): ChunkedReader, PerformanceMetrics, StreamingReader, AESProxyTestInstance, ExitProxyTestInstance, EncryptionValidationConfig, EncryptionValidationResult, createAWSChunkedDataMultiChunk() (+91 more)

### Community 2 - "Velero E2E Backup Suite"
Cohesion: 0.09
Nodes (81): backendObject, backendClient(), caTrustingHTTPClient(), listBackendObjects(), proxyClient(), readBackendObject(), readViaProxy(), veleroBucket() (+73 more)

### Community 3 - "Bucket Handler Error Fixtures"
Cohesion: 0.07
Nodes (81): BktclosingBody, BktfailingReader, BktfailingWriter, BktforeignHits, errBkt, strings.Reader, TestBktTagAMultipartTagInAListingIsNotMarked(), TestBktTagBothListingsMarkADigestShapedTag() (+73 more)

### Community 4 - "Multipart Handler Coverage Tests"
Cohesion: 0.10
Nodes (76): MockS3Backend, MpuAPIError(), MpuChain(), MpuCompleteBody(), MpuDigest(), MpuNewEnv(), MpuNewEnvWithProvider(), MpuParseError() (+68 more)

### Community 5 - "Contributor Guide and KMS Provider ADR"
Cohesion: 0.03
Nodes (84): CLAUDE.md AI coding instructions, The complete configuration structure, A configuration key shape change has to run make test-conformance, A breaking change is declared, never discovered, DEVELOPER.md contributor entry point, Checklist: adding a configuration key, Repository layout, The semantic-release dry run is a separate workflow (+76 more)

### Community 6 - "DeleteObjects Handler Tests"
Cohesion: 0.06
Nodes (75): net/http/httptest.ResponseRecorder, Handler, ObjMiscbodyDigest(), ObjMiscdeleteObjects(), ObjMiscnewFailWriter(), ObjMiscparseDeleteResult(), TestObjMiscDeleteObjectsBackendErrorsAreMapped(), TestObjMiscDeleteObjectsBodyReadErrorIsRefused() (+67 more)

### Community 7 - "Proxy-Owned Part Layout"
Cohesion: 0.04
Nodes (85): The proxy owns the part layout, ADR 0011 The proxy owns the part layout, ADR 0011 D1: Every client part is encrypted by the proxy and becomes exactly one backend part, ADR 0011 D10: A client that needs a second name re-uploads through the proxy, ADR 0011 D2: A client-driven upload must use uniform, segment-aligned parts, checked at Complete, ADR 0011 D3: The part size is inferred from the largest part that could be a middle part, ADR 0011 D4: The trailer is an extra part, or rides a held last part; 9999 usable part numbers, ADR 0011 D6: Complete is built from the proxy's own part table, never from the client's ETags (+77 more)

### Community 8 - "Checksum and ETag Echo Tests"
Cohesion: 0.10
Nodes (76): github.com/stretchr/testify/mock.Call, ObjCrcwant(), TestObjCrcADeclaredChecksumAndTheAnsweredOneAgree(), TestObjCrcAnEmptyObjectStillAnswersAChecksum(), TestObjCrcARefusedUploadStatesNoChecksum(), TestObjCrcIsNotTheChecksumOfTheStoredBytes(), TestObjCrcSingleRequestPutAnswersThePlaintextChecksum(), TestObjCrcTheExitProviderStatesNoChecksum() (+68 more)

### Community 9 - "KEK Providers and Key Rotation"
Cohesion: 0.04
Nodes (76): Only the active alias writes; every configured provider can decrypt, config/multi-example.yaml (key rotation by provider list), ADR 0002 One data key per object, Rotation is configuration: add a provider, move the alias, restart (D7), ADR 0004 One local key provider, AES-256-GCM Key Wrap (76 bytes), AES-KWP Deterministic Wrap (rejected: not in the standard library), AES Provider (type: aes) (+68 more)

### Community 10 - "DEK Cache and Provider Manager"
Cohesion: 0.06
Nodes (51): container/list.Element, container/list.List, sync.Mutex, sync.RWMutex, Case, Recorder, row, buildDEKCacheKey() (+43 more)

### Community 11 - "Keygen and KEK Factory"
Cohesion: 0.05
Nodes (44): main(), printKey(), TestKeygenDrawsAFreshKeyEachTime(), TestKeygenOutput(), KeyEncryptionType, AESProvider, ExitProvider, FacFactoryWithAES() (+36 more)

### Community 12 - "Multipart Semantics and ETag Marker"
Cohesion: 0.03
Nodes (68): Pinning the Current Answer as the Expectation, A Test States the Target Behaviour, The -0 Entity Tag Marker, The Marker Is Invertible and the Inverse Is Driven by Shape, The Marker Is Answered at Object Level and at Part Level, A Permanent State Is a 4xx, a Transient Failure a 5xx, The Client-Driven Multipart Upload, The Internal Multipart Producer (+60 more)

### Community 13 - "Multipart Handler Constructors"
Cohesion: 0.10
Nodes (47): github.com/sirupsen/logrus.Entry, github.com/stretchr/testify/mock.Arguments, sync.WaitGroup, Manager, NewAbortHandler(), NewCompleteHandler(), NewCopyHandler(), NewCreateHandler() (+39 more)

### Community 14 - "Response Composition Rules"
Cohesion: 0.04
Nodes (64): Checklist: rendering a response document, ADR 0008 Every response describes the proxy, The ETag Is Still the Backend's (documented exception), ADR 0008 D1: Every response is composed by the proxy; a backend response object is never serialised as received, ADR 0008 D10: The backend account identity never appears in a response document, ADR 0008 D11: A new pass-through of backend-supplied text is decided per element, ADR 0008 D12: A value the proxy does not have is omitted, never rendered as a zero value, ADR 0008 D12a: The proxy states its own request identifier on every answer it composes (+56 more)

### Community 15 - "Config Accessors and Dashboard Contract"
Cohesion: 0.08
Nodes (56): testing.T, TestCfgGetActiveProviderErrorPaths(), TestCfgGetActiveProviderReturnsLivePointer(), TestCfgGetAllProvidersReflectsSlice(), TestCfgIsValidProviderType(), TestCfgStreamingAccessors(), TestGetMultipartPartSize(), TestOptimizationsConfig() (+48 more)

### Community 16 - "Release 5.0.0 Breaking Changes"
Cohesion: 0.04
Nodes (61): CHANGELOG.md release history, 5.0.0: a chart upgrade that changes the configuration restarts the pods, 5.0.0: wrong or unsupported upload checksums are refused, 5.0.0: clean_http_transfer_chunked and the aws-chunked keys are gone, 5.0.0: the listing response document changes shape, Release 5.0.0 - the storage format break, The committed graph predates the 5.0.0 removal, Integrity is not configurable and never was a layer (+53 more)

### Community 17 - "Forward-or-Refuse and CI Gates"
Cohesion: 0.04
Nodes (60): MinIO is the oracle, the AWS documentation is the specification, Pull request requirements, Checklist: every backend call carries the owner guard, test-pipeline.yml continuous integration jobs, Paid conformance runs on a schedule, never on a pull request, Fifteen required checks are repository configuration, not a file, ADR 0007 Forward it or refuse it, PUT /{bucket}?acl and PUT /{bucket}?cors Documents (+52 more)

### Community 18 - "Bucket Sub-Resource Handlers"
Cohesion: 0.12
Nodes (50): BaseSubResourceHandler, NewAccelerateHandler(), TestAccelerateHandler_AccelerateStatuses(), TestAccelerateHandler_AccelerationBenefits(), TestAccelerateHandler_BucketNamingRequirements(), TestAccelerateHandler_ContentTypeHandling(), TestAccelerateHandler_Handle(), TestAccelerateHandler_HandleErrors() (+42 more)

### Community 19 - "Any-S3-Client Scope and E2E Rules"
Cohesion: 0.04
Nodes (58): 5.0.0: the none and tink provider types are removed, The e2e harness has two halves, One tool, one suite, one job - never bundled, The stored contract stays spelled out per suite, Checklist: adding a KEK provider, Checklist: adding an end-to-end client suite, A ranged read plans without a key, ADR 0006 The proxy serves any S3 client (+50 more)

### Community 20 - "Response Header Helpers"
Cohesion: 0.07
Nodes (28): github.com/aws/aws-sdk-go-v2/service/s3/types.ServerSideEncryption, RecordObjectIntegrityFailure(), StripAWSChunked(), TestStripAWSChunked(), applyResponseOverrides(), integrityReason(), objectVersionID(), readDocument() (+20 more)

### Community 21 - "MockS3Backend Bucket Operations"
Cohesion: 0.07
Nodes (19): context.Context, github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationInput (+11 more)

### Community 22 - "Integration Corpus Seed and Budget"
Cohesion: 0.11
Nodes (42): Budget, CorpusObject, sync/atomic.Int64, bucketAlreadyThere(), seedClientMultipart(), TestCorpusStillExercisesEveryWritePath(), TestSeed(), TestSeedIsComplete() (+34 more)

### Community 23 - "Authentication Integration Tests"
Cohesion: 0.08
Nodes (41): SimpleTestContext, tbTrickleReader, authErrorCode(), NewSimpleTestContext(), proxyHost(), sendWellFormedAuthHeader(), TestAuthentication(), testClockSkewProtection() (+33 more)

### Community 24 - "Configuration Loading and Upload Sweeper"
Cohesion: 0.04
Nodes (49): An Incomplete Multipart Upload Is Treated as a Leak, AbortIncompleteMultipartUpload Lifecycle Rule, Expiry Is Measured From the Last Part, Never From Creation, optimizations.multipart_session_idle_timeout, The Sweeper Aborts at the Backend Before It Forgets, It Refuses Rather Than Documents, An ADR Carries No References Into the Code, AutomaticEnv Removed in 5.0.0 (+41 more)

### Community 25 - "Documentation and Release Process Rules"
Cohesion: 0.05
Nodes (48): Every design decision is recorded as an ADR, Documentation has five homes, a statement goes to exactly one, Nothing outside docs/tickets/ may reference a ticket, A test asserts the target behaviour, never today's, A ticket is a work list and nothing else, Documentation updated in the same change, in the right place, The integration and e2e suites are the product's behaviour, The license expiry is discovered by a build, not by an environment (D8, D9, D10) (+40 more)

### Community 26 - "PUT Routing and Short-Part Budget"
Cohesion: 0.05
Nodes (48): Encryption happens exactly once, The internal multipart producer overlaps receive with send, A PUT routes on PlaintextContentLength and nothing else, ADR 0011 D5: A part that cannot be a middle part is held under two bounds, 400 EntityTooLarge, EntityTooSmall, Held Short Last Part, optimizations.multipart_short_part_buffer_size (+40 more)

### Community 27 - "Renovate Dependency Configuration"
Cohesion: 0.04
Nodes (46): :automergeDigest, config:recommended, :dependencyDashboard, docker:enableMajor, :semanticCommits, assignAutomerge, automerge, automergeType (+38 more)

### Community 28 - "Replication and ACL Handlers"
Cohesion: 0.09
Nodes (10): ReplicationHandler, net/http.Request, ACLHandler, Handler, TaggingHandler, UserMetadata(), verifying(), Parser (+2 more)

### Community 29 - "Request Parser and Framing Tests"
Cohesion: 0.10
Nodes (34): newChunkedRequest(), mustStream(), newTestRequest(), TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented(), TestReqPlaintextContentLength(), TestReqReadAllSized_HintBoundaries(), TestReqReadBody_ForgedDecodedContentLength(), TestReqReadBody_IdentityBodyReadError() (+26 more)

### Community 30 - "Bucket Handler Dispatch"
Cohesion: 0.07
Nodes (11): AccelerateHandler, LocationHandler, NotificationHandler, RequestPaymentHandler, VersioningHandler, ACLHandler, Handler, TaggingHandler (+3 more)

### Community 31 - "MockS3Backend Object Operations"
Cohesion: 0.07
Nodes (20): MockS3Backend, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketCorsOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclOutput, github.com/aws/aws-sdk-go-v2/service/s3.PutBucketAccelerateConfigurationInput (+12 more)

### Community 32 - "S3 Method Error Mapping Tests"
Cohesion: 0.13
Nodes (34): github.com/aws/aws-sdk-go-v2/service/s3.Options, net/http.Header, ObjIntfailingWriter, RandomString(), TestDeleteObjectFunctionality(), apiCodeOf(), apiMessageOf(), errorsAs() (+26 more)

### Community 33 - "ListBuckets Root Handler"
Cohesion: 0.08
Nodes (32): github.com/sirupsen/logrus.FieldLogger, NewHandler(), TestHandleListBuckets(), TestHandleListBucketsError(), TestHandleListBucketsMultipleBuckets(), TestNewHandler(), Handler, MockS3Backend (+24 more)

### Community 34 - "Segmented Session Tests"
Cohesion: 0.14
Nodes (38): assembleSession(), Manager, segCompleted(), segRegisteredSession(), segStreamPart(), slowlyOver(), TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused(), TestSegmentedSessionASlowPartOutlivesTheIdleTimeout() (+30 more)

### Community 35 - "Segmented Manager Streaming IO"
Cohesion: 0.08
Nodes (14): io.ReadCloser, io.Reader, Manager, PartStoredLen(), PlaintextSize(), fillPart(), countingBody, MpuCountingReader (+6 more)

### Community 36 - "Proxy Server Lifecycle Tests"
Cohesion: 0.10
Nodes (36): RtPxconfig(), RtPxnewFailingListener(), RtPxstringPtr(), TestRtPxListenerBudgetsReachTheServer(), TestRtPxMetadataPrefixResolution(), TestRtPxNewServerLoadsAllProvidersButActivatesOne(), TestRtPxNewServerRejectsUnusableConfig(), TestRtPxProbesReportShutdownState() (+28 more)

### Community 37 - "Hostile Backend Threat Model"
Cohesion: 0.06
Nodes (39): config/exit-example.yaml (the way out of the product), The aes provider stays listed beside exit or old objects stop being readable, ADR 0001 The backend is hostile, A control that exists only in configuration is worse than none (D6), The exit provider (the way out, deciding per object), Fail closed on foreign objects (D5), Hostile-backend threat model (D1, D2), Integrity is not separable from decryption (D4) (+31 more)

### Community 38 - "KEK Fingerprint and Client Checksums"
Cohesion: 0.06
Nodes (39): ADR 0004 D6: Fingerprint and wrapping key are derived with HKDF-SHA256 under distinct labels, HKDF Labels and Wrap Associated Data Are Fixed Format Constants, HKDF-SHA256 Derivation, s3ep-kek-fingerprint, ADR 0005 D8: The published fingerprint identifies the key's address, not its material, s3ep-kek-fingerprint (the one fingerprint not derived from key material), ADR 0010 D5: No listing entry carries a checksum element, No Checksum Element in a Listing (+31 more)

### Community 39 - "ACL, CORS and Lifecycle Handlers"
Cohesion: 0.09
Nodes (11): ACLHandler, CORSHandler, LifecycleHandler, PolicyHandler, TaggingHandler, github.com/aws/aws-sdk-go-v2/service/s3/types.CORSRule, NewACLHandler(), NewCORSHandler() (+3 more)

### Community 40 - "Configuration Struct and Accessors"
Cohesion: 0.12
Nodes (33): EncryptionConfig, MonitoringConfig, OptimizationsConfig, S3BackendConfig, S3SecurityConfig, TLSConfig, A Provider Block Swallows Its Own Parameters (the ErrorUnused Boundary), aesKeyError() (+25 more)

### Community 41 - "Bucket Website and Create/Delete"
Cohesion: 0.11
Nodes (8): WebsiteHandler, net/http.ResponseWriter, Hlthprobe, Handler, Handler, clientETag(), UploadHandler, forwardingWriter

### Community 42 - "Segmented GCM Reader and Writer"
Cohesion: 0.10
Nodes (12): reader, sealSink, Writer, io.Writer, benchGetResponse(), BenchmarkGetResponseCopy(), copyWithSize(), benchReader (+4 more)

### Community 43 - "HTTP Middleware Coverage Tests"
Cohesion: 0.09
Nodes (16): bufio.ReadWriter, net.Conn, MwechoHandler(), MwtestLogger(), TestMwCORSMiddleware(), TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader(), TestMwLoggerMiddleware(), TestMwRequestTracker() (+8 more)

### Community 44 - "Performance Harness Shell Script"
Cohesion: 0.15
Nodes (34): build_project(), check_dependencies(), check_services(), cleanup(), generate_markdown_report(), get_iso_timestamp(), get_timestamp(), log_error() (+26 more)

### Community 45 - "Segment Encrypt Reader Tests"
Cohesion: 0.12
Nodes (32): errAfterReader, errReader, TestSegEncryptReaderChecksum(), TestSegEncryptReaderMatchesWriter(), TestSegEncryptReaderPropagatesSourceError(), TestSegEncryptReaderRoundTrip(), TestSegEncryptReaderStaysFailedAfterAnError(), TestSegEncryptReaderTinyReads() (+24 more)

### Community 46 - "Large Multipart and DEK Cache Tests"
Cohesion: 0.10
Nodes (30): crypto/x509.CertPool, github.com/aws/aws-sdk-go-v2/service/s3.Client, TestLargeMultipart500MB(), makePattern(), putMultipartTwoParts(), putSinglePart(), requireDownloadHashEquals(), runReuploadCycle() (+22 more)

### Community 47 - "Multipart Conformance Suite"
Cohesion: 0.23
Nodes (33): github.com/aws/aws-sdk-go-v2/service/s3/types.CompletedPart, MpuShape, MpuTarget, NewTestContextWithTimeout(), ProxyIsTLS(), MpuAbortQuiet(), MpuComplete(), MpuCreate() (+25 more)

### Community 48 - "Segmented Session Lifecycle"
Cohesion: 0.10
Nodes (7): CanStreamPart(), Manager, Manager, SegmentedSession, FinalPart, sessionPart, touchingReader

### Community 49 - "MockS3Backend Multipart Operations"
Cohesion: 0.09
Nodes (10): github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.HeadObjectOutput, github.com/aws/aws-sdk-go-v2/service/s3.PutObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.PutObjectOutput (+2 more)

### Community 50 - "Network Boundary and HA Store"
Cohesion: 0.09
Nodes (34): ADR 0030 The network boundary belongs to the administrator, The Unauthenticated Monitoring Listener Is Fenced by the Cluster or Not at All, The Chart Ships No NetworkPolicy at All, The Scrape Names No Licensee and Carries No Countdown, A Dropped Values Key Is Silent, So the Removal Is Announced, The Store Credential And Sentinel Address List Are Plural From The First Release, A Backend Health Notion For The Write Policy, Entity Tags, Conditional Requests And VersionId Are Backend-Local (+26 more)

### Community 51 - "ListObjects Conformance Fixtures"
Cohesion: 0.15
Nodes (33): github.com/aws/aws-sdk-go-v2/service/s3/types.CommonPrefix, github.com/aws/aws-sdk-go-v2/service/s3/types.Object, lstBulkFixture, lstRefFixture, lstAssertElementOrder(), lstBody(), lstBulkKeys(), lstChildElements() (+25 more)

### Community 52 - "Config Loading Coverage Tests"
Cohesion: 0.27
Nodes (33): InitConfig(), Load(), CfgNoLicense(), CfgResetViper(), CfgWriteConfigFile(), TestCfgAbsentSessionIdleTimeoutTakesTheDefault(), TestCfgBackendsAreAList(), TestCfgInitConfigDiscoversFileInHomeDirectory() (+25 more)

### Community 53 - "Bucket XML Document Types"
Cohesion: 0.12
Nodes (32): abortIncompleteUploadDocument, accessControlXlatePD, encryptionConfigPD, errorDocumentPD, indexDocumentPD, lifecycleAndDocument, lifecycleConfigurationDocument, lifecycleExpirationDocument (+24 more)

### Community 54 - "Encryption-at-Rest Assertions"
Cohesion: 0.23
Nodes (32): github.com/aws/smithy-go/middleware.Stack, EncObjectView, EncStored, NewProxyTLSClient(), EncAPICode(), EncAssertBodyIsCiphertext(), EncAssertEncryptedAtRest(), EncAssertHeadersClean() (+24 more)

### Community 55 - "Ranged Read and Passthrough Tests"
Cohesion: 0.22
Nodes (28): ckAnswer, TestRangeReadErrors(), TestRangeReadsOnEncryptedObjects(), EnsureMinIOAndProxyAvailable(), NewTestContext(), TestPassthroughOperations_DeleteObjects(), TestPassthroughOperations_GetObjectTorrent(), TestPassthroughOperations_SelectObjectContent() (+20 more)

### Community 56 - "Bucket Location and Logging Tests"
Cohesion: 0.09
Nodes (28): TestBucketLocationErrorHandling(), TestBucketLocationMethodHandling(), TestBucketLocationRegionMapping(), TestBucketLocationSecurityScenarios(), TestBucketLocationXMLFormat(), TestBucketLocationXMLValidation(), TestHandleBucketLocation_GET_NoClient(), TestBucketLoggingErrorHandling() (+20 more)

### Community 57 - "XML Document Marshalling"
Cohesion: 0.08
Nodes (29): accelerateConfigurationDocument, BkterrorDoc, locationConstraintDocument, requestPaymentConfigurationDocument, versioningConfigurationDocument, encoding/xml.Name, commonPrefix, ownerEntry (+21 more)

### Community 58 - "S3 Error Mapping"
Cohesion: 0.12
Nodes (28): One Function Renders the S3 Error Document, IsChecksumFailure(), IsChecksumUnsupported(), checksumVerdict(), codeForStatus(), internalMarkers, MapError(), discardLogger() (+20 more)

### Community 59 - "Vault Transit KEK Provider (parked)"
Cohesion: 0.08
Nodes (31): The DEK Cache Lifetime Becomes A Security Parameter, Demo Vault Defects, Key Custody Is What This Buys, And Only That, Five Decisions Before Any Vault Code, A Rewrap Campaign Is Not A Metadata Edit, Three Rotation Mechanisms, Vault As A Key Provider (Parked), Vault Availability Becomes Proxy Availability (+23 more)

### Community 60 - "Monitoring HTTP Server"
Cohesion: 0.12
Nodes (23): net/http.Server, net.Listener, sync/atomic.Bool, SetServerInfo(), Server, MonfreeAddr(), Monserve(), TestMonMetricsEndpointExportsTheRequestMetrics() (+15 more)

### Community 61 - "Checksum Verifier Tests"
Cohesion: 0.24
Nodes (30): BenchmarkChkVerifyingRead(), chkAssertOutcome(), chkChunkedRequest(), chkEncode(), chkFramed(), chkIdentityRequest(), chkParser(), chkPayload() (+22 more)

### Community 62 - "Ranged GET Path and Window"
Cohesion: 0.12
Nodes (20): Which Range Headers Are Acted On Is Decided Twice, The Ranged GET Path, The Ranged-Read Window and Its Amplification Bound, contentRangeTotal(), Handler, headForRange, parseByteRange(), parseRangeSpec() (+12 more)

### Community 63 - "DeleteObjects Batch Documents"
Cohesion: 0.24
Nodes (29): DelDeletedEntry, DelErrorDoc, DelErrorEntry, DelRequestDoc, DelRequestObject, DelResponse, DelResultDoc, DelBuildDoc() (+21 more)

### Community 64 - "Semantic Release Toolchain"
Cohesion: 0.07
Nodes (25): ADR-0017, ADR-0018, author, description, devDependencies, conventional-changelog-conventionalcommits, semantic-release, @semantic-release/changelog (+17 more)

### Community 65 - "Health Probe Handler"
Cohesion: 0.14
Nodes (17): Handler, HlthfailingWriter, HlthrecordingWriter, HlthnewFailingWriter(), HlthnewTestLogger(), TestHlthLiveIsConstantEvenWhileDraining(), TestHlthLogHealthRequests(), TestHlthNewHandler() (+9 more)

### Community 66 - "Orchestration Manager Coverage"
Cohesion: 0.20
Nodes (26): Manager, OrcMgrAESConfig(), OrcMgrNewManager(), orcMgrOpenSession(), OrcMgrPrefixPtr(), orcMgrSessionCount(), TestOrcMgrAccessorsAndMetadataFiltering(), TestOrcMgrBackgroundCleanupRemovesExpiredSessions() (+18 more)

### Community 67 - "SigV4 Authentication Rules"
Cohesion: 0.08
Nodes (27): 5.0.0: an unknown configuration key stops the start, ADR 0012 D15: The SigV4 payload hash is verified when s3_security.verify_payload_hash is on, s3_security.verify_payload_hash, ADR 0014 Authentication is SigV4, no rate limiting, An authentication refusal answers the code that names what failed (D13), Canonical query string sorts by parameter name, not by name=value, Per-chunk aws-chunked signatures are not verified (D6), The client address is a log field, never an identity (D8) (+19 more)

### Community 68 - "Error Mapping Coverage Tests"
Cohesion: 0.15
Nodes (23): RespAPIErrorNoResponse(), RespCapturingLogger(), RespFindEntry(), RespNewFailingWriter(), RespStatusOnlyError(), RespWrapMarker(), TestRespMapErrorBackend5xxKeepsReasonPhrase(), TestRespMapErrorCodeForStatusFallback() (+15 more)

### Community 69 - "License Tool"
Cohesion: 0.18
Nodes (24): collectLicenseInfo(), LicTcaptureStdout(), LicTextractToken(), LicTkey(), LicTwithStdin(), LicTwritePEM(), TestLicTCollectLicenseInfo(), TestLicTEndToEnd() (+16 more)

### Community 70 - "CORS Middleware and SSE-C Stripping"
Cohesion: 0.13
Nodes (10): What Never Reaches a Client, net/http.Handler, SSECustomerHeader(), CORS, NewCORS(), authErrorMessage, authErrorStatus(), Server (+2 more)

### Community 71 - "Config Env Var Expansion"
Cohesion: 0.14
Nodes (23): TestCfgExpandConfigEnvVarsErrorPerField(), TestCfgExpandConfigEnvVarsExpandsEveryField(), expandConfigEnvVars(), expandEnvVars(), Config, TestExpandConfigEnvVars_MissingProviderVarReturnsError(), TestExpandConfigEnvVars_MissingVarReturnsError(), TestExpandConfigEnvVars_MultipleClientsWithMixedRefs() (+15 more)

### Community 72 - "s3cmd E2E Suite"
Cohesion: 0.20
Nodes (20): endpoint, suite, SHA256File(), WriteRandomFile(), boolWord(), containsStr(), endpoints(), newSuite() (+12 more)

### Community 73 - "Streaming Upload and Sealed Checksum"
Cohesion: 0.17
Nodes (21): TestContext, downloadAndVerifyWithSDK(), performMultipartUploadWithSDK(), TestStreamingMultipartUpload(), TestStreamingVsStandardPerformance(), CksAssertServedChecksum(), CksDelete(), CksExpected() (+13 more)

### Community 74 - "Monitoring Middleware Tests"
Cohesion: 0.13
Nodes (12): MonrequestMetric(), TestMonHTTPMiddlewareDefaultsToStatus200(), TestMonHTTPMiddlewareRecordsRoutedRequest(), TestMonHTTPMiddlewareTracksActiveConnections(), TestMonHTTPMiddlewareUnknownEndpoint(), TestMonResponseWriterCapturesStatusCode(), TestMonResponseWriterForwardsToTheLiveWriter(), TestMonResponseWriterKeepsTheWriterCapabilities() (+4 more)

### Community 75 - "Metadata Manager Coverage"
Cohesion: 0.20
Nodes (23): Manager, OrcMetaAssertOnlyAllowedKeys(), OrcMetaConfig(), OrcMetaNewManager(), OrcMetaPrefixedKeys(), OrcMetaPrefixPtr(), OrcMetaSHA256(), TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten() (+15 more)

### Community 76 - "MockS3Backend Attribute Operations"
Cohesion: 0.12
Nodes (9): github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningInput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketVersioningOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectRetentionInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectRetentionOutput, github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyInput, github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyOutput (+1 more)

### Community 77 - "Config Defaults and Provider Loading"
Cohesion: 0.12
Nodes (22): loadProviderConfigs(), setDefaults(), TestGetActiveProvider(), TestGetActiveProvider_NoAlias(), TestGetActiveProvider_NotFound(), TestGetAllProviders(), TestListenerBudgetDefaults(), TestLoad_MissingTargetEndpoint() (+14 more)

### Community 78 - "rclone E2E Suite"
Cohesion: 0.21
Nodes (18): endpoint, remote, suite, SHA256Bytes(), endpoints(), newSuite(), preflight(), rcloneBin() (+10 more)

### Community 79 - "MockS3Backend Tagging and Policy"
Cohesion: 0.12
Nodes (9): github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationInput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLocationOutput, github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyInput, github.com/aws/aws-sdk-go-v2/service/s3.PutBucketPolicyOutput, github.com/stretchr/testify/mock.Mock, MockS3Backend (+1 more)

### Community 80 - "Segmented GCM Range Reader"
Cohesion: 0.14
Nodes (17): rangeReader, PlanRange(), Codec, Codec, Window, PlanRange(), segmentStoredLen(), min64() (+9 more)

### Community 81 - "Performance Test Client"
Cohesion: 0.19
Nodes (20): net/http.Client, rssSampler, emptyBucket(), ensureBucket(), httpClientFor(), isAlreadyOwned(), legsFor(), newS3Client() (+12 more)

### Community 82 - "Performance Baselines and Findings"
Cohesion: 0.11
Nodes (22): closeDrained(), wave3 — 1 MiB Ranged Read at 153.8 MiB/s (68 % of Direct), wave3 Run — uploadpath and memory Skipped, Baseline Run wave3-checksums (20260911T064137Z-233d559), Baseline Run post-v2-wave5 (20260911T101344Z-cc62c05), Baseline Run post-v2-wave5-drained (20260911T102319Z-cc62c05), Between-Run Spread — Anything Under 15 % End to End Is the Machine, The Multipart Leg Moved (+33 % to +47 %) (+14 more)

### Community 83 - "SigV4 Header and Presign Tests"
Cohesion: 0.19
Nodes (20): TestMwPresignedRejections(), S3AuthenticationService, requireAuthErr(), signWithSDK(), TestAuthenticateRequest_ClockSkew(), TestAuthenticateRequest_HeaderTampering(), TestAuthenticateRequest_MalformedHeaders(), TestAuthenticateRequest_SDKSignedHeaders() (+12 more)

### Community 84 - "aws-chunked Streaming Decoder"
Cohesion: 0.23
Nodes (20): newStreamingAWSChunkedReader(), testLogger(), TestStreamingAWSChunkedReader_Errors(), TestStreamingAWSChunkedReader_MultipleTrailers(), TestStreamingAWSChunkedReader_RoundTrip(), TestStreamingAWSChunkedReader_SizeMismatch(), TestStreamingAWSChunkedReader_SmallReads(), TestReqStreamingAWSChunkedReader_BlankLineBetweenChunks() (+12 more)

### Community 85 - "S3 Error Document Writer"
Cohesion: 0.24
Nodes (17): TestRespErrorDocumentCarriesTheResponseRequestID(), TestRespWriteS3Error_DoesNotLeakBackendDetail(), TestRespWriteS3Error_EscapesResource(), TestRespWriteS3Error_InternalTextStaysInternal(), TestRespWriteS3Error_NilError(), TestRespWriteS3Error_ResourceComposition(), TestRespWriteS3Error_StatusDrivesLogLevel(), TestRespWriteS3Error_WriteFailureIsLogged() (+9 more)

### Community 86 - "Client E2E Verdicts"
Cohesion: 0.10
Nodes (21): Assert what is stored, compare by SHA-256, One tool, one e2e job, A client suite asserts the target behaviour, e2e verdict table (Still broken section), rclone's X-Amz-Meta-Md5chksum annotation, rclone, use_multipart_etag = false, host_bucket must equal host_base (path style) (+13 more)

### Community 87 - "Backend Call Observation"
Cohesion: 0.38
Nodes (19): backendSnapshot(), ObserveBackendClient(), MonbackendRequest(), MoncounterValue(), MonresetBackendObservation(), TestMonBackendCancelledRequestIsNeitherCountedNorLogged(), TestMonBackendClassifiesFailures(), TestMonBackendFailureIsCountedAndLogged() (+11 more)

### Community 88 - "Copy and Delete Object Handlers"
Cohesion: 0.16
Nodes (17): TestCopyHandler_NotSupportedWithEncryption(), TestHandler_CopyObjectHeaderDetection(), TestHandler_CopyObjectNotSupported(), TestHandleDeleteObject_InputValidation(), TestHandleDeleteObject_S3Error(), TestHandleDeleteObject_Success(), TestHandleDeleteObject_VersionID(), TestHandleDeleteObjectIntegration_BaseObjectOperations() (+9 more)

### Community 89 - "Object Listing Handler"
Cohesion: 0.19
Nodes (10): callerOwner(), formatLastModified(), Handler, ownerEntry, clientWantsURLEncoding(), decodeBackendValue(), encodeForClient(), parseMaxKeys() (+2 more)

### Community 90 - "Segment Seal and Open Internals"
Cohesion: 0.16
Nodes (3): Codec, Checksum, Codec

### Community 91 - "Shutdown Order and Probes"
Cohesion: 0.12
Nodes (20): Drain Guard: 503 ServiceUnavailable With Retry-After While the Listener Stays Up, A Multipart Session Is Process-Local and Unfinishable Once the Process Exits, The Four-Step Shutdown Order, Every Upload the Process Still Holds Is Ended at the Backend, A Second Replica Answers NoSuchUpload for an Upload the First Holds, The Chart Refuses to Render a Second Replica, /livez: Liveness Is a Constant Success, No Probe Depends on Anything Outside the Process (+12 more)

### Community 92 - "SigV4 Service Coverage Tests"
Cohesion: 0.18
Nodes (19): github.com/sirupsen/logrus.Logger, S3AuthenticationService, MwauthService(), MwhmacSHA256(), MwsignDateHeaderRequest(), TestMwAuthenticateRequestDateHeaderPath(), TestMwAuthenticateRequestRejections(), TestMwAuthErrorsCarryTheS3ErrorCodeMarkers() (+11 more)

### Community 93 - "Monitoring Status Endpoint"
Cohesion: 0.19
Nodes (18): TestMonSetLicenseInfo(), SetLicenseInfo(), SetActiveProvider(), setStatusBuild(), setStatusLicense(), StatusSnapshot(), MonresetStatusState(), MonstatusBody() (+10 more)

### Community 94 - "ETag Marker Codec"
Cohesion: 0.18
Nodes (13): isHexDigest(), leadingSpace(), Mark(), requote(), TestEtagMarkOnlyTouchesTheDigestShape(), TestEtagRoundTripsForEveryShapeTheProxyAnswers(), TestEtagTheMarkerIsNotAShapeS3Produces(), TestEtagUnmarkIsShapeDrivenNotATrim() (+5 more)

### Community 95 - "Values Proxy"
Cohesion: 0.12
Nodes (20): In-Cluster MinIO Backend, minio-mkbucket Job (velero Bucket), minio-nodeport Service (30900), minio-root Credentials Secret, minio-tls Certificate Secret, UNSIGNED-PAYLOAD Requires TLS on the Backend Leg, AES Key via Chart Secret Wiring (s3ep-aes-key), affinity Must Be null, Not {} (+12 more)

### Community 96 - "Main"
Cohesion: 0.16
Nodes (16): initConfig(), main(), monitoringPlan(), runProxy(), runShutdownTail(), startupWarnings(), TestMainMonitoringPlanKeepsPprofIndependent(), TestMainShutdownClosesTheListenerEvenWhenTheSweepFails() (+8 more)

### Community 97 - "Hardening History"
Cohesion: 0.15
Nodes (19): kopia reads pack blobs with ranges, Under exit the decision is taken per object, 403 InvalidObjectState for objects this proxy did not write, A fault found mid-stream cuts the body, The refusals are 4xx deliberately, s3ep_object_integrity_failures_total, Pre-signed URLs and max_presign_expiry_seconds, Ranged reads (Range: bytes=...) (+11 more)

### Community 98 - "Integrity"
Cohesion: 0.12
Nodes (19): optimizations.multipart_session_idle_timeout, Associated data binds segment index and object key, s3ep-dek-algorithm, s3ep-encrypted-dek, s3ep-kek-algorithm, s3ep-kek-fingerprint, metadata_key_prefix is the proxy's exclusive namespace, Storage format s3ep-gcm-seg-v2 (+11 more)

### Community 99 - "Exec"
Cohesion: 0.19
Nodes (12): bytes.Buffer, regexp.Regexp, teeBuffer, FirstMatch(), Result, io2(), MustRun(), Redact() (+4 more)

### Community 100 - "Backend"
Cohesion: 0.17
Nodes (13): net/http.Response, sync/atomic.Pointer, classifyBackendFailure(), isConnectFailure(), isTimeoutFailure(), isTLSFailure(), observeRequestBody(), recordBackendFailure() (+5 more)

### Community 101 - "Logger"
Cohesion: 0.23
Nodes (17): LiclevelOf(), TestLicFormatTimeRemainingSubHour(), TestLicLogLicenseInfoExhaustedTimeRemaining(), TestLicLogLicenseInfoExpiringSoon(), TestLicLogLicenseInfoFullDetails(), TestLicLogLicenseInfoInvalidResult(), TestLicLogLicenseInfoMinimalClaims(), TestLicLogLicenseInfoWithoutClaims() (+9 more)

### Community 102 - "Subresource Documents"
Cohesion: 0.14
Nodes (16): accessControlListPD, accessControlPolicyDocument, bucketLoggingStatusDocument, grantDocument, granteeDocument, loggingEnabledDocument, ownerDocument, targetGrantsPD (+8 more)

### Community 103 - "Testing"
Cohesion: 0.12
Nodes (18): BACKEND DEVIATION log instead of a skip, Build tags separate the layers, not -short, Conformance cost rule and Budget.Authorize, Conformance suite (any backend), Two-process coverage merge, one toolchain, LINT_TAGS covers the tagged trees, MinIO is the oracle, AWS docs are the specification, Paid-run bucket policy (scoped sub-user) (+10 more)

### Community 104 - "Monitoring"
Cohesion: 0.12
Nodes (18): encryption-modes starts the proxy in process, Integration suites under test/integration, shutdown integration package, TLS integration run reaches the trailer decoder, AbortIncompleteMultipartUpload lifecycle rule, The exit provider needs no license, Graceful shutdown ends open uploads, Shipped configuration examples (+10 more)

### Community 105 - "Configuration"
Cohesion: 0.11
Nodes (18): config/default.yaml (the image's own configuration), ${VAR} environment reference mechanism, optimizations.multipart_part_size, S3EP_AES_KEY, S3EP_BACKEND_ENDPOINT, S3EP_LICENSE_TOKEN, Keep the key encryption key, One instance per release; the chart refuses a second (+10 more)

### Community 106 - "Monitoring"
Cohesion: 0.11
Nodes (18): Docker Compose deployment, Helm chart install, Three installation paths, The KEK belongs in a Secret, never in the ConfigMap, Unauthenticated metrics listener, PrometheusRule alerting rules ship with the chart, endpoint label is the route template, s3ep_active_connections (+10 more)

### Community 107 - "Checksum"
Cohesion: 0.19
Nodes (12): hash.Hash, declaredChecksums(), declaredPayloadHash(), DeclaresChecksum(), decodeDigest(), malformed(), mismatch(), TestChkPayloadHashIgnoresEverythingThatIsNotADigest() (+4 more)

### Community 108 - "Validator"
Cohesion: 0.18
Nodes (17): LicenseClaims, LicenseValidator, LicclaimsFor(), LicclearLicenseEnv(), LicforeignKey(), LicrequireStopReturns(), LicsignWith(), LictamperPayload() (+9 more)

### Community 109 - "Golangci"
Cohesion: 0.13
Nodes (17): .golangci.yml linter configuration, revive context-as-argument excluded under test/, ST and QF checks are excluded from staticcheck, gosec exclusions for the test tree, SA1019 excluded under test/, v2 needs its default exclusion presets declared, The version key is load-bearing, The demo stack is not optional for the integration suite (+9 more)

### Community 110 - "Segmented GCM"
Cohesion: 0.18
Nodes (14): Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length, maxWindowOverAsk, CiphertextSize(), crc32Combine(), gf2MatrixSquare(), gf2MatrixTimes(), PlaintextSize(), segmentCount() (+6 more)

### Community 111 - "S3auth Presigned"
Cohesion: 0.18
Nodes (11): net/url.Values, canonicalQueryString(), canonicalURI(), S3AuthenticationService, isPresignedRequest(), parseCredentialScope(), TestAuthCanonicalQueryIsSortedByName(), TestCanonicalQueryString() (+3 more)

### Community 112 - "Performance"
Cohesion: 0.27
Nodes (16): testing.B, ComparisonResult, PerformanceResult, weightedLeg, BenchmarkStreamingDownload(), BenchmarkStreamingUpload(), clearPerformanceTestBucket(), EnsureBenchmarkEnvironment() (+8 more)

### Community 113 - "Multipart"
Cohesion: 0.20
Nodes (15): MpuCrcwant(), TestMpuCrcARefusedPartStatesNoChecksum(), TestMpuCrcAReplacedPartAnswersTheNewChecksum(), TestMpuCrcEveryPartAnswersItsOwnChecksum(), TestMpuCrcTheCompletionAnswersTheWholeObjectChecksum(), TestMpuCrcTheCompletionCoversAHeldShortPart(), TestMpuCrcTheExitProviderStatesNoChecksum(), MpuBytesAllocated() (+7 more)

### Community 114 - "Harness"
Cohesion: 0.24
Nodes (15): GitInfo, Hardware, Measurement, RunInfo, collectGit(), collectHardware(), Emit(), Init() (+7 more)

### Community 115 - "Range Conformance"
Cohesion: 0.36
Nodes (14): rngCase, rngFixture, rngObserved, rngCasesFor(), rngNewFixture(), rngPayload(), rngRawGet(), rngViaMinIO() (+6 more)

### Community 116 - "Conformance Run"
Cohesion: 0.16
Nodes (13): The key reference has one home (README), An undefined configuration key refuses the start, Removed configuration keys now refuse the start, The X-Forwarded-For keyed failure counter, H-7 Dead security configuration knobs, getClientIP (deleted), pull_image(), S3EP_CONFORMANCE_BACKEND_NAME (+5 more)

### Community 117 - "Segment Tamper"
Cohesion: 0.36
Nodes (9): TamEnv, TamShape, TamAssertRefused(), TamDigest(), TamInspect(), TamSetup(), TestSegmentChainRefusesTamperedBytes(), TestSegmentChainRefusesTamperedMetadata() (+1 more)

### Community 118 - "Backend Client"
Cohesion: 0.21
Nodes (12): github.com/aws/aws-sdk-go-v2/aws/transport/http.BuildableClient, backendOptions(), TestBackendClientOptions_ChecksumsOnlyWhenRequired(), TestBackendClientOptions_EveryPathIsObserved(), TestBackendClientOptions_InsecureSkipVerifyReachesTheTransport(), TestBackendClientOptions_NoEndpointLeavesDefaults(), TestBackendClientOptions_PathStyleAndEndpoint(), TestBackendHTTPClient_SkipVerifyKeepsEverythingElse() (+4 more)

### Community 119 - "Validation"
Cohesion: 0.23
Nodes (14): CfgExitProviderConfig(), CfgValidClients(), Config, TestCfgValidateBackendTransport(), TestCfgValidateEncryptionProviderList(), TestCfgValidateLicenseAndEncryption(), TestCfgValidateMonitoringPprofBindAddress(), TestCfgValidateOptimizationsBoundaries() (+6 more)

### Community 120 - "Scenarios Atrest"
Cohesion: 0.19
Nodes (11): AssertStoredIsNotPlaintext(), Format, statSize(), CopyFile(), MD5Base64File(), MD5File(), UserMetadata(), TestR7_EncryptionAtRest() (+3 more)

### Community 121 - "Subresource Documents"
Cohesion: 0.21
Nodes (11): github.com/aws/aws-sdk-go-v2/service/s3/types.ObjectLockLegalHold, github.com/aws/aws-sdk-go-v2/service/s3/types.ObjectLockRetention, newLegalHoldDocument(), newRetentionDocument(), newTaggingDocument(), legalHoldDocument, retentionDocument, tagDocument (+3 more)

### Community 122 - "Shutdown"
Cohesion: 0.31
Nodes (11): time.Duration, sinceStart(), shutdownTail, docker(), openUploads(), preflight(), proxyLogs(), restartProxy() (+3 more)

### Community 123 - "Types"
Cohesion: 0.21
Nodes (12): jwt.RegisteredClaims, LicenseValidator, calculateTimeRemaining(), checkClaims(), TestLicCalculateTimeRemainingBoundaries(), TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim(), LicenseClaims, TestCalculateTimeRemaining() (+4 more)

### Community 124 - "Bucket Crud"
Cohesion: 0.20
Nodes (10): TestBucketHandle_BaseOperationsStillReachTheBackend(), TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed(), TestBucketHandle_UnroutedSubResourceIsNotABaseOperation(), TestHandleCreateBucket(), TestHandleDeleteBucket(), NewHandler(), TestMainBucketHandler_NewHandlers(), NewLifecycleHandler() (+2 more)

### Community 125 - "S3auth Robust"
Cohesion: 0.27
Nodes (3): S3AuthenticationService, stripExcessSpaces(), SignatureInfo

### Community 126 - "Crc64nvme"
Cohesion: 0.16
Nodes (7): BenchmarkChkCRC64NVME(), TestChkCRC64NVMEAllocatesNothingPerWrite(), TestChkCRC64NVMECheckValue(), crc64NVMEUpdate(), naiveCRC64NVME(), newCRC64NVME(), crc64NVME

### Community 127 - "Subresource Documents"
Cohesion: 0.19
Nodes (13): cloudFunctionConfigPD, eventBridgeConfigurationPD, filterRulePD, notificationConfigurationDocument, notificationFilterPD, queueConfigurationPD, s3KeyFilterPD, topicConfigurationPD (+5 more)

### Community 128 - "Complete"
Cohesion: 0.19
Nodes (8): context.CancelFunc, completionLocation(), firstForwardedValue(), CleanupContext(), TestUtlCleanupContext(), CompletedPart, CompleteMultipartUpload, UtlCtxKey

### Community 129 - "Metrics"
Cohesion: 0.21
Nodes (10): github.com/prometheus/client_golang/prometheus.Gatherer, github.com/prometheus/client_golang/prometheus.Labels, MongatherMetric(), TestMonGetKubernetesLabels(), TestMonLicenseDaysRemainingIsGone(), TestMonLicenseInfoCarriesNoLicenseeIdentity(), TestMonSetServerInfo(), Gatherer() (+2 more)

### Community 130 - "Report"
Cohesion: 0.32
Nodes (12): strings.Builder, InstrumentStatus, ratioKey, Run, fmtFloats(), fmtValue(), humanBytes(), orDash() (+4 more)

### Community 131 - "S3 Signing Helper"
Cohesion: 0.32
Nodes (3): time.Time, AWSV4Signer, pacedBody

### Community 132 - "Validator"
Cohesion: 0.21
Nodes (12): TestLicExpiryHandlerReplacesTheExit(), TestLicGracefulShutdownExitsWithRestartCode(), TestLicValidateLicenseWhitespaceTokenIsRejected(), TestLicValidateProviderTypeMessage(), LicenseValidator, NewValidator(), TestLicenseClaims(), TestNewValidator() (+4 more)

### Community 133 - "Readme"
Cohesion: 0.21
Nodes (12): Resident Memory Fell — 130 MB to 109 MB Peak, HeadBucket Answered 200 for a Missing Bucket, Local Performance Baseline Suite, Memory Bound (ADR 0020 D14) — the One Assertion, memory Instrument (RSS and Profiles), perf Build Tag — Local by Design, Instruments Record, They Do Not Assert, smallobject Instrument (+4 more)

### Community 134 - "Conditional Requests"
Cohesion: 0.36
Nodes (12): condOutcome, condPrecondition, condCodeOf(), condGet(), condHead(), condHTTPStatus(), condPayload(), condPutObject() (+4 more)

### Community 135 - "Compare"
Cohesion: 0.26
Nodes (12): combined_spread(), human(), key(), load(), lower_is_better(), machine_line(), main(), Compare two performance baseline runs. ./test/perf/compare.py perf-… (+4 more)

### Community 136 - "Pipeline"
Cohesion: 0.20
Nodes (12): ignore-scripts on the pull-request gate, The dry run must not drift from the release, Semantic-release toolchain composite action, Breaking-change marker inspection (commits, title, body), Two checkouts: named branch for same-repo, merge ref for forks, release:major label is the declaration of a major, Semantic-Release (dry run) job, E2E rclone (minio) job (+4 more)

### Community 137 - "Configmap"
Cohesion: 0.18
Nodes (11): Helm Chart job, Helm chart README, Injected blocks are added, never merged into .Values.config, configmap.yaml (renders config.yaml), checksum/config hashes the RENDERED ConfigMap, s3-encryption-proxy.validateTLS, Ingress Template, servicetls-certificate.yaml (cert-manager Certificate for the Service) (+3 more)

### Community 138 - "Subresource Chunked Body"
Cohesion: 0.36
Nodes (11): bktChunkedTarget, BktChunkedBody(), BktChunkedHandler(), bktChunkedOutput(), BktChunkedRequest(), bktChunkedTargets(), Handler, TestBktChunkedBodyWithACorrectTrailerIsApplied() (+3 more)

### Community 139 - "Throughput"
Cohesion: 0.24
Nodes (11): No Attribution of the Upload Gain to One Change, Above 4 MiB the Proxy Writes Faster Than the Direct Leg, The Upload Deficit Is Gone, Backend Refuses an aws-chunked Chunk Above 16 MiB, throughput Instrument, getTimed(), measureThroughput(), putTimed() (+3 more)

### Community 140 - "Docker Compose Demo"
Cohesion: 0.24
Nodes (11): Combined Coverage job (unit + integration), Integration Tests job, Unit Tests job, Demo Stack (docker compose), GOCOVER instrumented proxy build and 45s stop grace, minio service (HTTPS S3 backend), s3-encryption-proxy service (container proxy, :8080), s3-encryption-proxy-tls service (container proxy-tls, :8443) (+3 more)

### Community 141 - "Install"
Cohesion: 0.40
Nodes (10): check_prerequisites(), create_namespace(), get_version(), install_chart(), log_error(), log_info(), log_warn(), main() (+2 more)

### Community 142 - "Cryptofloor"
Cohesion: 0.24
Nodes (10): crypto/cipher.AEAD, 64 KiB Is Where the Instrument Stops Resolving, Downloads and the Crypto Floor Are Unchanged, emptyDir Data Volume — the Backend Must Not Depend on the Thing Under Test, openSegments(), sealSegments(), TestCryptoFloor(), Every Variant Must Allocate the Same (+2 more)

### Community 143 - "Validator"
Cohesion: 0.24
Nodes (10): crypto/rsa.PublicKey, TestLicLoadLicenseFromFile(), TestLicLoadLicenseFromFileBinding(), LoadLicense(), LoadLicenseFromEnv(), LoadLicenseFromFile(), parseEmbeddedPublicKey(), readLicenseFile() (+2 more)

### Community 144 - "Requestid"
Cohesion: 0.33
Nodes (9): EnsureRequestID(), NewRequestID(), RequestID(), RequestIDMiddleware(), TestMwEnsureRequestIDDoesNotRestateAnExistingID(), TestMwRequestIDIsEmptyOutsideTheMiddleware(), TestMwRequestIDIsStatedAndReachesTheHandler(), TestMwRequestIDIsUniquePerRequest() (+1 more)

### Community 145 - "Backend"
Cohesion: 0.38
Nodes (10): BackendClient(), caTrustingHTTPClient(), EmptyAndDeleteBucket(), EmptyBucket(), EnsureBucket(), OpenUploads(), ProxyClient(), ProxyETag() (+2 more)

### Community 146 - "Deployment"
Cohesion: 0.20
Nodes (9): s3-encryption-proxy.validatePreStop, HorizontalPodAutoscaler Template, PDB Render-Time Fail Guard, PodDisruptionBudget Template, Dedicated Monitoring Service Template, Namespace/Release Job Label Relabeling, Prometheus ServiceMonitor Template, preStopSleepSeconds (EndpointSlice withdrawal budget) (+1 more)

### Community 147 - "Router"
Cohesion: 0.31
Nodes (7): github.com/gorilla/mux.RouteMatch, github.com/gorilla/mux.Router, net/http.HandlerFunc, allowedMethods(), bucketRoute(), Server, isProbeRequest()

### Community 148 - "List"
Cohesion: 0.40
Nodes (5): callerOwner(), formatListTime(), ownerEntry, parseListingCount(), ListHandler

### Community 149 - "Segmented GCM Vector"
Cohesion: 0.40
Nodes (9): NewCodec(), Codec, TestSegVectorAssociatedData(), TestSegVectorObjectIsBoundToItsKey(), TestSegVectorSegmentIsBoundToItsIndex(), TestSegVectorTrailerFieldsAreWhereTheyWere(), TestSegVectorWholeObjectReadsBack(), vecBytes() (+1 more)

### Community 150 - "Segmented GCM Part"
Cohesion: 0.40
Nodes (9): Codec, partCodec(), sealInParts(), TestSegOpenTrailerRejectsTampering(), TestSegPartWriterOffsetIsAuthenticated(), TestSegPartWriterRefusesShortMiddlePart(), TestSegPartWriterRefusesUnalignedOffset(), TestSegPartWriterRoundTrip() (+1 more)

### Community 151 - "Subresource Documents"
Cohesion: 0.22
Nodes (8): replicationConfigurationDocument, github.com/aws/aws-sdk-go-v2/service/s3/types.LifecycleRule, github.com/aws/aws-sdk-go-v2/service/s3/types.ReplicationConfiguration, github.com/aws/aws-sdk-go-v2/service/s3/types.Tag, formatDate(), newLifecycleConfigurationDocument(), newReplicationConfigurationDocument(), newTagDocuments()

### Community 152 - "AES Example"
Cohesion: 0.22
Nodes (9): config/aes-example.yaml (demo HTTP proxy configuration), pprof binds loopback only because the heap holds DEKs, config/aes-tls-example.yaml (TLS listener configuration), s3-encryption-proxy.validateReplicas, One instance only: a multipart upload lives in the process that created it, Bounded data-key cache keyed by a digest of the wrapped key (D9), The stale-key defect: a cache keyed by identity, not by content, All three write paths produce the identical byte layout (D11) (+1 more)

### Community 153 - "Prometheusrule"
Cohesion: 0.22
Nodes (8): Every rule tells a human; nothing in the platform acts on one, Alert S3EPBackendTransportFailing (share, not count), Alert S3EPLicenseExpired, Alert S3EPLicenseExpiringSoon, Alert S3EPObjectIntegrityFailure, helm-unittest suite: alerting rules, monitoring.prometheusRule thresholds and windows, s3ep_object_integrity_failures_total, labelled by reason and phase (D15)

### Community 154 - "Integrity"
Cohesion: 0.22
Nodes (9): s3cmd sends no Content-MD5 for an object body, 400 BadDigest, Checksum throughput per algorithm, A client checksum is never forwarded and never stored, Declared client checksums are verified and dropped, DeleteObjects requires a digest (400 InvalidRequest), 400 InvalidDigest, s3_security.verify_payload_hash (+1 more)

### Community 157 - "Harness"
Cohesion: 0.47
Nodes (6): Env, Binary(), CACert(), DemoStack(), LoadEnv(), RepoRoot()

### Community 158 - "Pprof"
Cohesion: 0.33
Nodes (6): TestPprofNewServerConfiguration(), TestPprofServerReportsItsFailures(), TestPprofServerServesOnlyProfiling(), TestPprofServerStartServesAndShutsDownOnContextCancel(), NewPprofServer(), PprofServer

### Community 159 - "Smallobject"
Cohesion: 0.47
Nodes (8): leg, smallObjectBatch(), smallObjectGet(), smallObjectKeys(), smallObjectLegOrder(), smallObjectOps(), smallObjectPut(), TestSmallObjectRate()

### Community 160 - "ACL"
Cohesion: 0.32
Nodes (6): github.com/aws/aws-sdk-go-v2/service/s3/types.AccessControlPolicy, github.com/aws/aws-sdk-go-v2/service/s3/types.BucketCannedACL, mapCannedACLForBucket(), parseACLXMLForTest(), TestACLXMLParsing(), TestCannedACLMapping()

### Community 161 - "Listing Document"
Cohesion: 0.36
Nodes (7): commonPrefix, listBucketResultV1, listBucketResultV2, objectEntry, ownerEntry, commonPrefix, ownerEntry

### Community 163 - "027 Whole Object Read"
Cohesion: 0.25
Nodes (8): test/perf baseline records, never asserts throughput, x-amz-checksum-crc32c answered on write, GET and HEAD, What a read costs (tail-first whole-object GET), The first read of a whole-object GET (evaluation), Option C — issue the second request on the first answer's headers, Window options A, B, D and E, The second backend round trip costs small reads, serveWholeObject

### Community 164 - "Scenarios Read"
Cohesion: 0.46
Nodes (7): endpoint, corpus, suite, hashsum(), seedCorpus(), TestR3_Download(), TestR5_ReportedHashes()

### Community 165 - "Default Config"
Cohesion: 0.39
Nodes (7): cfgDefaultLicence(), cfgLoadFrom(), Config, TestCfgDefaultConfigAsksForExactlyTheDocumentedVariables(), TestCfgDefaultConfigFailsClosedOnEveryVariable(), TestCfgDefaultConfigLoads(), TestCfgShippedExamplesLoad()

### Community 167 - "Main"
Cohesion: 0.43
Nodes (7): StackInfo, SetStack(), detectStack(), insecureClient(), reachable(), readProxyConfig(), TestMain()

### Community 168 - "Scenarios Read"
Cohesion: 0.43
Nodes (7): corpus, suite, lineFor(), oneField(), reported(), seedCorpus(), TestS5_ReportedDigests()

### Community 169 - "Default"
Cohesion: 0.29
Nodes (4): Chart version, appVersion and image tag rewritten from the release tag, The image default is aes, not exit, so a missing key refuses the start, config/default.yaml (the configuration the image starts with), values.yaml (chart defaults)

### Community 170 - "Helpers"
Cohesion: 0.43
Nodes (3): github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsInput, github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsOutput, RtPxrequest

### Community 171 - "Summary"
Cohesion: 0.43
Nodes (6): main(), module_path(), percent(), Per-package coverage table for the CI report. Reads the text profiles that…, {location: (statements, count)} for one text-format profile., read_profile()

### Community 172 - "Rclone"
Cohesion: 0.33
Nodes (7): testing.M, WriteStepSummary(), reportDir(), TestMain(), reportDir(), TestMain(), TestMain()

### Community 173 - "E2e Up"
Cohesion: 0.48
Nodes (6): k(), KUBECONFIG, log(), need(), proxy_upgrade(), e2e-up.sh script

### Community 174 - "Conformance Paid"
Cohesion: 0.33
Nodes (6): Conformance (paid backends) job, Billed backends run on a schedule, never on push or pull_request, Secrets read through env, never interpolated into script text, Conformance (minio, localstack) job, S3EP_AES_KEY injected from a chart or external Secret, S3EP_AES_KEY supplied from generated .env, no key tracked

### Community 207 - "Check Breaking Changes"
Cohesion: 0.47
Nodes (5): add_message(), die(), FOOTER_PATTERN, HEADER_PATTERN, check-breaking-changes.sh script

### Community 208 - "Server"
Cohesion: 0.33
Nodes (3): net.Addr, sync.Once, RtPxfailingListener

### Community 211 - "Etag Marker"
Cohesion: 0.60
Nodes (5): MpuTagacceptParts(), TestMpuTagAClientReturnsTheMarkedPartTagsAndCompletes(), TestMpuTagExitProviderMarksNothingAndForwardsTheList(), TestMpuTagListPartsAnswersTheMarker(), TestMpuTagPartUploadsAnswerTheMarker()

### Community 212 - "Rangeread"
Cohesion: 0.67
Nodes (5): rangeCase, rangeCases(), rangeNote(), TestRangeRead(), timeRangeGet()

### Community 213 - "Stored"
Cohesion: 0.53
Nodes (5): AssertEncryptedAtRest(), StoredObject, ListStored(), MetadataValue(), ReadStored()

### Community 214 - "E2e Up"
Cohesion: 0.73
Nodes (5): install_rclone(), log(), need(), e2e-up.sh script, wait_for()

### Community 215 - "E2e Up"
Cohesion: 0.73
Nodes (5): install_s3cmd(), log(), need(), e2e-up.sh script, wait_for()

### Community 216 - "Values Velero"
Cohesion: 0.33
Nodes (6): csi-hostpath-snapclass with the Velero discovery label, BackupStorageLocation pointing s3Url at the proxy, Explicit image.tag override so the chart appVersion cannot drift from versions.env, uploaderType kopia with EnableCSI and the node agent, publicUrl 127.0.0.1:30443 for pre-signed URLs fetched by the host CLI, Velero Helm values for the e2e cluster

### Community 217 - "Bucket Policy"
Cohesion: 0.60
Nodes (5): analyzePolicySecurity(), TestBucketPolicyComplexStructures(), TestBucketPolicySecurityAnalysis(), TestBucketPolicyValidation(), validatePolicyJSON()

### Community 218 - "Constants"
Cohesion: 0.60
Nodes (3): simplePRNG, generateDeterministicData(), newSimplePRNG()

### Community 219 - "Subresource Documents"
Cohesion: 0.40
Nodes (4): corsConfigurationDocument, corsRuleDocument, github.com/aws/aws-sdk-go-v2/service/s3/types.CORSConfiguration, optional()

### Community 220 - "Values"
Cohesion: 0.40
Nodes (5): s3-encryption-proxy.probe helper, livenessProbe on /livez, probes.scheme derived from tls.enabled in the rendered config, readinessProbe on /readyz (the lifecycle signal), proxy-healthcheck sidecar polling /livez

### Community 221 - "Checksum"
Cohesion: 0.50
Nodes (5): ChkpayloadHash(), ChkverifyingParser(), TestChkPayloadHashIsVerifiedBesideAnotherDigest(), TestChkPayloadHashIsVerifiedWhenConfigured(), TestChkPayloadHashNeverSatisfiesTheDeleteObjectsRule()

### Community 222 - "Push"
Cohesion: 0.50
Nodes (4): Build Docker Image job (release:published), Release Helm Chart to GitHub Pages job, SBOM, provenance and Docker Scout on the released image, s3-encryption-proxy Helm chart (5.0.0)

### Community 223 - "S3 API"
Cohesion: 0.50
Nodes (4): s3cmd del --recursive and multipart are refused, optimizations.max_request_document_size, A query string containing ';' is 400 InvalidArgument, Sub-resources: 501 NotImplemented or 405 MethodNotAllowed

### Community 225 - "Renovate Assign On Failure"
Cohesion: 0.67
Nodes (3): Assign on Renovate Pipeline Failure job, Renovate Application (self-hosted, daily), Malware Scan (ClamAV over source)

### Community 226 - "Checksum"
Cohesion: 0.67
Nodes (3): BenchmarkChkAlgorithms(), chkKey(), chkAlgorithm

## Ambiguous Edges - Review These
- `Pass-Through Provider (none, renamed exit)` → `tink Provider Type (refused by name)`  [AMBIGUOUS]
  docs/adr/0004-one-local-key-provider.md · relation: references

## Knowledge Gaps
- **380 isolated node(s):** `HEADER_PATTERN`, `FOOTER_PATTERN`, `version-dry-run.sh script`, `github.com/guided-traffic/s3-encryption-proxy`, `dekCacheEntry` (+375 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 756 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **58 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Pass-Through Provider (none, renamed exit)` and `tink Provider Type (refused by name)`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **Why does `Error Conventions` connect `Configuration Loading and Upload Sweeper` to `S3 Error Mapping`, `Contributor Guide and KMS Provider ADR`, `KEK Fingerprint and Client Checksums`, `Proxy-Owned Part Layout`, `CORS Middleware and SSE-C Stripping`, `Checksum`, `Multipart Semantics and ETag Marker`, `Response Composition Rules`, `Release 5.0.0 Breaking Changes`, `Forward-or-Refuse and CI Gates`, `PUT Routing and Short-Part Budget`?**
  _High betweenness centrality (0.073) - this node is a cross-community bridge._
- **Why does `declaredChecksums()` connect `Checksum` to `Configuration Loading and Upload Sweeper`, `Replication and ACL Handlers`?**
  _High betweenness centrality (0.067) - this node is a cross-community bridge._
- **Why does `What One In-Flight Request Costs in Memory` connect `Multipart Semantics and ETag Marker` to `PUT Routing and Short-Part Budget`, `aws-chunked Streaming Decoder`, `DeleteObjects Handler Tests`, `Proxy-Owned Part Layout`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Are the 5 inferred relationships involving `EnsureMinIOAndProxyAvailable()` (e.g. with `TestUnauthenticatedProbes()` and `EnsureBenchmarkEnvironment()`) actually correct?**
  _`EnsureMinIOAndProxyAvailable()` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `HEADER_PATTERN`, `FOOTER_PATTERN`, `version-dry-run.sh script` to the rest of the system?**
  _380 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Object GET Coverage Tests` be split into smaller, more focused modules?**
  _Cohesion score 0.05903506143242433 - nodes in this community are weakly interconnected._