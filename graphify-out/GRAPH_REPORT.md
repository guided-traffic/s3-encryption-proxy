# Graph Report - s3-encryption-proxy  (2026-10-07)

## Corpus Check
- 460 files (77 re-extracted in this update) · ~819,504 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 5280 nodes · 15593 edges · 300 communities (186 shown, 114 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 1983 edges (avg confidence: 0.85)
- Token cost: 1,210,782 input · 0 output

## Community Hubs (Navigation)
- Object GET Coverage Tests
- Changelog and Project Front Page
- Velero E2E Backup Suite
- Multipart Handler Coverage Tests
- Bucket Handler Error Fixtures
- Bucket ACL and Accelerate Handlers
- ADR Web: Auth, Checksums, Config
- DEK Cache and Provider Manager
- Checksum and ETag Echo Tests
- SigV4 Header and Presign Tests
- Streaming Integration Test Harness
- Storage Format Integrity Guarantees
- Config Accessors and Dashboard Contract
- Hostile Backend and Key Material ADRs
- MockS3Backend Tagging and Policy
- Multipart Part Layout Decisions
- Object Response Header Helpers
- Orchestration Manager Coverage
- MockS3Backend Object Operations
- Release and Test Discipline ADRs
- Integration Corpus Seed and Budget
- AWS-Chunked Reader Tests
- Segment Encrypt Reader Tests
- Forward-or-Refuse Response Rules
- Keygen and KEK Factory
- Proxy Server Lifecycle Tests
- Bucket Sub-Resource Handlers
- Encryption Mode Proxy Instances
- Filename Encryption Design
- Request Parser and Framing Tests
- Filename Encryption Pass Engine
- Segmented Session Tests
- Encryption-at-Rest Assertions
- Multipart Handler Wiring
- Transfer Bounds and Shutdown
- Multipart Conformance Suite
- Performance Harness Shell Script
- Segmented Manager Streaming IO
- Segmented Session Lifecycle
- Ranged Read and Passthrough Tests
- MockS3Backend Multipart Operations
- rclone E2E Suite
- ListObjects Conformance Fixtures
- DeleteObjects Coverage Tests
- Bucket XML Document Types
- Configuration Struct and Accessors
- Config Loading Coverage Tests
- Monitoring Test Imports
- Integration Failing Writer Fixtures
- Bucket Location and Logging Tests
- XML Document Marshalling
- Renovate Dependency Configuration
- CI Pipeline and Renovate Jobs
- Bucket Sub-Resource Handler Registry
- Segmented GCM Reader and Writer
- Health Probes and Request Tracker
- Checksum Verifier Tests
- DeleteObjects Batch Documents
- Bucket CORS Handler
- Service TLS and Operator Certificates
- Semantic Release Toolchain
- Config Env Var Expansion
- Performance Baselines and Findings
- MockS3Backend Listing and Upload Stubs
- Error Mapping Coverage Tests
- License Tool
- Helm ConfigMap and Deployment
- Multipart Handler Constructors
- Object Dispatch Coverage Tests
- ListBuckets Coverage Tests
- S3 Error Mapping
- MockS3Backend Abort and ACL Stubs
- Segment Seal and Open Internals
- Object Metadata Coverage Tests
- E2E At-Rest Assertions
- s3cmd E2E Suite
- Performance Test Client
- Config Defaults and Provider Loading
- Monitoring Middleware Tests
- Object Listing Handler
- Documentation Homes and Ticket Lifecycle
- Validation
- Multipart ListParts Handler
- Integration Test Imports
- aws-chunked Streaming Decoder
- Health Probe Handler
- Harness
- Configuration
- Copy and Delete Object Handlers
- Vault Transit KEK Provider (parked)
- Subresource Documents
- Exec
- Performance
- Backend Call Observation
- ETag Marker Codec
- S3 Error Document Writer
- Main
- Client E2E Verdicts
- Backend
- Metrics
- Checksum
- Logger
- HTTP Middleware Coverage Tests
- Testing
- Monitoring
- Segment Tamper
- Integration Test Layers
- Object Sub-Resource Documents
- Streaming Upload and Sealed Checksum
- Object Sub-Resource Dispatch
- Range Conformance
- Demo Stack and Integration Jobs
- Backend Client
- Cryptofloor
- Types
- Monitoring Status Endpoint
- Authentication Integration Tests
- Crc64nvme
- Validator
- Conformance Run
- Entity Tag Marker
- License Loading
- Server
- Values Proxy
- Subresource Chunked Body
- Bucket Notification Documents
- Error Conventions
- Upload Length Guards and Exit Provider
- ListBuckets Root Handler
- CORS Middleware and SSE-C Stripping
- Encryption Validation Helper
- License Expiry Handling
- Readme
- Conditional Requests
- Compare
- Segmented GCM Range Reader
- Streaming Aws Decoder
- Integrity Operator Notes
- Monitoring Hijack Middleware
- Requestid
- Install
- Pprof
- Report
- E2E Harness Backend Client
- Abandoned Upload Sweeper
- Shutdown Order and Probes
- Short-Part Budget and Memory
- Client-Driven Multipart Paths
- Storage Format Invariants
- Segmented GCM
- Router
- Object Handler Dependencies
- Segmented GCM Part
- Renovate Automerge Settings
- GET Copy Benchmarks
- E2E Harness Environment
- Smallobject
- S3 Method Error Mapping Tests
- Shutdown
- Listing Document
- Bucket Versioning Handler
- Prometheusrule
- Performance Measurement Rules
- Default Config
- Bucket Replication Handler
- Multipart Checksum Echo Tests
- Logging Middleware
- Pipeline
- Default
- Golangci Lint Configuration
- Bucket CORS Documents
- Integrity Failure Reporting
- Multipart Complete Handler
- Rclone
- Monitoring Dashboard Contract
- Metadata
- E2e Up
- Throughput
- Bucket Replication Documents
- Keygen Command
- Check Breaking Changes
- ACL
- License Validator Runtime
- Etag Marker
- Payload Hash Verification Tests
- Rangeread
- Renovate Presets
- rclone E2E Bring-Up
- s3cmd E2E Bring-Up
- Values Velero
- Bucket Policy
- Constants
- Strict Configuration Loading
- Authentication Error Messages
- Monitoring HTTP Server
- Bucket Lifecycle Handler
- Multipart Counting Readers
- AES KEK Vector Tests
- Perf Stack Detection
- Push
- S3 API
- Middleware Non-Flusher Stub
- AES Example Configs
- Monitoring Backend Stub
- Monitoring Failing Body Stub
- Multipart
- Object Broken Reader Stub
- Object Error Reader Stub
- Exit Provider Example Config
- Multi-Provider Rotation Config
- Chart
- Request Memory Bounds
- Conformance Corpus Keys
- Known-Failure Manifest Rejected
- Target-Behaviour Test Rule
- Pre-Signed URL Limits
- Security Page Form
- Version Dry Run
- Segmented Part Sealing
- Multipart Error Reader Stub
- E2e Down
- s3cmd E2E Tear-Down
- Velero E2E Tear-Down
- Kind Config
- Renovate Workflow
- Certificate
- Grafana Dashboard
- Upload Forwards While Receiving
- Overlapped Receive and Send
- Retriable Part Copy
- Exit Provider Needs No Licence
- Exit Provider Decision
- Exit Provider Read Path
- Exit Provider Write Path
- Provider None Refused
- Exit Provider Start Warning
- Chart existingSecret Arm
- Chart Certificate DNS Names
- Manual clusterDomain
- Ingress Kept
- Probe Scheme Derivation
- Render-Time Refusals
- serviceTLS Values Block
- Expected Bucket Owner Unenforced
- CRC32C, Not the Entity Tag
- Cooperating Proxies Are Code
- Location Names the Proxy
- Compromised Proxy Impact
- Go

## God Nodes (most connected - your core abstractions)
1. `EnsureMinIOAndProxyAvailable()` - 109 edges
2. `NewErrorWriter()` - 91 edges
3. `NewTestContextWithTimeout()` - 80 edges
4. `MpuNewEnv()` - 71 edges
5. `ObjGetdo()` - 67 edges
6. `RandomString()` - 65 edges
7. `MockS3Backend` - 64 edges
8. `MockS3Backend` - 64 edges
9. `ObjGetpayload()` - 60 edges
10. `ADR 0013` - 59 edges

## Surprising Connections (you probably didn't know these)
- `WriteS3Error` --calls--> `MapError()`  [EXTRACTED]
  docs/developer/errors.md → internal/proxy/response/error_mapping.go
- `Error Conventions` --references--> `declaredChecksums()`  [EXTRACTED]
  docs/developer/errors.md → internal/proxy/request/checksum.go
- `Assert what is stored, compare by SHA-256` --references--> `TestSegmentChainRefusesTamperedBytes()`  [EXTRACTED]
  docs/developer/testing.md → test/integration/360-degree-variants/segment_tamper_test.go
- `ca_file per s3_backends entry (sole trust roots for that backend)` --references--> `backendHTTPClient()`  [EXTRACTED]
  docs/tickets/039-backend-certificate-verification-failure-is-named.md → internal/proxy/server.go
- `D-C: one licence token copied into each provisioned namespace` --references--> `checkClaims()`  [EXTRACTED]
  docs/tickets/038-s3-encryption-operator.md → internal/license/validator.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Graceful Shutdown of a Process That Holds Its Uploads** — docs_adr_0028_an_abandoned_upload_is_ended_not_forgotten_sweeper_aborts_at_backend, docs_adr_0029_the_shutdown_budget_finishes_work_and_sweeps_what_cannot_be_finished_shutdown_order, docs_adr_0033_a_proxy_instance_holds_its_uploads_single_replica_chart, docs_developer_multipart_shutdown_ends_what_it_holds, internal_orchestration_manager_abandonallsessions [EXTRACTED 0.95]
- **The graceful drain: /readyz, the preStop sleep and the derived grace period** — deploy_helm_s3_encryption_proxy_templates_deployment_prestop_sleep_hook, deploy_helm_s3_encryption_proxy_values_prestopsleepseconds, deploy_helm_s3_encryption_proxy_values_readinessprobe, deploy_helm_s3_encryption_proxy_values_terminationgraceperiodseconds [EXTRACTED 1.00]
- **The ADR 0020 D17 Instrument Set** — test_perf_readme_cryptofloor_instrument, test_perf_readme_local_performance_baseline, test_perf_readme_memory_instrument, test_perf_readme_rangeread_instrument, test_perf_readme_smallobject_instrument, test_perf_readme_throughput_instrument, test_perf_readme_unwrap_instrument, test_perf_readme_uploadpath_instrument [EXTRACTED 1.00]
- **Three Runs of One Hour Establish the Between-Run Spread** — perf_baseline_20260911t101344z_cc62c05_report_post_v2_wave5_run, perf_baseline_20260911t102319z_cc62c05_report_post_v2_wave5_drained_run, perf_baseline_20260911t103132z_cc62c05_findings_between_run_spread, perf_baseline_20260911t103132z_cc62c05_report_post_v2_wave5_record_run [EXTRACTED 1.00]
- **The tail-first whole-object read** — docs_operations_integrity_s3ep_gcm_seg_v2, docs_operations_integrity_x_amz_checksum_crc32c, docs_operations_s3_api_what_a_read_costs, docs_tickets_027_whole_object_read_first_window_evaluation, object_handler_fetchobjecttail [EXTRACTED 1.00]
- **The Upload Deficit Investigation** — perf_baseline_20260909t175340z_9f3fbd1_findings_upload_cliff_at_threshold, perf_baseline_20260910t062529z_9f3fbd1_findings_self_copy_is_not_the_cause, perf_baseline_20260910t062529z_9f3fbd1_findings_streaming_path_faster_than_backend, perf_baseline_20260910t090543z_530472c_findings_deficit_is_per_byte [EXTRACTED 1.00]
- **The Velero e2e kind stack** — test_e2e_velero_kind_config_cluster, test_e2e_velero_manifests_snapshotclass_csi_hostpath, test_e2e_velero_values_velero_values [EXTRACTED 1.00]
- **The Velero e2e TLS Chain — Listener, Backend CA, Backend Certificate** — test_e2e_velero_values_proxy_backend_ca_ssl_cert_file, test_e2e_velero_values_proxy_service_tls_byo_cert [INFERRED 0.85]
- **Operator Secret privilege and its bounds** — docs_tickets_038_s3_encryption_operator_cluster_scoped_operator, docs_tickets_038_s3_encryption_operator_no_cross_namespace_references, docs_tickets_038_s3_encryption_operator_validating_admission_policy_bound, docs_tickets_038_s3_encryption_operator_ownerreference_forgery_risk, docs_tickets_038_s3_encryption_operator_cluster_wide_secret_read_risk, docs_tickets_038_s3_encryption_operator_finding_m_privileged_pod_escape [EXTRACTED 1.00]
- **Per-credential carried versus minted model** — docs_tickets_038_s3_encryption_operator_credential_model, docs_tickets_038_s3_encryption_operator_licence_copy_per_namespace, docs_tickets_038_s3_encryption_operator_finding_c_shared_key_pair, docs_tickets_038_s3_encryption_operator_finding_am_fleet_wide_expiry [EXTRACTED 1.00]
- **Backend-trust session follow-ups (ADR 0037)** — docs_tickets_042_a_certificate_failure_is_not_retried, docs_tickets_043_the_backend_is_checked_before_the_first_client_request, docs_adr_0037_the_backend_leg_is_trusted_explicitly_and_its_failures_are_named, docs_tickets_042_a_certificate_failure_is_not_retried_backend_observer_classification [INFERRED 0.85]
- **Pinned-tail resolution: held part, forward, identity pin, verdicts, CAS state machine** — docs_tickets_036_high_availability_held_short_part_stays_in_holder, docs_tickets_036_high_availability_complete_forward_peer_listener, docs_tickets_036_high_availability_holder_address_and_instance_identity, docs_tickets_036_high_availability_forward_verdict_table, docs_tickets_036_high_availability_completion_state_machine, docs_tickets_036_high_availability_failover_pinned_upload_out_of_scope [EXTRACTED 1.00]
- **Shared session store design components** — docs_tickets_036_high_availability_shared_session_table_valkey_sentinel, docs_tickets_036_high_availability_session_layer_operations_interface, docs_tickets_036_high_availability_row_field_rule, docs_tickets_036_high_availability_row_keyed_by_upload_id_set_nx, docs_tickets_036_high_availability_member_register_rotation, docs_tickets_036_high_availability_store_clock_cas_sweep, docs_tickets_036_high_availability_high_availability_config_block [INFERRED 0.85]
- **Backend leg trust and named certificate failure** — docs_tickets_039_backend_certificate_verification_failure_is_named_ca_file_per_backend, docs_tickets_039_backend_certificate_verification_failure_is_named_ca_file_insecure_skip_verify_refusal, docs_tickets_039_backend_certificate_verification_failure_is_named_tls_certificate_class, docs_tickets_039_backend_certificate_verification_failure_is_named_backend_observer_below_sdk, docs_tickets_039_backend_certificate_verification_failure_is_named_backend_transport_failures_metric [EXTRACTED 1.00]
- **Pass engine operations: rename, rewrap, replicate** — docs_tickets_017_filename_encryption_pass_engine, docs_tickets_017_filename_encryption_rename_operation, docs_tickets_040_managed_buckets_kek_rewrap_pass, docs_tickets_037_multiple_backends_backend_parity_replicate [EXTRACTED 1.00]
- **Mixed-bucket name resolution machinery** — docs_tickets_017_filename_encryption_mode_set, docs_tickets_017_filename_encryption_other_form_directory_cache, docs_tickets_017_filename_encryption_multi_source_paged_listing, docs_tickets_017_filename_encryption_lockstep_dedup, docs_tickets_017_filename_encryption_request_scoped_resolution_memo, docs_tickets_017_filename_encryption_explicit_forwarder [EXTRACTED 1.00]
- **Self-copy rewrap hazards measured against MinIO** — docs_tickets_040_managed_buckets_no_reupload_refuted, docs_tickets_040_managed_buckets_cas_copy_if_match, docs_tickets_040_managed_buckets_worm_strip_on_self_copy, docs_tickets_040_managed_buckets_five_gib_copy_cliff, docs_tickets_040_managed_buckets_renamed_prefix_double_encryption [EXTRACTED 1.00]
- **Stored object format, envelope wrap and refusal form the integrity guarantee** — readme_s3ep_gcm_seg_v2_format, readme_envelope_encryption, readme_four_metadata_keys, readme_invalidobjectstate_refusal, claude_tail_first_read, docs_adr_0003_objects_are_an_authenticated_segment_chain [INFERRED 0.85]
- **E2E client suites gating the release, one job each** — claude_velero_e2e_suite, claude_rclone_e2e_suite, claude_s3cmd_e2e_suite, claude_e2e_harness, claude_one_tool_one_job, developer_ci_test_pipeline [EXTRACTED 1.00]
- **Helm pod drain: preStop sleep, readiness 503, shutdown budget and multipart sweep** — deploy_helm_s3_encryption_proxy_readme_prestop_sleep, deploy_helm_s3_encryption_proxy_readme_split_probes, deploy_helm_s3_encryption_proxy_readme_termination_grace_derivation, docs_adr_0029_the_shutdown_budget_finishes_work_and_sweeps_what_cannot_be_finished, docs_adr_0028_an_abandoned_upload_is_ended_not_forgotten, deploy_helm_s3_encryption_proxy_readme_single_instance [INFERRED 0.85]
- **Jobs gating semantic-release** — _github_workflows_test_pipeline_semantic_release, _github_workflows_test_pipeline_integration_tests, _github_workflows_test_pipeline_conformance, _github_workflows_test_pipeline_e2e_velero, _github_workflows_test_pipeline_e2e_rclone, _github_workflows_test_pipeline_e2e_s3cmd, _github_workflows_test_pipeline_unit_tests, _github_workflows_test_pipeline_race, _github_workflows_test_pipeline_coverage_report [EXTRACTED 1.00]
- **403 InvalidObjectState read-refusal and detection path** — docs_operations_integrity_foreign_object_refusal, docs_operations_integrity_mid_stream_abort, docs_security_stored_objects_failure_surfaces, docs_developer_request_paths_tail_first_get, docs_developer_request_paths_head_trailer_read, docs_operations_monitoring_s3ep_object_integrity_failures_total [INFERRED 0.85]
- **Upload checksum verification on the client leg** — docs_developer_request_paths_checksum_verifier, docs_security_upload_integrity_held_final_byte, docs_security_upload_integrity_client_leg_verification, docs_operations_integrity_client_checksum_verification, docs_security_upload_integrity_checksum_family_claimed, docs_developer_request_paths_complete_unverified_body [INFERRED 0.85]
- **The four s3ep- metadata keys of the stored format** — docs_adr_0002_one_data_key_per_object_s3ep_kek_algorithm, docs_adr_0002_one_data_key_per_object_s3ep_encrypted_dek, docs_adr_0002_one_data_key_per_object_s3ep_kek_fingerprint, docs_adr_0009_the_metadata_prefix_is_the_proxys_namespace_metadata_prefix_namespace [EXTRACTED 1.00]
- **Fail-closed refusals answered 403 InvalidObjectState** — docs_adr_0001_the_backend_is_hostile_fail_closed_on_foreign_objects, docs_adr_0003_objects_are_an_authenticated_segment_chain_wrapped_key_auth_failure_403, docs_adr_0004_one_local_key_provider_tampered_wrap_distinct_error, docs_adr_0002_one_data_key_per_object_key_layer_fails_closed [INFERRED 0.85]
- **Request and response honesty: forward, refuse or state, never fake success** — docs_adr_0007_forward_it_or_refuse_it_forward_or_refuse_rule, docs_adr_0007_forward_it_or_refuse_it_error_under_success_status, docs_adr_0008_every_response_describes_the_proxy_proxy_composed_response, docs_adr_0008_every_response_describes_the_proxy_non_error_status_failure, docs_adr_0008_every_response_describes_the_proxy_typed_error_translation [INFERRED 0.85]
- **Fail-Closed Startup Refusals** — docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_unknown_key_refuses_start, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_unworkable_config_refuses_start, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_unreadable_config_refuses_start, docs_adr_0016_the_license_is_a_startup_gate_license_startup_gate, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_backend_scheme_decides_tls [INFERRED 0.85]
- **Upload-Leg Checksum Integrity** — docs_adr_0012_client_checksums_are_verified_never_forwarded_checksum_verified_against_plaintext, docs_adr_0012_client_checksums_are_verified_never_forwarded_missing_trailer_checksum_fails, docs_adr_0012_client_checksums_are_verified_never_forwarded_baddigest_invaliddigest, docs_adr_0012_client_checksums_are_verified_never_forwarded_verdict_before_commit, docs_adr_0012_client_checksums_are_verified_never_forwarded_checksum_never_forwarded, docs_adr_0012_client_checksums_are_verified_never_forwarded_no_plaintext_checksum_in_metadata [EXTRACTED 1.00]
- **Breaking-Change Release Process** — docs_adr_0017_stored_data_compatibility_is_not_owed_no_at_rest_compatibility_owed, docs_adr_0017_stored_data_compatibility_is_not_owed_release_notes_state_break, docs_adr_0018_a_major_release_is_declared_by_a_label_release_major_label, docs_adr_0018_a_major_release_is_declared_by_a_label_breaking_commit_guard, docs_adr_0018_a_major_release_is_declared_by_a_label_long_lived_major_bundle_branch, docs_adr_0019_integration_and_e2e_tests_are_the_product_e2e_gates_release [INFERRED 0.85]
- **Documentation governance: ADRs, tickets, five homes, per-perspective security pages** — docs_adr_0022_tickets_are_work_lists_that_get_archived_adr_is_decision_record, docs_adr_0022_tickets_are_work_lists_that_get_archived_ticket_is_work_list, docs_adr_0022_tickets_are_work_lists_that_get_archived_extraction_is_the_close, docs_adr_0035_the_readme_advertises_the_reference_lives_under_docs_five_documentation_homes, docs_adr_0038_the_security_architecture_is_one_page_per_perspective_one_page_per_perspective, docs_adr_0022_tickets_are_work_lists_that_get_archived_adr_no_code_references [INFERRED 0.85]
- **Pod shutdown lifecycle: preStop hold, readiness drain, grace period** — docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_prestop_hold, docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_readyz_readiness, docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_termination_grace_period_sum, docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_livez_liveness [EXTRACTED 1.00]
- **Backend failure reporting across status, counters, logs and the client answer** — docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_backend_transport_failure_counter, docs_adr_0034_a_probe_reports_the_process_never_its_dependencies_status_document, docs_adr_0037_the_backend_leg_is_trusted_explicitly_and_its_failures_are_named_tls_certificate_failure_class, docs_adr_0037_the_backend_leg_is_trusted_explicitly_and_its_failures_are_named_backend_failure_is_internal_error [INFERRED 0.85]

## Communities (300 total, 114 thin omitted)

### Community 0 - "Object GET Coverage Tests"
Cohesion: 0.05
Nodes (135): TestObjCrcARangedReadStatesNoChecksum(), TestObjCrcAWriteAndAReadAgreeOnTheChecksum(), ObjTagserve(), TestObjTagAProxyPinNeverCarriesTheMarker(), TestObjTagEveryObjectVerbAnswersTheMarker(), TestObjTagPreconditionsAreUnmarkedOnTheWayOut(), TestObjTagTheInternalPinIsNeverMarked(), ObjGetdigest() (+127 more)

### Community 1 - "Changelog and Project Front Page"
Cohesion: 0.04
Nodes (67): CHANGELOG, encryption.integrity_verification modes removed, Provider type none removed, becomes exit provider, Release 4.0.0 (2026-09-07): prefix validation, pprof on loopback listener, Release 5.1.0 (2026-09-15): probes refined, one endpoint per question, Release 5.1.5 (2026-10-07): dependency updates, CLAUDE.md AI Coding Instructions, Adding a new KEK provider checklist (stable Fingerprint) (+59 more)

### Community 2 - "Velero E2E Backup Suite"
Cohesion: 0.08
Nodes (83): sinceStart(), AssertEncryptedAtRest(), MetadataValue(), backendClient(), caTrustingHTTPClient(), listBackendObjects(), proxyClient(), readBackendObject() (+75 more)

### Community 3 - "Multipart Handler Coverage Tests"
Cohesion: 0.09
Nodes (83): MpuAPIError(), MpuBytesAllocated(), MpuChain(), MpuCompleteBody(), MpuDigest(), MpuNewEnv(), MpuNewEnvWithProvider(), MpuNewExitEnv() (+75 more)

### Community 4 - "Bucket Handler Error Fixtures"
Cohesion: 0.07
Nodes (75): BktclosingBody, BktfailingReader, BktfailingWriter, BktforeignHits, errBkt, TestBktTagAMultipartTagInAListingIsNotMarked(), TestBktTagBothListingsMarkADigestShapedTag(), TestBktTagTheExitProviderListingIsUnmarked() (+67 more)

### Community 5 - "Bucket ACL and Accelerate Handlers"
Cohesion: 0.05
Nodes (16): LifecycleHandler, LoggingHandler, TaggingHandler, WebsiteHandler, Hlthprobe, Handler, readDocument(), UserMetadata() (+8 more)

### Community 6 - "ADR Web: Auth, Checksums, Config"
Cohesion: 0.04
Nodes (32): Licence routes: chart-managed Secret or S3EP_LICENSE_TOKEN env, ADR 0013, ADR 0014: authentication is sigv4 no rate limiting, ADR 0016, ADR 0021, ADR 0030, ADR 0034, ADR 0037 (+24 more)

### Community 7 - "DEK Cache and Provider Manager"
Cohesion: 0.06
Nodes (48): Case, Recorder, row, buildDEKCacheKey(), OrcMetaAESProvider(), OrcMetaCachingManager(), OrcMetaNewProviderManager(), OrcMetaProviderConfig() (+40 more)

### Community 8 - "Checksum and ETag Echo Tests"
Cohesion: 0.11
Nodes (70): ObjCrcwant(), TestObjCrcADeclaredChecksumAndTheAnsweredOneAgree(), TestObjCrcAnEmptyObjectStillAnswersAChecksum(), TestObjCrcARefusedUploadStatesNoChecksum(), TestObjCrcIsNotTheChecksumOfTheStoredBytes(), TestObjCrcSingleRequestPutAnswersThePlaintextChecksum(), TestObjCrcTheExitProviderStatesNoChecksum(), TestObjCrcTheProducerAnswersTheSameChecksumAsAPut() (+62 more)

### Community 9 - "SigV4 Header and Presign Tests"
Cohesion: 0.05
Nodes (51): Canonical header whitespace collapsing matches aws-sdk-go-v2, SigV4 header and pre-signed forms, No multi-tenancy, per-client keys or rate limiting, MwauthService(), MwhmacSHA256(), MwsignDateHeaderRequest(), TestMwAuthenticateRequestDateHeaderPath(), TestMwAuthenticateRequestRejections() (+43 more)

### Community 10 - "Streaming Integration Test Harness"
Cohesion: 0.07
Nodes (61): PerformanceMetrics, StreamingReader, TestLargeMultipart500MB(), cleanupTestFile(), downloadLargeFile(), generateLargeFileTestData(), NewStreamingReader(), TestComprehensiveMultipartUpload() (+53 more)

### Community 11 - "Storage Format Integrity Guarantees"
Cohesion: 0.04
Nodes (31): Internal multipart producer (concurrency+1 buffers, receive overlaps send), ADR 0003, Plaintext length is a pure function of stored length, ADR 0010: Sizes and listings describe the plaintext, ADR 0012: client checksums are verified never forwarded, ADR 0024: an upload forwards while it receives, ADR 0032: The entity tag is a change token, Developer: Storage format (+23 more)

### Community 12 - "Config Accessors and Dashboard Contract"
Cohesion: 0.08
Nodes (54): TestCfgGetActiveProviderErrorPaths(), TestCfgGetActiveProviderReturnsLivePointer(), TestCfgGetAllProvidersReflectsSlice(), TestCfgIsValidProviderType(), TestCfgStreamingAccessors(), TestGetMultipartPartSize(), TestOptimizationsConfig(), TestCORSComplexConfiguration() (+46 more)

### Community 13 - "Hostile Backend and Key Material ADRs"
Cohesion: 0.05
Nodes (21): S3EP_AES_KEY injected from a chart or external Secret, ADR 0002, s3ep-encrypted-dek metadata key, s3ep-kek-algorithm metadata key, s3ep-kek-fingerprint metadata key, Bounded unwrapped data key cache, s3ep-gcm-seg-v2 AES-256-GCM segment chain, ADR 0004: One local key provider (+13 more)

### Community 15 - "Multipart Part Layout Decisions"
Cohesion: 0.05
Nodes (33): ADR 0001: The backend is hostile, ADR 0011, ADR 0020: Performance is measured before and after, Stored objects: what is written, what it guarantees, what leaks, Upload integrity: the client leg, Ticket 026: SSE-C on every verb, or not at all, MinIO accepts SSE-C only over TLS (tests in TLS suite), SSE-C algorithm and key-MD5 echo headers join the response allowlist (+25 more)

### Community 16 - "Object Response Header Helpers"
Cohesion: 0.09
Nodes (25): RecordObjectIntegrityFailure(), PlaintextSize(), applyResponseOverrides(), integrityReason(), objectVersionID(), writeEntityHeaders(), WriteSSEHeaders(), writeVersionHeaders() (+17 more)

### Community 17 - "Orchestration Manager Coverage"
Cohesion: 0.10
Nodes (47): OrcMgrAESConfig(), OrcMgrNewManager(), orcMgrOpenSession(), OrcMgrPrefixPtr(), orcMgrSessionCount(), TestOrcMgrAccessorsAndMetadataFiltering(), TestOrcMgrBackgroundCleanupRemovesExpiredSessions(), TestOrcMgrCleanupExpiredSessions() (+39 more)

### Community 19 - "Release and Test Discipline ADRs"
Cohesion: 0.06
Nodes (12): Semantic-release generated changelog with quality metrics, ADR 0006: the proxy serves any s3 client, CloudNativePG Barman, Velero (with kopia), ADR 0017, ADR 0018, ADR 0019: Integration and e2e tests are the product, ADR 0027: conformance is asserted against a backend that is not minio (+4 more)

### Community 20 - "Integration Corpus Seed and Budget"
Cohesion: 0.11
Nodes (41): Budget, CorpusObject, bucketAlreadyThere(), seedClientMultipart(), TestCorpusStillExercisesEveryWritePath(), TestSeed(), TestSeedIsComplete(), TestBudgetRefusesWhatItCannotPayFor() (+33 more)

### Community 21 - "AWS-Chunked Reader Tests"
Cohesion: 0.10
Nodes (42): ChunkedReader, tbTrickleReader, createAWSChunkedDataMultiChunk(), createAWSChunkedEncodedBody(), downloadObjectSimple(), generateTestData(), NewChunkedReader(), parseChunkedDataManually() (+34 more)

### Community 22 - "Segment Encrypt Reader Tests"
Cohesion: 0.09
Nodes (43): errAfterReader, errReader, TestSegEncryptReaderChecksum(), TestSegEncryptReaderMatchesWriter(), TestSegEncryptReaderPropagatesSourceError(), TestSegEncryptReaderRoundTrip(), TestSegEncryptReaderStaysFailedAfterAnError(), TestSegEncryptReaderTinyReads() (+35 more)

### Community 23 - "Forward-or-Refuse Response Rules"
Cohesion: 0.06
Nodes (10): Response timestamps via response.S3Timestamp, omitempty for absent values, ADR 0007: Forward it or refuse it, ?tagging, ?retention, ?legal-hold passthrough, Ten storage headers forwarded on every upload path, ADR 0008: every response describes the proxy, S3 backend interface (52 SDK methods), Refusals: where the proxy says no rather than pretending, Managed-bucket list in configuration (+2 more)

### Community 24 - "Keygen and KEK Factory"
Cohesion: 0.09
Nodes (34): KeyEncryptionType, FacFactoryWithAES(), TestFacAESFingerprintIsDerivedFromTheKeyNotHashedFromIt(), TestFacCreateKeyEncryptorFromConfigTypes(), TestFacGetKeyEncryptor(), TestFacKeyEncryptionTypeConstants(), TestFacRegisterKeyEncryptorKeysByFingerprint(), Factory (+26 more)

### Community 25 - "Proxy Server Lifecycle Tests"
Cohesion: 0.09
Nodes (37): RtPxconfig(), RtPxnewFailingListener(), RtPxstringPtr(), TestRtPxListenerBudgetsReachTheServer(), TestRtPxMetadataPrefixResolution(), TestRtPxNewServerLoadsAllProvidersButActivatesOne(), TestRtPxNewServerRejectsUnusableConfig(), TestRtPxProbesReportShutdownState() (+29 more)

### Community 26 - "Bucket Sub-Resource Handlers"
Cohesion: 0.15
Nodes (38): NewAccelerateHandler(), TestAccelerateHandler_AccelerateStatuses(), TestAccelerateHandler_AccelerationBenefits(), TestAccelerateHandler_BucketNamingRequirements(), TestAccelerateHandler_ContentTypeHandling(), TestAccelerateHandler_Handle(), TestAccelerateHandler_HandleErrors(), TestAccelerateHandler_XMLValidation() (+30 more)

### Community 27 - "Encryption Mode Proxy Instances"
Cohesion: 0.15
Nodes (37): AESProxyTestInstance, ExitProxyTestInstance, getKeys(), IsAESProviderActive(), StartAESProviderProxyInstance(), TestAESProvider_LargeFile(), TestAESProvider_MetadataHandling(), TestAESProviderMultipleObjects() (+29 more)

### Community 28 - "Filename Encryption Design"
Cohesion: 0.06
Nodes (20): ADR 0023: Filename encryption, ADR 0025, Ticket 017: Filename encryption, Velero leaf census and name side channels, Listing encoding asymmetry across one backend call, Lockstep duplicate drop across listing phases, Mixed-bucket name leak via clear-form fallback requests, Multi-source paged listing with proxy-minted continuation token (F3) (+12 more)

### Community 29 - "Request Parser and Framing Tests"
Cohesion: 0.10
Nodes (34): newChunkedRequest(), mustStream(), newTestRequest(), TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented(), TestReqPlaintextContentLength(), TestReqReadAllSized_HintBoundaries(), TestReqReadBody_ForgedDecodedContentLength(), TestReqReadBody_IdentityBodyReadError() (+26 more)

### Community 30 - "Filename Encryption Pass Engine"
Cohesion: 0.07
Nodes (33): Multipart abandoner closure calls raw SDK client outside the interface, names CLI surface: wrap, map, unmap, audit, migrate, Off-state accident: feature off on a mapped bucket serves ciphertext names (D-J), Extensible pass engine: enumerate/plan/transfer/verify/delete/report/config (F11), Rename operation (names migrate), Request-scoped resolution memo, s3ep-admin operator binary (favourite home of tools), Ticket 025: Vault as a key provider (parked) (+25 more)

### Community 31 - "Segmented Session Tests"
Cohesion: 0.14
Nodes (36): assembleSession(), segCompleted(), segRegisteredSession(), segStreamPart(), slowlyOver(), TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused(), TestSegmentedSessionASlowPartOutlivesTheIdleTimeout(), TestSegmentedSessionEveryPartMovesTheIdleClock() (+28 more)

### Community 32 - "Encryption-at-Rest Assertions"
Cohesion: 0.17
Nodes (31): EncObjectView, EncStored, EncAPICode(), EncAssertBodyIsCiphertext(), EncAssertEncryptedAtRest(), EncAssertHeadersClean(), EncAssertNoMetadataLeak(), EncAssertRoundTrip() (+23 more)

### Community 33 - "Multipart Handler Wiring"
Cohesion: 0.15
Nodes (21): Manager, NewAbortHandler(), NewCompleteHandler(), NewCopyHandler(), NewHandler(), NewListHandler(), NewACLHandler(), NewHandler() (+13 more)

### Community 34 - "Transfer Bounds and Shutdown"
Cohesion: 0.06
Nodes (18): Release 5.0.2: multipart idle clock moves while a part arrives, ADR 0015: a transfer is bounded by the client and by shutdown, ADR 0028: an abandoned upload is ended not forgotten, ADR 0029, Key management: hierarchy, providers, custody, rotation, Tenancy and privilege: the blast radius, Security: Threat model, Roles table (operator, client, proxy, backend, legs) (+10 more)

### Community 35 - "Multipart Conformance Suite"
Cohesion: 0.20
Nodes (34): MpuShape, MpuTarget, TestRangeReadErrors(), TestRangeReadsOnEncryptedObjects(), NewTestContextWithTimeout(), ProxyIsTLS(), MpuAbortQuiet(), MpuComplete() (+26 more)

### Community 36 - "Performance Harness Shell Script"
Cohesion: 0.15
Nodes (34): build_project(), check_dependencies(), check_services(), cleanup(), generate_markdown_report(), get_iso_timestamp(), get_timestamp(), log_error() (+26 more)

### Community 37 - "Segmented Manager Streaming IO"
Cohesion: 0.10
Nodes (9): Manager, PartStoredLen(), PlanRange(), ObjGetclosedBody, ObjGetcloseErrReader, SealedPart, SegmentedUpload, SegmentedWrite (+1 more)

### Community 38 - "Segmented Session Lifecycle"
Cohesion: 0.10
Nodes (6): CanStreamPart(), Manager, SegmentedSession, FinalPart, sessionPart, touchingReader

### Community 39 - "Ranged Read and Passthrough Tests"
Cohesion: 0.21
Nodes (29): ckAnswer, NewTestContext(), RandomString(), TestDeleteObjectFunctionality(), TestListBucketsOperation(), TestListBucketsPassthrough(), TestPassthroughOperations_DeleteObjects(), TestPassthroughOperations_GetObjectTorrent() (+21 more)

### Community 41 - "rclone E2E Suite"
Cohesion: 0.15
Nodes (24): corpus, endpoint, remote, suite, SHA256Bytes(), endpoints(), newSuite(), preflight() (+16 more)

### Community 42 - "ListObjects Conformance Fixtures"
Cohesion: 0.15
Nodes (31): lstBulkFixture, lstRefFixture, lstAssertElementOrder(), lstBody(), lstBulkKeys(), lstChildElements(), lstCiphertextSize(), lstElementSequence() (+23 more)

### Community 43 - "DeleteObjects Coverage Tests"
Cohesion: 0.13
Nodes (29): ObjMiscbodyDigest(), ObjMiscdeleteObjects(), ObjMiscnewFailWriter(), ObjMiscparseDeleteResult(), TestObjMiscDeleteObjectsBackendErrorsAreMapped(), TestObjMiscDeleteObjectsBodyReadErrorIsRefused(), TestObjMiscDeleteObjectsEmptyBodyIsMalformed(), TestObjMiscDeleteObjectsEmptyDocumentIsRefused() (+21 more)

### Community 44 - "Bucket XML Document Types"
Cohesion: 0.12
Nodes (31): abortIncompleteUploadDocument, accessControlXlatePD, encryptionConfigPD, errorDocumentPD, indexDocumentPD, lifecycleAndDocument, lifecycleConfigurationDocument, lifecycleExpirationDocument (+23 more)

### Community 45 - "Configuration Struct and Accessors"
Cohesion: 0.12
Nodes (29): EncryptionConfig, MonitoringConfig, OptimizationsConfig, S3BackendConfig, S3SecurityConfig, TLSConfig, Defaults Written Into Viper Before the File Is Read, A Provider Block Swallows Its Own Parameters (the ErrorUnused Boundary) (+21 more)

### Community 46 - "Config Loading Coverage Tests"
Cohesion: 0.28
Nodes (32): InitConfig(), Load(), CfgNoLicense(), CfgResetViper(), CfgWriteConfigFile(), TestCfgAbsentSessionIdleTimeoutTakesTheDefault(), TestCfgBackendsAreAList(), TestCfgInitConfigDiscoversFileInHomeDirectory() (+24 more)

### Community 47 - "Monitoring Test Imports"
Cohesion: 0.09
Nodes (15): MonfreeAddr(), Monserve(), TestMonMetricsEndpointExportsTheRequestMetrics(), TestMonNewServerConfiguration(), TestMonServerEndpointsSurviveWriteFailures(), TestMonServerLivenessEndpoint(), TestMonServerMetricsEndpoint(), TestMonServerNeverServesPprof() (+7 more)

### Community 48 - "Integration Failing Writer Fixtures"
Cohesion: 0.15
Nodes (25): ObjIntfailingWriter, HdrCaptureResponseBody(), HdrCaptureResponseHeaders(), HdrCleanupBucket(), HdrGetHeaders(), HdrHeadHeaders(), HdrIsContentDigestShape(), HdrIsObjectHeader() (+17 more)

### Community 49 - "Bucket Location and Logging Tests"
Cohesion: 0.09
Nodes (26): TestBucketLocationErrorHandling(), TestBucketLocationMethodHandling(), TestBucketLocationRegionMapping(), TestBucketLocationSecurityScenarios(), TestBucketLocationXMLFormat(), TestBucketLocationXMLValidation(), TestHandleBucketLocation_GET_NoClient(), TestBucketLoggingErrorHandling() (+18 more)

### Community 50 - "XML Document Marshalling"
Cohesion: 0.08
Nodes (26): accelerateConfigurationDocument, BkterrorDoc, locationConstraintDocument, requestPaymentConfigurationDocument, versioningConfigurationDocument, TestRespNewXMLWriter(), commonPrefix, completeMultipartUploadResult (+18 more)

### Community 51 - "Renovate Dependency Configuration"
Cohesion: 0.06
Nodes (30): assignAutomerge, automerge, automergeType, branchConcurrentLimit, commitMessagePrefix, configMigration, customManagers, dockerfile (+22 more)

### Community 52 - "CI Pipeline and Renovate Jobs"
Cohesion: 0.09
Nodes (26): Assign on Renovate Pipeline Failure job, Self-hosted Renovate job, Test pipeline workflow (test-pipeline.yml), Combined Coverage job, E2E rclone (minio) job, E2E s3cmd (minio) job, E2E Velero (kind) job, GoSec Security Scan job (+18 more)

### Community 53 - "Bucket Sub-Resource Handler Registry"
Cohesion: 0.09
Nodes (18): AccelerateHandler, ACLHandler, BaseSubResourceHandler, LocationHandler, NotificationHandler, RequestPaymentHandler, NewACLHandler(), TestBucketHandle_BaseOperationsStillReachTheBackend() (+10 more)

### Community 54 - "Segmented GCM Reader and Writer"
Cohesion: 0.13
Nodes (5): reader, sealSink, Writer, Codec, EncryptReader

### Community 55 - "Health Probes and Request Tracker"
Cohesion: 0.12
Nodes (10): Handler, AWSV4Signer, StripAWSChunked(), TestStripAWSChunked(), ReadEntityHeaders(), ReadStorageAttributes(), ReadUploadHeaders(), pacedBody (+2 more)

### Community 56 - "Checksum Verifier Tests"
Cohesion: 0.25
Nodes (29): BenchmarkChkVerifyingRead(), chkAssertOutcome(), chkChunkedRequest(), chkEncode(), chkFramed(), chkIdentityRequest(), chkParser(), chkPayload() (+21 more)

### Community 57 - "DeleteObjects Batch Documents"
Cohesion: 0.24
Nodes (29): DelDeletedEntry, DelErrorDoc, DelErrorEntry, DelRequestDoc, DelRequestObject, DelResponse, DelResultDoc, DelBuildDoc() (+21 more)

### Community 58 - "Bucket CORS Handler"
Cohesion: 0.11
Nodes (4): CORSHandler, PolicyHandler, ReplicationHandler, Handler

### Community 59 - "Service TLS and Operator Certificates"
Cohesion: 0.12
Nodes (20): ADR 0026, ADR 0033, Ticket 038: s3-encryption-operator, Accepted risk: cluster-wide Secret read bounded by nothing, Configuration read only at start (no SIGHUP, no watch), Operator credential model (backend carried, client minted, licence copied, KEK open), Finding AM: one licence token guarantees fleet-wide simultaneous expiry, Finding C: one key pair serves as backend and client credential (+12 more)

### Community 60 - "Semantic Release Toolchain"
Cohesion: 0.07
Nodes (25): ADR-0017, ADR-0018, author, description, devDependencies, conventional-changelog-conventionalcommits, semantic-release, @semantic-release/changelog (+17 more)

### Community 61 - "Config Env Var Expansion"
Cohesion: 0.12
Nodes (25): ${VAR} References Inside a Named List of Fields, Where each secret lives, default_config_test.go — the ${VAR} set of the shipped image config, TestCfgExpandConfigEnvVarsErrorPerField(), TestCfgExpandConfigEnvVarsExpandsEveryField(), expandConfigEnvVars(), expandEnvVars(), TestExpandConfigEnvVars_MissingProviderVarReturnsError() (+17 more)

### Community 62 - "Performance Baselines and Findings"
Cohesion: 0.10
Nodes (22): closeDrained(), wave3 — 1 MiB Ranged Read at 153.8 MiB/s (68 % of Direct), wave3 Run — uploadpath and memory Skipped, Baseline Run wave3-checksums (20260911T064137Z-233d559), Baseline Run post-v2-wave5 (20260911T101344Z-cc62c05), Baseline Run post-v2-wave5-drained (20260911T102319Z-cc62c05), Between-Run Spread — Anything Under 15 % End to End Is the Machine, The Multipart Leg Moved (+33 % to +47 %) (+14 more)

### Community 64 - "Error Mapping Coverage Tests"
Cohesion: 0.15
Nodes (23): RespAPIErrorNoResponse(), RespCapturingLogger(), RespFindEntry(), RespNewFailingWriter(), RespStatusOnlyError(), RespWrapMarker(), TestRespMapErrorBackend5xxKeepsReasonPhrase(), TestRespMapErrorCodeForStatusFallback() (+15 more)

### Community 65 - "License Tool"
Cohesion: 0.18
Nodes (22): collectLicenseInfo(), LicTcaptureStdout(), LicTextractToken(), LicTkey(), LicTwithStdin(), LicTwritePEM(), TestLicTCollectLicenseInfo(), TestLicTEndToEnd() (+14 more)

### Community 66 - "Helm ConfigMap and Deployment"
Cohesion: 0.09
Nodes (19): configmap.yaml (renders config.yaml), s3-encryption-proxy.probe helper, s3-encryption-proxy.validatePreStop, s3-encryption-proxy.validateReplicas, s3-encryption-proxy.validateTLS, HorizontalPodAutoscaler Template, Ingress Template, PodDisruptionBudget Template (+11 more)

### Community 67 - "Multipart Handler Constructors"
Cohesion: 0.23
Nodes (23): NewCreateHandler(), alignedPlaintext(), assertDetachedContext(), setupMultipartTestEnv(), TestAbortHandler_AbortSurvivesCancelledRequestContext(), TestAbortHandler_Handle(), TestCompleteHandler_AbortSurvivesClientDisconnect(), TestCompleteHandler_Handle() (+15 more)

### Community 68 - "Object Dispatch Coverage Tests"
Cohesion: 0.24
Nodes (23): ObjMiscallowedMethods(), ObjMiscassertNotImplemented(), ObjMiscdo(), ObjMiscdoFunc(), ObjMiscnewHandler(), ObjMiscsealed(), TestObjMiscACLHandlerDirectEntryPoint(), TestObjMiscHandleACLBeatsTaggingWhenBothArePresent() (+15 more)

### Community 69 - "ListBuckets Coverage Tests"
Cohesion: 0.15
Nodes (18): RtPxdoListBuckets(), RtPxlistBuckets(), RtPxnewHandler(), TestRtPxListBucketsBackendErrors(), TestRtPxListBucketsClientDisconnect(), TestRtPxListBucketsDocumentShape(), TestRtPxListBucketsEchoesPrefixAndContinuationToken(), TestRtPxListBucketsEmptyAccount() (+10 more)

### Community 70 - "S3 Error Mapping"
Cohesion: 0.15
Nodes (23): IsChecksumFailure(), IsChecksumUnsupported(), checksumVerdict(), codeForStatus(), internalMarkers, MapError(), discardLogger(), sdkError() (+15 more)

### Community 72 - "Segment Seal and Open Internals"
Cohesion: 0.13
Nodes (8): Handlers that reach past orchestration into the format package, objectTail, Codec, crc32Combine(), gf2MatrixSquare(), gf2MatrixTimes(), Checksum, Codec

### Community 73 - "Object Metadata Coverage Tests"
Cohesion: 0.13
Nodes (21): ObjMiscnewHandlerWithPrefix(), copyWithPooledBuffer(), ObjMiscdigest(), ObjMiscpayload(), ObjMiscstore(), TestObjMiscCleanMetadataEdgeInputs(), TestObjMiscCleanMetadataHonoursACustomPrefix(), TestObjMiscCleanMetadataStripsOnlyThePrefixedKeys() (+13 more)

### Community 74 - "E2E At-Rest Assertions"
Cohesion: 0.13
Nodes (19): corpus, AssertStoredIsNotPlaintext(), Format, statSize(), CopyFile(), MD5Base64File(), MD5File(), StoredObject (+11 more)

### Community 75 - "s3cmd E2E Suite"
Cohesion: 0.21
Nodes (20): endpoint, suite, SHA256File(), WriteRandomFile(), boolWord(), containsStr(), endpoints(), newSuite() (+12 more)

### Community 76 - "Performance Test Client"
Cohesion: 0.18
Nodes (19): rssSampler, emptyBucket(), ensureBucket(), httpClientFor(), isAlreadyOwned(), legsFor(), newS3Client(), testCAPool() (+11 more)

### Community 77 - "Config Defaults and Provider Loading"
Cohesion: 0.12
Nodes (22): loadProviderConfigs(), setDefaults(), TestGetActiveProvider(), TestGetActiveProvider_NoAlias(), TestGetActiveProvider_NotFound(), TestGetAllProviders(), TestListenerBudgetDefaults(), TestLoad_MissingTargetEndpoint() (+14 more)

### Community 78 - "Monitoring Middleware Tests"
Cohesion: 0.13
Nodes (12): MonrequestMetric(), TestMonHTTPMiddlewareDefaultsToStatus200(), TestMonHTTPMiddlewareRecordsRoutedRequest(), TestMonHTTPMiddlewareTracksActiveConnections(), TestMonHTTPMiddlewareUnknownEndpoint(), TestMonResponseWriterCapturesStatusCode(), TestMonResponseWriterForwardsToTheLiveWriter(), TestMonResponseWriterKeepsTheWriterCapabilities() (+4 more)

### Community 79 - "Object Listing Handler"
Cohesion: 0.16
Nodes (10): callerOwner(), formatLastModified(), Handler, clientWantsURLEncoding(), decodeBackendValue(), encodeForClient(), parseMaxKeys(), ClientIdentity() (+2 more)

### Community 80 - "Documentation Homes and Ticket Lifecycle"
Cohesion: 0.11
Nodes (5): Five documentation homes (ADR, developer, operations, security, tickets), ADR 0022, ADR 0035: the readme advertises the reference lives under docs, ADR 0038: The security architecture is one page per perspective, ADR numbers assigned by hand with no uniqueness check

### Community 81 - "Validation"
Cohesion: 0.16
Nodes (20): backendUsesTLS(), validate(), validateBackendTransport(), validateLicenseAndEncryption(), validateS3Clients(), validateS3Security(), CfgExitProviderConfig(), CfgValidClients() (+12 more)

### Community 82 - "Multipart ListParts Handler"
Cohesion: 0.17
Nodes (6): ListParts answered from the session part table, clientETag(), callerOwner(), formatListTime(), parseListingCount(), UploadHandler

### Community 83 - "Integration Test Imports"
Cohesion: 0.15
Nodes (11): CksAssertChecksumSealed(), CksAssertServedChecksum(), CksCheckWritePath(), CksDelete(), CksExpected(), CksOffsets(), CksPayload(), CksStored() (+3 more)

### Community 84 - "aws-chunked Streaming Decoder"
Cohesion: 0.23
Nodes (20): newStreamingAWSChunkedReader(), testLogger(), TestStreamingAWSChunkedReader_Errors(), TestStreamingAWSChunkedReader_MultipleTrailers(), TestStreamingAWSChunkedReader_RoundTrip(), TestStreamingAWSChunkedReader_SizeMismatch(), TestStreamingAWSChunkedReader_SmallReads(), TestReqStreamingAWSChunkedReader_BlankLineBetweenChunks() (+12 more)

### Community 85 - "Health Probe Handler"
Cohesion: 0.20
Nodes (16): HlthfailingWriter, HlthrecordingWriter, HlthnewFailingWriter(), HlthnewTestLogger(), TestHlthLiveIsConstantEvenWhileDraining(), TestHlthLogHealthRequests(), TestHlthNewHandler(), TestHlthReadyReportsTheDrain() (+8 more)

### Community 86 - "Harness"
Cohesion: 0.19
Nodes (20): GitInfo, Hardware, InstrumentStatus, Measurement, Run, RunInfo, StackInfo, collectGit() (+12 more)

### Community 87 - "Configuration"
Cohesion: 0.10
Nodes (19): config/default.yaml (the image's own configuration), ${VAR} environment reference mechanism, optimizations.multipart_part_size, S3EP_AES_KEY, S3EP_BACKEND_ENDPOINT, S3EP_LICENSE_TOKEN, An undefined configuration key refuses the start, One instance per release; the chart refuses a second (+11 more)

### Community 88 - "Copy and Delete Object Handlers"
Cohesion: 0.16
Nodes (17): TestCopyHandler_NotSupportedWithEncryption(), TestHandler_CopyObjectHeaderDetection(), TestHandler_CopyObjectNotSupported(), TestHandleDeleteObject_InputValidation(), TestHandleDeleteObject_S3Error(), TestHandleDeleteObject_Success(), TestHandleDeleteObject_VersionID(), TestHandleDeleteObjectIntegration_BaseObjectOperations() (+9 more)

### Community 89 - "Vault Transit KEK Provider (parked)"
Cohesion: 0.10
Nodes (17): The HMAC Is The Entire Difference, The Container Memory Limit Is Nowhere Near Reached, pre-v2 Baseline Findings, Ranged Reads: The Alignment Before-Column, The Proxy Barely Gets Faster With More Clients, RSA Unwrap Is Four Orders Of Magnitude Off The Local Provider, Upload Falls Off A Cliff At The Routing Threshold, pre-v2 Baseline Run Record (+9 more)

### Community 90 - "Subresource Documents"
Cohesion: 0.13
Nodes (12): accessControlListPD, accessControlPolicyDocument, bucketLoggingStatusDocument, grantDocument, granteeDocument, loggingEnabledDocument, ownerDocument, targetGrantsPD (+4 more)

### Community 91 - "Exec"
Cohesion: 0.18
Nodes (10): teeBuffer, FirstMatch(), Result, io2(), MustRun(), Redact(), Run(), RunWithEnv() (+2 more)

### Community 92 - "Performance"
Cohesion: 0.21
Nodes (18): BenchmarkChkAlgorithms(), chkKey(), ComparisonResult, PerformanceResult, weightedLeg, chkAlgorithm, BenchmarkStreamingDownload(), BenchmarkStreamingUpload() (+10 more)

### Community 93 - "Backend Call Observation"
Cohesion: 0.38
Nodes (18): backendSnapshot(), ObserveBackendClient(), MonbackendRequest(), MoncounterValue(), MonresetBackendObservation(), TestMonBackendCancelledRequestIsNeitherCountedNorLogged(), TestMonBackendClassifiesFailures(), TestMonBackendFailureIsCountedAndLogged() (+10 more)

### Community 94 - "ETag Marker Codec"
Cohesion: 0.18
Nodes (13): isHexDigest(), leadingSpace(), Mark(), requote(), TestEtagMarkOnlyTouchesTheDigestShape(), TestEtagRoundTripsForEveryShapeTheProxyAnswers(), TestEtagTheMarkerIsNotAShapeS3Produces(), TestEtagUnmarkIsShapeDrivenNotATrim() (+5 more)

### Community 95 - "S3 Error Document Writer"
Cohesion: 0.28
Nodes (16): TestRespErrorDocumentCarriesTheResponseRequestID(), TestRespWriteS3Error_DoesNotLeakBackendDetail(), TestRespWriteS3Error_EscapesResource(), TestRespWriteS3Error_InternalTextStaysInternal(), TestRespWriteS3Error_NilError(), TestRespWriteS3Error_ResourceComposition(), TestRespWriteS3Error_StatusDrivesLogLevel(), TestRespWriteS3Error_WriteFailureIsLogged() (+8 more)

### Community 96 - "Main"
Cohesion: 0.16
Nodes (13): initConfig(), monitoringPlan(), runProxy(), runShutdownTail(), startupWarnings(), TestMainMonitoringPlanKeepsPprofIndependent(), TestMainShutdownClosesTheListenerEvenWhenTheSweepFails(), TestMainShutdownExhaustedBudgetStillSweepsAndCloses() (+5 more)

### Community 97 - "Client E2E Verdicts"
Cohesion: 0.11
Nodes (17): test/perf baseline records, never asserts throughput, e2e verdict table (Still broken section), rclone's X-Amz-Meta-Md5chksum annotation, rclone, use_multipart_etag = false, host_bucket must equal host_base (path style), s3cmd sends no Content-MD5 for an object body, s3cmd (+9 more)

### Community 98 - "Backend"
Cohesion: 0.18
Nodes (12): Backend observer on o.HTTPClient below the SDK (classifyBackendFailure: dns/tls/timeout/connect/other), s3ep_backend_transport_failures_total{class}, classifyBackendFailure(), isConnectFailure(), isTimeoutFailure(), isTLSFailure(), observeRequestBody(), recordBackendFailure() (+4 more)

### Community 99 - "Metrics"
Cohesion: 0.18
Nodes (14): MondefaultMetric(), MongatherMetric(), TestMonGetKubernetesLabels(), TestMonLicenseDaysRemainingIsGone(), TestMonLicenseInfoCarriesNoLicenseeIdentity(), TestMonSetLicenseInfo(), TestMonSetServerInfo(), Gatherer() (+6 more)

### Community 100 - "Checksum"
Cohesion: 0.18
Nodes (12): declaredChecksums(), declaredPayloadHash(), DeclaresChecksum(), decodeDigest(), malformed(), mismatch(), TestChkPayloadHashIgnoresEverythingThatIsNotADigest(), Verdict() (+4 more)

### Community 101 - "Logger"
Cohesion: 0.23
Nodes (17): LiclevelOf(), TestLicFormatTimeRemainingSubHour(), TestLicLogLicenseInfoExhaustedTimeRemaining(), TestLicLogLicenseInfoExpiringSoon(), TestLicLogLicenseInfoFullDetails(), TestLicLogLicenseInfoInvalidResult(), TestLicLogLicenseInfoMinimalClaims(), TestLicLogLicenseInfoWithoutClaims() (+9 more)

### Community 102 - "HTTP Middleware Coverage Tests"
Cohesion: 0.20
Nodes (10): MwechoHandler(), MwtestLogger(), TestMwCORSMiddleware(), TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader(), TestMwLoggerMiddleware(), TestMwRequestTracker(), TestMwResponseWriterForwardsToTheLiveWriter(), TestMwResponseWriterKeepsTheWriterCapabilities() (+2 more)

### Community 103 - "Testing"
Cohesion: 0.12
Nodes (14): Conformance cost rule and Budget.Authorize, Conformance suite (any backend), Two-process coverage merge, one toolchain, LINT_TAGS covers the tagged trees, Paid-run bucket policy (scoped sub-user), Five test layers, x-amz-expected-bucket-owner forwarded on every verb, Part numbers run 1 to 9999 (+6 more)

### Community 104 - "Monitoring"
Cohesion: 0.11
Nodes (16): Docker Compose deployment, Helm chart install, Three installation paths, Unauthenticated metrics listener, PrometheusRule alerting rules ship with the chart, s3ep_active_connections, s3ep_backend_last_failure_timestamp, s3ep_backend_last_response_timestamp (+8 more)

### Community 105 - "Segment Tamper"
Cohesion: 0.29
Nodes (10): TamEnv, TamShape, What a ranged read proves, TamAssertRefused(), TamDigest(), TamInspect(), TamSetup(), TestSegmentChainRefusesTamperedBytes() (+2 more)

### Community 106 - "Integration Test Layers"
Cohesion: 0.12
Nodes (13): encryption-modes starts the proxy in process, Integration suites under test/integration, shutdown integration package, AbortIncompleteMultipartUpload lifecycle rule, Graceful shutdown ends open uploads, optimizations.multipart_session_idle_timeout, Shipped configuration examples, GET /livez (+5 more)

### Community 107 - "Object Sub-Resource Documents"
Cohesion: 0.17
Nodes (9): newTagDocuments(), newLegalHoldDocument(), newRetentionDocument(), newTaggingDocument(), legalHoldDocument, retentionDocument, tagDocument, taggingDocument (+1 more)

### Community 108 - "Streaming Upload and Sealed Checksum"
Cohesion: 0.24
Nodes (13): TestContext, downloadAndVerifyWithSDK(), performMultipartUploadWithSDK(), TestStreamingMultipartUpload(), TestStreamingVsStandardPerformance(), TestVbClientDrivenMultipartEntityHeaders(), TestVbDeleteMarkerAndVersionDelete(), TestVbMultipartUploadLeavesExactlyOneVersion() (+5 more)

### Community 109 - "Object Sub-Resource Dispatch"
Cohesion: 0.14
Nodes (3): Handler, IsAWSProtocolQueryParam(), TestReqIsAWSProtocolQueryParam()

### Community 110 - "Range Conformance"
Cohesion: 0.36
Nodes (14): rngCase, rngFixture, rngObserved, rngCasesFor(), rngNewFixture(), rngPayload(), rngRawGet(), rngViaMinIO() (+6 more)

### Community 111 - "Demo Stack and Integration Jobs"
Cohesion: 0.13
Nodes (13): Integration Tests job, Performance summary and badge step, Demo MinIO service (HTTPS, pgsty/minio), Proxy healthcheck sidecar, Demo proxy service (container proxy, :8080), Demo TLS proxy service (container proxy-tls, :8443), S3 explorer through the proxy (encrypted-manager), Vault dev server (transit engine) (+5 more)

### Community 112 - "Backend Client"
Cohesion: 0.19
Nodes (11): backendOptions(), TestBackendClientOptions_ChecksumsOnlyWhenRequired(), TestBackendClientOptions_EveryPathIsObserved(), TestBackendClientOptions_InsecureSkipVerifyReachesTheTransport(), TestBackendClientOptions_NoEndpointLeavesDefaults(), TestBackendClientOptions_PathStyleAndEndpoint(), TestBackendHTTPClient_SkipVerifyKeepsEverythingElse(), TestBackendHTTPClient_VerifiesByDefault() (+3 more)

### Community 113 - "Cryptofloor"
Cohesion: 0.17
Nodes (8): AESProvider, 64 KiB Is Where the Instrument Stops Resolving, Downloads and the Crypto Floor Are Unchanged, openSegments(), sealSegments(), TestCryptoFloor(), cryptofloor Instrument (In-Process Crypto Floor), Noise Floor — Below 10 % Is the Machine

### Community 114 - "Types"
Cohesion: 0.17
Nodes (10): LicenseValidator, calculateTimeRemaining(), checkClaims(), TestLicCalculateTimeRemainingBoundaries(), TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim(), TestCalculateTimeRemaining(), LicenseClaims, LicenseInfo (+2 more)

### Community 115 - "Monitoring Status Endpoint"
Cohesion: 0.25
Nodes (14): SetActiveProvider(), StatusSnapshot(), MonresetStatusState(), MonstatusBody(), TestMonStatusBeforeAnythingHappened(), TestMonStatusCarriesBuildAndActiveProvider(), TestMonStatusEndpointRendersTheObservedBackend(), TestMonStatusExpiredLicenseRemainsAtZero() (+6 more)

### Community 116 - "Authentication Integration Tests"
Cohesion: 0.27
Nodes (13): SimpleTestContext, authErrorCode(), NewSimpleTestContext(), proxyHost(), sendWellFormedAuthHeader(), TestAuthentication(), testClockSkewProtection(), testEnterpriseSecurityConfiguration() (+5 more)

### Community 117 - "Crc64nvme"
Cohesion: 0.15
Nodes (7): BenchmarkChkCRC64NVME(), TestChkCRC64NVMEAllocatesNothingPerWrite(), TestChkCRC64NVMECheckValue(), crc64NVMEUpdate(), naiveCRC64NVME(), newCRC64NVME(), crc64NVME

### Community 118 - "Validator"
Cohesion: 0.21
Nodes (10): LicclaimsFor(), LicforeignKey(), LicrequireStopReturns(), LicsignWith(), LictamperPayload(), TestLicParseEmbeddedPublicKey(), TestLicStartRuntimeMonitoringIsStartedOnlyOnce(), TestLicStopIsIdempotent() (+2 more)

### Community 119 - "Conformance Run"
Cohesion: 0.19
Nodes (9): Conformance (paid backends) job, Conformance matrix job (minio, localstack), pull_image(), S3EP_CONFORMANCE_BACKEND_NAME, S3EP_CONFORMANCE_PROXY_ENDPOINT, S3EP_CONFORMANCE_SEGMENT_SIZE, conformance-run.sh script, start_localstack() (+1 more)

### Community 120 - "Entity Tag Marker"
Cohesion: 0.14
Nodes (11): The -0 Entity Tag Marker, Under the Exit Provider There Is No Session at All, ListParts Is Answered From the Session Part Table, Multipart Uploads, The Part Size Is Inferred and Must Survive Arrival Order, The Trailer's Part Number Is Reserved, Parts Are Segment-Aligned, ErrPartNumberReserved (+3 more)

### Community 121 - "License Loading"
Cohesion: 0.19
Nodes (12): LicclearLicenseEnv(), TestLicLoadLicenseFromEnvIsOneName(), TestLicLoadLicenseFromFile(), TestLicLoadLicenseFromFileBinding(), TestLicLoadLicensePrefersEnvironment(), LoadLicense(), LoadLicenseFromEnv(), LoadLicenseFromFile() (+4 more)

### Community 122 - "Server"
Cohesion: 0.19
Nodes (3): RequestTracker, NewRequestTracker(), Server

### Community 123 - "Values Proxy"
Cohesion: 0.15
Nodes (8): AES Key via Chart Secret Wiring (s3ep-aes-key), Embedded Proxy Configuration for the Velero Run, Velero e2e Proxy Helm Values, S3EP_LICENSE_TOKEN from Secret s3ep-license, livenessProbe /livez, readinessProbe /readyz, serviceTLS with the Test PKI Secret s3ep-tls, Missing License Token Blocks Every Instrument

### Community 124 - "Subresource Chunked Body"
Cohesion: 0.32
Nodes (10): bktChunkedTarget, BktChunkedBody(), BktChunkedHandler(), bktChunkedOutput(), BktChunkedRequest(), bktChunkedTargets(), TestBktChunkedBodyWithACorrectTrailerIsApplied(), TestBktChunkedBodyWithAMalformedTrailerIsRefused() (+2 more)

### Community 125 - "Bucket Notification Documents"
Cohesion: 0.19
Nodes (11): cloudFunctionConfigPD, eventBridgeConfigurationPD, filterRulePD, notificationConfigurationDocument, notificationFilterPD, queueConfigurationPD, s3KeyFilterPD, topicConfigurationPD (+3 more)

### Community 126 - "Error Conventions"
Cohesion: 0.15
Nodes (11): Error Conventions, 403 InvalidObjectState: The Three Integrity Refusals, Five Error Codes the Proxy Invented, ProviderManager.DecryptDEK, SegmentedSession.PartChecksum, WriteChecksumVerdict, ErrorWriter.writeErrorDocument, WriteGenericError (+3 more)

### Community 128 - "ListBuckets Root Handler"
Cohesion: 0.23
Nodes (10): NewHandler(), TestHandleListBuckets(), TestHandleListBucketsError(), TestHandleListBucketsMultipleBuckets(), TestNewHandler(), TestRtPxNewHandlerIsUsableImmediately(), ListAllMyBucketsResult, S3Bucket (+2 more)

### Community 130 - "Encryption Validation Helper"
Cohesion: 0.35
Nodes (12): EncryptionValidationConfig, EncryptionValidationResult, AssertDataIsEncrypted(), calculateShannonEntropy(), CompareEncryptionStrength(), ConfigForDataSize(), containsForbiddenPatterns(), containsReadableStrings() (+4 more)

### Community 131 - "License Expiry Handling"
Cohesion: 0.21
Nodes (11): TestLicExpiryHandlerReplacesTheExit(), TestLicGracefulShutdownExitsWithRestartCode(), TestLicValidateLicenseWhitespaceTokenIsRejected(), TestLicValidateProviderTypeMessage(), NewValidator(), TestLicenseClaims(), TestNewValidator(), TestValidateLicense_EmptyToken() (+3 more)

### Community 132 - "Readme"
Cohesion: 0.21
Nodes (10): Resident Memory Fell — 130 MB to 109 MB Peak, HeadBucket Answered 200 for a Missing Bucket, Local Performance Baseline Suite, Memory Bound (ADR 0020 D14) — the One Assertion, memory Instrument (RSS and Profiles), smallobject Instrument, unwrap Instrument (KEK Wrap/Unwrap), median() (+2 more)

### Community 133 - "Conditional Requests"
Cohesion: 0.36
Nodes (12): condOutcome, condPrecondition, condCodeOf(), condGet(), condHead(), condHTTPStatus(), condPayload(), condPutObject() (+4 more)

### Community 134 - "Compare"
Cohesion: 0.26
Nodes (9): combined_spread(), human(), key(), load(), lower_is_better(), machine_line(), main(), reference_key() (+1 more)

### Community 135 - "Segmented GCM Range Reader"
Cohesion: 0.21
Nodes (5): rangeReader, Codec, Window, segmentStoredLen(), segmentCount()

### Community 137 - "Integrity Operator Notes"
Cohesion: 0.18
Nodes (10): kopia reads pack blobs with ranges, Under exit the decision is taken per object, 403 InvalidObjectState for objects this proxy did not write, s3ep-dek-algorithm, metadata_key_prefix is the proxy's exclusive namespace, stored = plaintext + ceil(plaintext/65536)*28 + 40, HEAD, GET and listings report the plaintext size, Ranged reads (Range: bytes=...) (+2 more)

### Community 140 - "Requestid"
Cohesion: 0.29
Nodes (9): EnsureRequestID(), NewRequestID(), RequestID(), RequestIDMiddleware(), TestMwEnsureRequestIDDoesNotRestateAnExistingID(), TestMwRequestIDIsEmptyOutsideTheMiddleware(), TestMwRequestIDIsStatedAndReachesTheHandler(), TestMwRequestIDIsUniquePerRequest() (+1 more)

### Community 141 - "Install"
Cohesion: 0.40
Nodes (10): check_prerequisites(), create_namespace(), get_version(), install_chart(), log_error(), log_info(), log_warn(), main() (+2 more)

### Community 142 - "Pprof"
Cohesion: 0.25
Nodes (6): TestPprofNewServerConfiguration(), TestPprofServerReportsItsFailures(), TestPprofServerServesOnlyProfiling(), TestPprofServerStartServesAndShutsDownOnContextCancel(), NewPprofServer(), PprofServer

### Community 143 - "Report"
Cohesion: 0.38
Nodes (9): ratioKey, fmtFloats(), fmtValue(), humanBytes(), orDash(), renderPlainSection(), renderRatioSection(), renderReport() (+1 more)

### Community 144 - "E2E Harness Backend Client"
Cohesion: 0.38
Nodes (10): BackendClient(), caTrustingHTTPClient(), EmptyAndDeleteBucket(), EmptyBucket(), EnsureBucket(), OpenUploads(), ProxyClient(), ProxyETag() (+2 more)

### Community 145 - "Abandoned Upload Sweeper"
Cohesion: 0.20
Nodes (6): AbortIncompleteMultipartUpload Lifecycle Rule, optimizations.multipart_session_idle_timeout, The Session Sweeper Measures Inactivity, Not Age, CleanupExpiredSegmentedSessions, Manager.SetMultipartAbandoner, SegmentedSession.TouchWhileReading

### Community 146 - "Shutdown Order and Probes"
Cohesion: 0.22
Nodes (7): Drain Guard: 503 ServiceUnavailable With Retry-After While the Listener Stays Up, A Multipart Session Is Process-Local and Unfinishable Once the Process Exits, A Second Replica Answers NoSuchUpload for an Upload the First Holds, Shutdown Ends What the Process Is Still Holding, AbandonAllSessions, Manager.Shutdown, drainGuardMiddleware

### Community 147 - "Short-Part Budget and Memory"
Cohesion: 0.20
Nodes (9): The Process-Wide Short-Part Budget, What One In-Flight Request Costs in Memory, RecordStreamedPart, SegmentedSession.SealStreamingPart, readHeldPart, readWholePart, uploadStreamedPart, Parser.ReadBodyLimited (+1 more)

### Community 148 - "Client-Driven Multipart Paths"
Cohesion: 0.20
Nodes (8): The Client-Driven Multipart Upload, The Internal Multipart Producer, A Part Is Streamed or Held, and the Declared Length Decides, orchestration.CanStreamPart, SegmentedSession, UploadHandler.Handle, putObjectAutoMultipart, utils.CleanupContext

### Community 149 - "Storage Format Invariants"
Cohesion: 0.20
Nodes (7): Invariant 1: Each Seal Is Bound to Its Position and Its Object, The Four Metadata Keys That Mark an Object as Ours, Invariant 3: A Nonce Is Never Reused Under One Key, The Ranged-Read Window and Its Amplification Bound, The Storage Format (s3ep-gcm-seg-v2), Manager.ClaimsSegmentedFormat, Manager.IsSegmentedObject

### Community 150 - "Segmented GCM"
Cohesion: 0.27
Nodes (10): Invariant 2: The Stored Length Is a Pure Function of the Plaintext Length, maxWindowOverAsk, CiphertextSize(), PlaintextSize(), SegmentOverhead, SegmentSize, TestSegOversizeRefused(), TestSegSizeFunctionsRoundTrip() (+2 more)

### Community 151 - "Router"
Cohesion: 0.31
Nodes (5): CORS, NewCORS(), allowedMethods(), bucketRoute(), Server

### Community 153 - "Segmented GCM Part"
Cohesion: 0.40
Nodes (8): partCodec(), sealInParts(), TestSegOpenTrailerRejectsTampering(), TestSegPartWriterOffsetIsAuthenticated(), TestSegPartWriterRefusesShortMiddlePart(), TestSegPartWriterRefusesUnalignedOffset(), TestSegPartWriterRoundTrip(), TestSegSealTrailerMatchesSequentialWriter()

### Community 154 - "Renovate Automerge Settings"
Cohesion: 0.20
Nodes (10): lockFileMaintenance, automerge, automergeType, commitMessageAction, commitMessagePrefix, dependencyDashboardApproval, enabled, platformAutomerge (+2 more)

### Community 155 - "GET Copy Benchmarks"
Cohesion: 0.31
Nodes (6): benchGetResponse(), BenchmarkGetResponseCopy(), copyWithSize(), benchReader, hidingWriter, writerOnly

### Community 156 - "E2E Harness Environment"
Cohesion: 0.47
Nodes (6): Env, Binary(), CACert(), DemoStack(), LoadEnv(), RepoRoot()

### Community 157 - "Smallobject"
Cohesion: 0.47
Nodes (8): leg, smallObjectBatch(), smallObjectGet(), smallObjectKeys(), smallObjectLegOrder(), smallObjectOps(), smallObjectPut(), TestSmallObjectRate()

### Community 158 - "S3 Method Error Mapping Tests"
Cohesion: 0.47
Nodes (8): apiCodeOf(), apiMessageOf(), errorsAs(), httpStatusOf(), TestBackendErrorsKeepTheirStatusAndCode(), TestConditionalRequestErrors(), TestLstListObjectsMissingBucket(), TestVbRefusedCopiesLeaveNothingBehind()

### Community 159 - "Shutdown"
Cohesion: 0.56
Nodes (8): docker(), openUploads(), preflight(), proxyLogs(), restartProxy(), shutdownBudget(), TestShutdownEndsOpenMultipartUploadsUnderSIGTERM(), waitForExit()

### Community 160 - "Listing Document"
Cohesion: 0.36
Nodes (5): commonPrefix, listBucketResultV1, listBucketResultV2, objectEntry, ownerEntry

### Community 161 - "Bucket Versioning Handler"
Cohesion: 0.39
Nodes (6): VersioningHandler, NewVersioningHandler(), TestVersioningHandler_Handle(), TestVersioningHandler_HandleErrors(), TestVersioningHandler_MFAValidation(), TestVersioningHandler_XMLParsing()

### Community 162 - "Prometheusrule"
Cohesion: 0.25
Nodes (6): Alert S3EPBackendTransportFailing (share, not count), Alert S3EPLicenseExpired, Alert S3EPLicenseExpiringSoon, Alert S3EPObjectIntegrityFailure, helm-unittest suite: alerting rules, monitoring.prometheusRule thresholds and windows

### Community 163 - "Performance Measurement Rules"
Cohesion: 0.25
Nodes (5): The In-Process Crypto Floor Rules the Cipher Out, The Memory Instrument Is the One Asserted Figure, Performance, Three Suspicions Measured and Falsified, The Second Backend Request of a Whole-Object Read Costs About 300 Microseconds

### Community 164 - "Default Config"
Cohesion: 0.39
Nodes (6): cfgDefaultLicence(), cfgLoadFrom(), TestCfgDefaultConfigAsksForExactlyTheDocumentedVariables(), TestCfgDefaultConfigFailsClosedOnEveryVariable(), TestCfgDefaultConfigLoads(), TestCfgShippedExamplesLoad()

### Community 165 - "Bucket Replication Handler"
Cohesion: 0.39
Nodes (6): NewReplicationHandler(), TestReplicationHandler_ComplexConfigurations(), TestReplicationHandler_Handle(), TestReplicationHandler_HandleErrors(), TestReplicationHandler_ReplicationMetrics(), TestReplicationHandler_XMLValidation()

### Community 166 - "Multipart Checksum Echo Tests"
Cohesion: 0.39
Nodes (7): MpuCrcwant(), TestMpuCrcARefusedPartStatesNoChecksum(), TestMpuCrcAReplacedPartAnswersTheNewChecksum(), TestMpuCrcEveryPartAnswersItsOwnChecksum(), TestMpuCrcTheCompletionAnswersTheWholeObjectChecksum(), TestMpuCrcTheCompletionCoversAHeldShortPart(), TestMpuCrcTheExitProviderStatesNoChecksum()

### Community 167 - "Logging Middleware"
Cohesion: 0.32
Nodes (3): Logger, NewLogger(), responseWriter

### Community 168 - "Pipeline"
Cohesion: 0.29
Nodes (4): Semantic-release toolchain composite action, Breaking-change marker inspection (commits, title, body), release:major label is the declaration of a major, Semantic-Release (dry run) job

### Community 169 - "Default"
Cohesion: 0.29
Nodes (3): Chart version, appVersion and image tag rewritten from the release tag, config/default.yaml (the configuration the image starts with), values.yaml (chart defaults)

### Community 171 - "Bucket CORS Documents"
Cohesion: 0.29
Nodes (4): corsConfigurationDocument, corsRuleDocument, newCORSConfigurationDocument(), optional()

### Community 172 - "Integrity Failure Reporting"
Cohesion: 0.29
Nodes (6): s3ep_object_integrity_failures_total, Phased Before-Response and Mid-Stream, A Fault Found After WriteHeader Aborts the Body, The Sealed 40-Byte Trailer, Segment Chain Layout, Handler.reportStreamFault, Checksum.Append

### Community 173 - "Multipart Complete Handler"
Cohesion: 0.38
Nodes (4): completionLocation(), firstForwardedValue(), CompletedPart, CompleteMultipartUpload

### Community 174 - "Rclone"
Cohesion: 0.33
Nodes (6): WriteStepSummary(), reportDir(), TestMain(), reportDir(), TestMain(), TestMain()

### Community 175 - "Monitoring Dashboard Contract"
Cohesion: 0.43
Nodes (6): monExportedSeries(), TestMonAlertRulesQueryOnlySeriesTheProxyExports(), TestMonAlertRulesReadTheBackendFailureShareNotItsCount(), TestMonDashboardQueriesOnlySeriesTheProxyExports(), TestMonDashboardVariablesResolveBeforeTheFirstRequest(), TestMonScrapeCarriesTheRuntimeCollectors()

### Community 177 - "E2e Up"
Cohesion: 0.48
Nodes (6): k(), KUBECONFIG, log(), need(), proxy_upgrade(), e2e-up.sh script

### Community 178 - "Throughput"
Cohesion: 0.52
Nodes (6): getTimed(), measureThroughput(), putTimed(), TestThroughput(), throughputSizes(), uploadNote()

### Community 209 - "Bucket Replication Documents"
Cohesion: 0.40
Nodes (5): replicationConfigurationDocument, replicationRuleDocument, sourceSelectionPD, statusOnlyPD, newReplicationConfigurationDocument()

### Community 210 - "Keygen Command"
Cohesion: 0.47
Nodes (4): main(), printKey(), TestKeygenDrawsAFreshKeyEachTime(), TestKeygenOutput()

### Community 211 - "Check Breaking Changes"
Cohesion: 0.47
Nodes (5): add_message(), die(), FOOTER_PATTERN, HEADER_PATTERN, check-breaking-changes.sh script

### Community 212 - "ACL"
Cohesion: 0.47
Nodes (4): mapCannedACLForBucket(), parseACLXMLForTest(), TestACLXMLParsing(), TestCannedACLMapping()

### Community 214 - "Etag Marker"
Cohesion: 0.60
Nodes (5): MpuTagacceptParts(), TestMpuTagAClientReturnsTheMarkedPartTagsAndCompletes(), TestMpuTagExitProviderMarksNothingAndForwardsTheList(), TestMpuTagListPartsAnswersTheMarker(), TestMpuTagPartUploadsAnswerTheMarker()

### Community 215 - "Payload Hash Verification Tests"
Cohesion: 0.40
Nodes (6): ChkpayloadHash(), ChkverifyingParser(), TestChkPayloadHashIsNotVerifiedUnlessConfigured(), TestChkPayloadHashIsVerifiedBesideAnotherDigest(), TestChkPayloadHashIsVerifiedWhenConfigured(), TestChkPayloadHashNeverSatisfiesTheDeleteObjectsRule()

### Community 216 - "Rangeread"
Cohesion: 0.67
Nodes (5): rangeCase, rangeCases(), rangeNote(), TestRangeRead(), timeRangeGet()

### Community 217 - "Renovate Presets"
Cohesion: 0.33
Nodes (6): :automergeDigest, config:recommended, :dependencyDashboard, docker:enableMajor, :semanticCommits, extends

### Community 218 - "rclone E2E Bring-Up"
Cohesion: 0.73
Nodes (5): install_rclone(), log(), need(), e2e-up.sh script, wait_for()

### Community 219 - "s3cmd E2E Bring-Up"
Cohesion: 0.73
Nodes (5): install_s3cmd(), log(), need(), e2e-up.sh script, wait_for()

### Community 220 - "Values Velero"
Cohesion: 0.33
Nodes (4): csi-hostpath-snapclass with the Velero discovery label, BackupStorageLocation pointing s3Url at the proxy, uploaderType kopia with EnableCSI and the node agent, Velero Helm values for the e2e cluster

### Community 221 - "Bucket Policy"
Cohesion: 0.60
Nodes (5): analyzePolicySecurity(), TestBucketPolicyComplexStructures(), TestBucketPolicySecurityAnalysis(), TestBucketPolicyValidation(), validatePolicyJSON()

### Community 222 - "Constants"
Cohesion: 0.60
Nodes (3): simplePRNG, generateDeterministicData(), newSimplePRNG()

### Community 223 - "Strict Configuration Loading"
Cohesion: 0.40
Nodes (3): Strict Decoding: An Unknown Key Refuses the Start, Configuration: Where a Value Comes From, loading_coverage_test.go — pins the AutomaticEnv removal

### Community 225 - "Monitoring HTTP Server"
Cohesion: 0.60
Nodes (3): NewServer(), Config, Server

### Community 226 - "Bucket Lifecycle Handler"
Cohesion: 0.50
Nodes (3): NewLifecycleHandler(), TestLifecycleHandler_ComplexRules(), TestLifecycleHandler_Handle()

### Community 228 - "AES KEK Vector Tests"
Cohesion: 0.70
Nodes (4): aesVecProvider(), TestAesVectorFingerprintIsStable(), TestAesVectorWrapIsBoundToItsSalt(), TestAesVectorWrappedKeyStillOpens()

### Community 229 - "Perf Stack Detection"
Cohesion: 0.70
Nodes (4): detectStack(), insecureClient(), reachable(), readProxyConfig()

### Community 230 - "Push"
Cohesion: 0.50
Nodes (4): Build Docker Image job (release:published), Release Helm Chart to GitHub Pages job, SBOM, provenance and Docker Scout on the released image, s3-encryption-proxy Helm chart (5.0.0)

### Community 231 - "S3 API"
Cohesion: 0.50
Nodes (4): s3cmd del --recursive and multipart are refused, optimizations.max_request_document_size, A query string containing ';' is 400 InvalidArgument, Sub-resources: 501 NotImplemented or 405 MethodNotAllowed

## Ambiguous Edges - Review These
- `ADR 0021` → `Go toolchain version spelled out in Containerfile and go.mod only`  [AMBIGUOUS]
  DEVELOPER.md · relation: conceptually_related_to
- `s3ep-gcm-seg-v2 stored format (AES-256-GCM segment chain + sealed trailer)` → `Initial implementation (Google Tink envelope, aes-gcm direct)`  [AMBIGUOUS]
  CHANGELOG.md · relation: conceptually_related_to
- `Streaming in both directions (bounded part buffers)` → `One instance, the chart refuses a second`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/README.md · relation: conceptually_related_to
- `Short Part Held in Memory and Sealed at Complete (D5)` → `Verdict Lands Before Anything Is Committed (D7)`  [AMBIGUOUS]
  docs/adr/0011-the-proxy-owns-the-part-layout.md · relation: conceptually_related_to
- `No working key material tracked in the repository` → `Per-backend ca_file trust root`  [AMBIGUOUS]
  docs/adr/0037-the-backend-leg-is-trusted-explicitly-and-its-failures-are-named.md · relation: conceptually_related_to
- `Per-object name form lookup in mixed and drain` → `/status document on the monitoring listener`  [AMBIGUOUS]
  docs/adr/0023-filename-encryption-encrypts-directory-segments.md · relation: conceptually_related_to

## Knowledge Gaps
- **314 isolated node(s):** `dekCacheEntry`, `tagDocument`, `UtlCtxKey`, `ratioKey`, `requestIDKey` (+309 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 747 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **114 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `ADR 0021` and `Go toolchain version spelled out in Containerfile and go.mod only`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `Ticket 038: s3-encryption-operator` connect `Service TLS and Operator Certificates` to `Transfer Bounds and Shutdown`, `ADR Web: Auth, Checksums, Config`, `Storage Format Integrity Guarantees`, `Hostile Backend and Key Material ADRs`, `Multipart Part Layout Decisions`, `Documentation Homes and Ticket Lifecycle`, `Release and Test Discipline ADRs`, `Filename Encryption Design`, `Filename Encryption Pass Engine`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Are the 5 inferred relationships involving `EnsureMinIOAndProxyAvailable()` (e.g. with `TestUnauthenticatedProbes()` and `EnsureBenchmarkEnvironment()`) actually correct?**
  _`EnsureMinIOAndProxyAvailable()` has 5 INFERRED edges - model-reasoned connections that need verification._
- **What connects `dekCacheEntry`, `tagDocument`, `UtlCtxKey` to the rest of the system?**
  _314 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Object GET Coverage Tests` be split into smaller, more focused modules?**
  _Cohesion score 0.05262711145064086 - nodes in this community are weakly interconnected._
- **What is the exact relationship between `s3ep-gcm-seg-v2 stored format (AES-256-GCM segment chain + sealed trailer)` and `Initial implementation (Google Tink envelope, aes-gcm direct)`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `ADR 0021` connect `ADR Web: Auth, Checksums, Config` to `Changelog and Project Front Page`, `Hostile Backend and Key Material ADRs`, `Demo Stack and Integration Jobs`, `Release and Test Discipline ADRs`, `Service TLS and Operator Certificates`, `Filename Encryption Design`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._