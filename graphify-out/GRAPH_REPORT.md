# Graph Report - s3-encryption-proxy  (2026-09-10)

## Corpus Check
- 325 files · ~535,722 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 3851 nodes · 11179 edges · 210 communities (153 shown, 51 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 1421 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `3530f1c6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- net/http.Request
- ObjGetdo
- preflight
- multipart_coverage_test.go
- ObjMiscnewHandler
- testing.T
- MockS3Backend
- NewMetadataManager
- github.com/sirupsen/logrus.Entry
- BktnewHandlerWith
- NewParser
- MapError
- harness.go
- context.Context
- objectput_coverage_test.go
- testCodec
- Handler
- renovate.json
- Proxy Deployment Template
- segManager
- io.Reader
- Ticket 010 Tier 2 Snapshot (AFTER)
- providers_coverage_test.go
- NewManager
- NewXMLWriter
- S3AuthenticationService
- start-demo.sh
- Config
- RandomString
- PlanRange
- testParser
- EnsureMinIOAndProxyAvailable
- NewErrorWriter
- listbuckets_coverage_test.go
- delete_objects_batch_test.go
- multipart_conformance_test.go
- RtPxrouter
- CreateTestBucket
- listobjects_conformance_test.go
- net/http.Handler
- validator_coverage_test.go
- Ticket 015: Configuration hygiene
- middleware_coverage_test.go
- validation_coverage_test.go
- object/metadata_coverage_test.go
- NewTestContext
- Load
- envexpand_test.go
- orchestration/metadata_coverage_test.go
- main_coverage_test.go
- TamSetup
- runProxy
- monitoring/server_coverage_test.go
- Checksum
- comprehensive_chunked_test.go
- setupMultipartTestEnv
- http_middleware_coverage_test.go
- testLogger
- canonicalQueryString
- github.com/aws/aws-sdk-go-v2/service/s3.Client
- minio_test_helper.go
- handler_coverage_test.go
- TestExitProvider_ReadsBackAnEncryptedObject
- Ticket 012: Performance improvements round 2
- LiccaptureLogs
- calculateTimeRemaining
- presignTestService
- package.json
- CiphertextSize
- NewAESKeyEncryptor
- RtPxserver
- Provider comparison: RSA, AES, None
- Ticket 013: Storage format v2 — segmented AES-GCM
- NewServer
- Server
- Release 4.0.0
- H-5 integrity_verification does not refuse a tampered aes-ctr object
- Ticket 022: S3 surface fidelity
- Performance baseline — pre-v2
- The client-driven upload
- Testing
- net/http.Header
- config_test.go
- time.Time
- Handler
- What this run says
- partCodec
- CORSHandler
- range_conformance_test.go
- comprehensive_singlepart_test.go
- NewHandler
- Request paths
- s3auth_coverage_test.go
- NewValidator
- ADR 0024: An upload forwards while it receives
- ADR 0025: Leaving is a supported mode
- The storage format
- bucket_acl_test.go
- backendOptions
- NewWebsiteHandler
- Semantic Release job
- auth_test.go
- Local performance baseline
- Ticket index
- MockS3Backend
- NewPprofServer
- encryption_validation_helper.go
- SegmentedSession
- Ticket 010: Performance Improvements - Streaming Throughput
- ACLHandler
- LifecycleHandler
- ReplicationHandler
- performance_test.go
- reader
- net.Conn
- Errors
- NewNotificationHandler
- NewReplicationHandler
- Vault as a key provider — open decisions, parked
- NewTaggingHandler
- Breaking Change Guard
- The three rules
- Performance baseline — segment-codec, item 1
- Where the upload deficit actually is
- Performance baseline — upload path decomposition
- Performance baseline — pre-v2-uploadpath
- validator.go
- Integration Tests job
- install.sh
- A Configuration Key Exists Only If Code Reads It
- Authenticated Segment Chain (s3ep-gcm-seg-v2)
- Hostile Backend Threat Model
- compare.py
- Ticket 014: Verify client upload checksums
- LocationHandler
- .DeleteBucketCors
- .DeleteBucketLifecycle
- conditional_requests_test.go
- .DeleteBucketPolicy
- A KMS-Backed KEK Is Its Own Provider Type
- Forward It or Refuse It, Never Silently Drop It
- .DeleteBucketTagging
- .DeleteObjects
- .GetBucketReplication
- github.com/aws/aws-sdk-go-v2/service/s3.ListBucketsOutput
- .PutBucketLogging
- Performance
- TaggingHandler
- .ReadBody
- Writer
- responseWriter
- Combined Coverage job
- The segment codec, measured
- LicenseValidator
- Handler
- The "before" column for the producer restructuring
- TestLargeMultipart500MB
- coverage-summary.py
- MwNotAFlusher
- MonNotAFlusher
- complete.go
- github.com/aws/aws-sdk-go-v2/service/s3.CreateMultipartUploadInput
- .DeleteBucketReplication
- ObjMiscbrokenReader
- .GetBucketAccelerateConfiguration
- .GetBucketAcl
- .GetBucketCors
- MockS3Backend
- .GetBucketPolicy
- .GetBucketRequestPayment
- .GetBucketVersioning
- .GetBucketWebsite
- github.com/aws/aws-sdk-go-v2/service/s3.GetObjectOutput
- .GetObjectTorrent
- github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketInput
- .HeadObject
- github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsInput
- github.com/aws/aws-sdk-go-v2/service/s3.ListObjectsV2Input
- .PutBucketAcl
- .PutBucketCors
- .PutBucketLifecycleConfiguration
- .PutBucketNotificationConfiguration
- .PutBucketPolicy
- .PutBucketTagging
- .PutBucketVersioning
- github.com/aws/aws-sdk-go-v2/service/s3.PutObjectInput
- An Unworkable Configuration Refuses to Start
- DEK cache key (fingerprint:objectKey)
- check-breaking-changes.sh
- e2e-up.sh
- bucket_policy_test.go
- Velero E2E (kind) job
- .handleBucket
- Reporting a vulnerability
- Authenticated Trailer (Length and Sealed CRC32C)
- Fail Closed on Foreign Objects (InvalidObjectState 403)
- release.config.mjs
- All Three Write Paths Produce the Identical Byte Layout
- A Query String Containing ';' Is Refused (Parser/Router Disagreement)
- version-dry-run.sh
- e2e-down.sh
- gen-certs.sh
- One Bring-Up Script for Workstation and CI
- github.com/guided-traffic/s3-encryption-proxy

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
- `Health Check Sidecar` --semantically_similar_to--> `Default Chart Values`  [INFERRED] [semantically similar]
  docker-compose.demo.yml → deploy/helm/s3-encryption-proxy/values.yaml
- `Client checksums are dropped, never forwarded` --semantically_similar_to--> `H-2 Per-chunk signatures are never verified`  [INFERRED] [semantically similar]
  README.md → SECURITY_ARCHITECTURE.md
- `Demo Proxy Service (HTTP, container proxy)` --semantically_similar_to--> `Proxy Deployment Template`  [INFERRED] [semantically similar]
  docker-compose.demo.yml → deploy/helm/s3-encryption-proxy/templates/deployment.yaml
- `Development Values Profile` --semantically_similar_to--> `MinIO Demo Backend Service`  [INFERRED] [semantically similar]
  deploy/helm/s3-encryption-proxy/values-development.yaml → docker-compose.demo.yml
- `Why a Second TLS Proxy Instance Exists` --semantically_similar_to--> `Ingress Streaming Annotations`  [INFERRED] [semantically similar]
  docker-compose.demo.yml → deploy/helm/s3-encryption-proxy/values-production.yaml

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **The Announced-But-Unperformed Control Family** — docs_adr_0001_the_backend_is_hostile_dead_control_rule, docs_adr_0007_forward_it_or_refuse_it_forward_or_refuse, docs_adr_0013_a_configuration_key_exists_only_if_code_reads_it_key_needs_a_reader, docs_adr_0014_authentication_is_sigv4_no_rate_limiting_no_rate_limiting, docs_adr_0019_integration_and_e2e_tests_are_the_product_suites_are_the_product, docs_adr_0021_key_material_is_generated_never_committed_no_committed_key_material [EXTRACTED 1.00]
- **Local Demo Stack (start-demo.sh)** — docker_compose_demo_minio, docker_compose_demo_s3_encryption_proxy, docker_compose_demo_s3_encryption_proxy_tls, docker_compose_demo_proxy_healthcheck, docker_compose_demo_s3_explorer_encrypted, docker_compose_demo_vault [EXTRACTED 1.00]
- **Rendered Kubernetes Resource Set of the Chart** — deploy_helm_s3_encryption_proxy_chart_s3_encryption_proxy_chart, deploy_helm_s3_encryption_proxy_templates_deployment_deployment, deploy_helm_s3_encryption_proxy_templates_service_service, deploy_helm_s3_encryption_proxy_templates_configmap_configmap, deploy_helm_s3_encryption_proxy_templates_ingress_ingress, deploy_helm_s3_encryption_proxy_templates_certificate_certificate, deploy_helm_s3_encryption_proxy_templates_hpa_horizontalpodautoscaler, deploy_helm_s3_encryption_proxy_templates_networkpolicy_networkpolicy, deploy_helm_s3_encryption_proxy_templates_poddisruptionbudget_poddisruptionbudget, deploy_helm_s3_encryption_proxy_templates_service_monitoring_monitoring_service, deploy_helm_s3_encryption_proxy_templates_servicemonitor_servicemonitor, deploy_helm_s3_encryption_proxy_templates_grafana_dashboard_grafana_dashboard_configmap [EXTRACTED 1.00]
- **A major release is declared, computed and cut** — _github_workflows_breaking_change_guard_guard, _github_workflows_breaking_change_guard_release_major_label, _github_workflows_breaking_change_guard_adr_0018, _github_workflows_version_dry_run_version_dry_run, _github_workflows_release_semantic_release, changelog_v4_0_0 [EXTRACTED 1.00]
- **The 5.0.0 migration-forcing bundle** — docs_tickets_023_major_v5_release, docs_tickets_013_storage_format_v2_ticket, docs_tickets_014_upload_checksum_verification_ticket, docs_tickets_015_configuration_hygiene_ticket, docs_tickets_018_listobjectsv2_document_ticket, docs_tickets_022_s3_surface_fidelity_ticket, docs_tickets_023_major_v5_bundle_branch [EXTRACTED 1.00]
- **Test and Release gates that must pass before a release is cut** — _github_workflows_release_malware_scan, _github_workflows_release_gosec, _github_workflows_release_govulncheck, _github_workflows_release_linter, _github_workflows_release_unit_tests, _github_workflows_release_integration_tests, _github_workflows_release_coverage_report, _github_workflows_release_e2e_velero, _github_workflows_release_semantic_release [EXTRACTED 1.00]
- **Elements of the s3ep-gcm-seg-v2 stored-object format** — docs_tickets_013_storage_format_v2_segmented_gcm_format, docs_tickets_013_storage_format_v2_trailer, docs_tickets_013_storage_format_v2_associated_data, docs_tickets_013_storage_format_v2_random_inline_nonces, docs_tickets_013_storage_format_v2_size_pure_function, docs_tickets_013_storage_format_v2_crc32c_sealed_checksum, docs_tickets_013_storage_format_v2_read_path_tail_first, docs_tickets_013_storage_format_v2_segment_codec_api [EXTRACTED 1.00]
- **Tier 1 Per-Read Hot-Path Fixes and Their Baseline Hotspots** — docs_tickets_010_performance_improvements_tier1_1_inplace_ctr_xor, docs_tickets_010_performance_improvements_tier1_2_remove_per_read_mutex, docs_tickets_010_performance_improvements_tier1_3_remove_per_read_logrus, docs_tickets_010_baseline_proxy_cpu_top20_memmove, docs_tickets_010_baseline_proxy_allocs_top20_ctr_encrypt_decrypt_part, docs_tickets_010_baseline_proxy_allocs_objects_top15_logrus_withfields [EXTRACTED 1.00]
- **Tier 2 optimization program (2.3 / 2.4 / 2.5 / 2.6) landing on the same 1 GB benchmark** — docs_tickets_010_tier2_readme_tier_2_3_gcm_get_readall_removal, docs_tickets_010_tier2_readme_tier_2_4_parallel_uploadpart, docs_tickets_010_tier2_readme_tier_2_5_append_elimination, docs_tickets_010_tier2_readme_tier_2_6_streaming_decryption_no_per_chunk_copy, docs_tickets_010_tier2_readme_tier2_snapshot [EXTRACTED 1.00]
- **Paired client/proxy pprof artifact set captured per tier (CPU, alloc_space, alloc_objects)** — docs_tickets_010_tier2_cpu_top20_client_cpu_profile, docs_tickets_010_tier2_mem_alloc_space_client_alloc_space_profile, docs_tickets_010_tier2_mem_alloc_objects_client_alloc_objects_profile, docs_tickets_010_tier2_proxy_cpu_top20_proxy_cpu_profile, docs_tickets_010_tier2_proxy_allocs_top20_proxy_alloc_space_profile, docs_tickets_010_tier2_proxy_allocs_objects_top15_proxy_alloc_objects_profile, docs_tickets_010_tier4_1_cpu_top20_client_cpu_profile, docs_tickets_010_tier4_1_mem_alloc_space_client_alloc_space_profile, docs_tickets_010_tier4_1_mem_alloc_objects_client_alloc_objects_profile, docs_tickets_010_tier4_1_proxy_cpu_top20_proxy_cpu_profile, docs_tickets_010_tier4_1_proxy_allocs_top20_proxy_alloc_space_profile, docs_tickets_010_tier4_1_proxy_allocs_objects_top15_proxy_alloc_objects_profile [EXTRACTED 1.00]
- **The 5.0.0 Stored-Format Break Bundle** — docs_adr_0003_objects_are_an_authenticated_segment_chain_segment_chain_format, docs_adr_0004_one_local_key_provider_authenticated_kek_wrap, docs_adr_0009_the_metadata_prefix_is_the_proxys_namespace_prefix_shape_rule, docs_adr_0011_the_proxy_owns_the_part_layout_segment_aligned_parts, docs_adr_0017_stored_data_compatibility_is_not_owed_no_migration, docs_adr_0018_a_major_release_is_declared_by_a_label_bundle_branch [EXTRACTED 1.00]
- **The Velero e2e kind stack** — test_e2e_velero_kind_config_cluster, test_e2e_velero_manifests_minio_backend, test_e2e_velero_manifests_proxy_nodeport_service, test_e2e_velero_manifests_snapshotclass_csi_hostpath, test_e2e_velero_values_proxy_values, test_e2e_velero_values_velero_values [EXTRACTED 1.00]
- **The aes-ctr integrity gap and its single fix** — security_architecture_h1, security_architecture_h5, security_architecture_h6, security_architecture_gcm_vs_ctr, readme_integrity_verification, claude_integrity_verification_modes, security_architecture_adr_0003_segment_chain [INFERRED 0.85]
- **Production Hardening Profile** — deploy_helm_s3_encryption_proxy_values_production_production_values, deploy_helm_s3_encryption_proxy_values_production_network_policy, deploy_helm_s3_encryption_proxy_values_production_pod_anti_affinity, deploy_helm_s3_encryption_proxy_values_production_cert_manager_certificate, deploy_helm_s3_encryption_proxy_values_production_ingress_streaming_annotations, deploy_helm_s3_encryption_proxy_templates_poddisruptionbudget_poddisruptionbudget, deploy_helm_s3_encryption_proxy_templates_hpa_horizontalpodautoscaler [INFERRED 0.85]
- **Copy- and Allocation-Avoidance Campaign Across Upload and Download Paths** — docs_tickets_010_baseline_proxy_allocs_top20_io_readall, docs_tickets_010_baseline_proxy_allocs_top20_processpartordered, docs_tickets_010_performance_improvements_tier2_3_stream_to_responsewriter, docs_tickets_010_performance_improvements_tier2_5_eliminate_append_build, docs_tickets_010_performance_improvements_tier3_1_gcm_copy_avoidance, docs_tickets_010_performance_improvements_tier4_2_pooled_copybuffer [INFERRED 0.85]
- **Upload-side body-collection alloc hotspot spanning ReadBody, aws-chunked decoding, io.ReadAll and the Tier 3.1 target** — docs_tickets_010_tier2_readme_io_readall_hotspot, docs_tickets_010_tier2_readme_awschunkeddecoder_requireschunkeddecoding, docs_tickets_010_tier4_1_proxy_allocs_top20_readbody_alloc_path, docs_tickets_010_tier2_readme_tier_3_1_upload_side_readall_target, docs_tickets_010_tier2_proxy_allocs_top20_upload_alloc_chain [INFERRED 0.85]
- **Key Hierarchy and Custody Chain** — docs_adr_0002_one_data_key_per_object_one_dek_per_object, docs_adr_0002_one_data_key_per_object_kek_fingerprint_selection, docs_adr_0004_one_local_key_provider_authenticated_kek_wrap, docs_adr_0005_a_kms_key_is_a_provider_kms_provider_type, docs_adr_0021_key_material_is_generated_never_committed_no_committed_key_material, docs_adr_0023_filename_encryption_encrypts_directory_segments_aes_siv_name_transform [INFERRED 0.95]

## Communities (210 total, 51 thin omitted)

### Community 0 - "net/http.Request"
Cohesion: 0.07
Nodes (16): LoggingHandler, PolicyHandler, TaggingHandler, net/http.Request, net/http.ResponseWriter, PlaintextSize(), Handler, NewPolicyHandler() (+8 more)

### Community 1 - "ObjGetdo"
Cohesion: 0.06
Nodes (106): Handler, MockS3Backend, ObjGetdigest(), ObjGetdo(), ObjGetgetOutput(), ObjGetmutateMetadata(), ObjGetnewExitHandler(), ObjGetnewHandler() (+98 more)

### Community 2 - "preflight"
Cohesion: 0.09
Nodes (80): time.Duration, backendClient(), caTrustingHTTPClient(), hasEncryptionMetadata(), listBackendObjects(), metadataValue(), proxyClient(), readBackendObject() (+72 more)

### Community 3 - "multipart_coverage_test.go"
Cohesion: 0.07
Nodes (84): BkterrorDoc, BucketLoggingStatus, Grantee, LoggingEnabled, TargetGrant, encoding/xml.Name, MockS3Backend, MpuAPIError() (+76 more)

### Community 4 - "ObjMiscnewHandler"
Cohesion: 0.09
Nodes (57): net/http/httptest.ResponseRecorder, Handler, ObjMiscdeleteObjects(), ObjMiscnewFailWriter(), ObjMiscparseDeleteResult(), TestObjMiscDeleteObjectsAcceptsAnObjectWithoutAKey(), TestObjMiscDeleteObjectsBackendErrorsAreMapped(), TestObjMiscDeleteObjectsBodyReadErrorIsRefused() (+49 more)

### Community 5 - "testing.T"
Cohesion: 0.05
Nodes (61): testing.T, TestCfgGetActiveProviderErrorPaths(), TestCfgGetActiveProviderReturnsLivePointer(), TestCfgGetAllProvidersReflectsSlice(), TestCfgIsValidProviderType(), TestCfgStreamingAccessors(), TestGetStreamingSegmentSize(), TestOptimizationsConfig() (+53 more)

### Community 6 - "MockS3Backend"
Cohesion: 0.04
Nodes (36): MockS3Backend, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.CopyObjectOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectTaggingOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAclOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectLegalHoldInput (+28 more)

### Community 7 - "NewMetadataManager"
Cohesion: 0.22
Nodes (9): NewMetadataManager(), createTestConfigForMetadata(), createTestConfigWithoutPrefix(), TestGetAlgorithm(), TestGetEncryptedDEK(), TestGetFingerprint(), TestGetMetadataPrefix(), TestNewMetadataManager() (+1 more)

### Community 8 - "github.com/sirupsen/logrus.Entry"
Cohesion: 0.11
Nodes (26): github.com/sirupsen/logrus.Entry, sync.WaitGroup, Manager, NewAbortHandler(), NewCompleteHandler(), NewCopyHandler(), NewHandler(), NewListHandler() (+18 more)

### Community 9 - "BktnewHandlerWith"
Cohesion: 0.07
Nodes (75): BktclosingBody, BktfailingReader, BktfailingWriter, BktforeignHits, errBkt, net/http.HandlerFunc, strings.Reader, BktassertIsListBucketResult() (+67 more)

### Community 10 - "NewParser"
Cohesion: 0.19
Nodes (25): BaseSubResourceHandler, NewAccelerateHandler(), TestAccelerateHandler_AccelerateStatuses(), TestAccelerateHandler_AccelerationBenefits(), TestAccelerateHandler_BucketNamingRequirements(), TestAccelerateHandler_ContentTypeHandling(), TestAccelerateHandler_Handle(), TestAccelerateHandler_HandleErrors() (+17 more)

### Community 11 - "MapError"
Cohesion: 0.12
Nodes (33): codeForStatus(), RespAPIErrorNoResponse(), RespStatusOnlyError(), RespWrapMarker(), TestRespMapErrorBackend5xxKeepsReasonPhrase(), TestRespMapErrorCodeForStatusFallback(), TestRespMapErrorCodeStatusTableMatchesAWS(), TestRespMapErrorEmptyCodeWithoutResponseStaysOpaque() (+25 more)

### Community 12 - "harness.go"
Cohesion: 0.05
Nodes (83): crypto/cipher.AEAD, crypto/x509.CertPool, net/http.Client, strings.Builder, testing.M, GitInfo, Hardware, InstrumentStatus (+75 more)

### Community 13 - "context.Context"
Cohesion: 0.08
Nodes (17): context.Context, github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.AbortMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadInput, github.com/aws/aws-sdk-go-v2/service/s3.CompleteMultipartUploadOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketWebsiteOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLifecycleConfigurationInput (+9 more)

### Community 14 - "objectput_coverage_test.go"
Cohesion: 0.13
Nodes (58): github.com/stretchr/testify/mock.Call, Handler, MockS3Backend, ObjPutcapturePut(), ObjPutchunked(), ObjPutdigest(), ObjPutdo(), ObjPutdropCall() (+50 more)

### Community 15 - "testCodec"
Cohesion: 0.13
Nodes (31): errAfterReader, errReader, TestSegEncryptReaderChecksum(), TestSegEncryptReaderMatchesWriter(), TestSegEncryptReaderPropagatesSourceError(), TestSegEncryptReaderStaysFailedAfterAnError(), TestSegEncryptReaderTinyReads(), NewChecksum() (+23 more)

### Community 16 - "Handler"
Cohesion: 0.08
Nodes (8): AccelerateHandler, NotificationHandler, RequestPaymentHandler, VersioningHandler, WebsiteHandler, ACLHandler, Handler, TaggingHandler

### Community 17 - "renovate.json"
Cohesion: 0.04
Nodes (46): :automergeDigest, config:recommended, :dependencyDashboard, docker:enableMajor, :semanticCommits, assignAutomerge, automerge, automergeType (+38 more)

### Community 18 - "Proxy Deployment Template"
Cohesion: 0.06
Nodes (44): s3-encryption-proxy Helm Chart, Helm Chart Configuration Reference, Evaluation-Tuned Chart Defaults, PodDisruptionBudget minAvailable/maxUnavailable Exclusivity, Production Installation with cert-manager, Chart Secrets Management Policy, cert-manager Certificate Template, Proxy ConfigMap Template (+36 more)

### Community 19 - "segManager"
Cohesion: 0.20
Nodes (24): assembleSession(), Manager, segRegisteredSession(), TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst(), TestSegmentedSessionLifecycle(), TestSegmentedSessionPartReupload(), TestSegmentedSessionRefusesABufferAboveTheLimit(), TestSegmentedSessionRefusesALayoutItCannotStore() (+16 more)

### Community 20 - "io.Reader"
Cohesion: 0.10
Nodes (12): io.ReadCloser, io.Reader, Manager, PartStoredLen(), ObjGetcloseErrReader, SealedPart, SegmentedUpload, SegmentedWrite (+4 more)

### Community 21 - "Ticket 010 Tier 2 Snapshot (AFTER)"
Cohesion: 0.06
Nodes (40): Tier 2 client CPU profile (performance-test.test, 23.97 s / 4.53 s samples), Client-side SHA-256 verification cost (crypto/sha256.Sum256, 17.88 % cum), Tier 2 client alloc_objects profile (204 319 objects, AWS SDK middleware dominated), Tier 2 client alloc_space profile (3.59 GB, io.ReadAll 71.29 % inside runPerformanceTest), performance-test runPerformanceTest (test harness allocating the 1 GB payload), Tier 2 proxy alloc_objects profile (465 597 objects, HTTP/TLS plumbing on top), Middleware chain alloc pass-through (gorilla/mux → monitoring.HTTPMiddleware → cors → logging → requestTracking → s3Auth, ~99.6 % cum), Tier 2 proxy alloc_space profile (10 007.86 MB total) (+32 more)

### Community 22 - "providers_coverage_test.go"
Cohesion: 0.07
Nodes (46): container/list.Element, container/list.List, sync/atomic.Int64, sync.RWMutex, buildDEKCacheKey(), OrcMetaAESProvider(), OrcMetaCachingManager(), OrcMetaNewProviderManager() (+38 more)

### Community 23 - "NewManager"
Cohesion: 0.19
Nodes (18): Manager, OrcMgrAESConfig(), OrcMgrNewManager(), orcMgrOpenSession(), OrcMgrPrefixPtr(), orcMgrSessionCount(), TestOrcMgrAccessorsAndMetadataFiltering(), TestOrcMgrBackgroundCleanupRemovesExpiredSessions() (+10 more)

### Community 24 - "NewXMLWriter"
Cohesion: 0.18
Nodes (21): RespCapturingLogger(), RespFindEntry(), RespNewFailingWriter(), TestRespWriteErrorDocumentSurvivesFailedWrite(), TestRespWriteS3ErrorLogLevels(), TestRespWriteS3ErrorNilErrorLogsNoDetail(), TestRespWriteS3ErrorSurvivesFailedWrite(), TestRespNewXMLWriter() (+13 more)

### Community 25 - "S3AuthenticationService"
Cohesion: 0.26
Nodes (4): github.com/sirupsen/logrus.Logger, S3AuthenticationService, NewS3AuthenticationService(), SignatureInfo

### Community 26 - "start-demo.sh"
Cohesion: 0.16
Nodes (32): build_project(), check_dependencies(), check_services(), cleanup(), generate_markdown_report(), get_iso_timestamp(), get_timestamp(), log_error() (+24 more)

### Community 27 - "Config"
Cohesion: 0.14
Nodes (26): EncryptionConfig, MonitoringConfig, OptimizationsConfig, S3BackendConfig, S3SecurityConfig, TLSConfig, aesKeyError(), createProviderFromProviderMap() (+18 more)

### Community 28 - "RandomString"
Cohesion: 0.25
Nodes (32): github.com/aws/smithy-go/middleware.Stack, EncObjectView, EncStored, RandomString(), EncAPICode(), EncAssertBodyIsCiphertext(), EncAssertEncryptedAtRest(), EncAssertHeadersClean() (+24 more)

### Community 29 - "PlanRange"
Cohesion: 0.16
Nodes (16): rangeReader, PlanRange(), Codec, Window, PlanRange(), segmentStoredLen(), min64(), TestSegRangeAmplificationBound() (+8 more)

### Community 30 - "testParser"
Cohesion: 0.13
Nodes (33): newChunkedRequest(), newTestRequest(), ReqnewTransferChunkedRequest(), TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented(), TestReqPlaintextContentLength(), TestReqReadAllSized_HintBoundaries(), TestReqReadBody_AWSChunkedTakesPrecedenceOverTransferEncoding(), TestReqReadBody_ForgedDecodedContentLength() (+25 more)

### Community 31 - "EnsureMinIOAndProxyAvailable"
Cohesion: 0.16
Nodes (26): TestRangeReadErrors(), TestRangeReadsOnEncryptedObjects(), EnsureMinIOAndProxyAvailable(), TestContext, NewTestContextWithTimeout(), apiCodeOf(), apiMessageOf(), errorsAs() (+18 more)

### Community 32 - "NewErrorWriter"
Cohesion: 0.16
Nodes (17): TestCopyHandler_NotSupportedWithEncryption(), TestHandler_CopyObjectHeaderDetection(), TestHandler_CopyObjectNotSupported(), TestHandleDeleteObject_InputValidation(), TestHandleDeleteObject_S3Error(), TestHandleDeleteObject_Success(), TestHandleDeleteObject_VersionID(), TestHandleDeleteObjectIntegration_BaseObjectOperations() (+9 more)

### Community 33 - "listbuckets_coverage_test.go"
Cohesion: 0.06
Nodes (45): commonPrefix, listBucketResultV1, listBucketResultV2, objectEntry, ownerEntry, github.com/sirupsen/logrus.FieldLogger, callerOwner(), formatLastModified() (+37 more)

### Community 34 - "delete_objects_batch_test.go"
Cohesion: 0.24
Nodes (29): DelDeletedEntry, DelErrorDoc, DelErrorEntry, DelRequestDoc, DelRequestObject, DelResponse, DelResultDoc, DelBuildDoc() (+21 more)

### Community 35 - "multipart_conformance_test.go"
Cohesion: 0.29
Nodes (27): github.com/aws/aws-sdk-go-v2/service/s3/types.CompletedPart, MpuShape, MpuTarget, MpuAbortQuiet(), MpuComplete(), MpuCreate(), MpuDigest(), MpuEncryptionMeta() (+19 more)

### Community 36 - "RtPxrouter"
Cohesion: 0.24
Nodes (16): github.com/gorilla/mux.RouteMatch, github.com/gorilla/mux.Router, Server, RtPxhandlerName(), RtPxmatch(), RtPxrouter(), TestRtPxBaseBucketHandlerRefusesSubResourceRequests(), TestRtPxBucketSubResourceNeverReachesBaseBucketHandler() (+8 more)

### Community 37 - "CreateTestBucket"
Cohesion: 0.22
Nodes (25): AESProxyTestInstance, ExitProxyTestInstance, context.CancelFunc, TestChunkedUploadDecoding(), getKeys(), IsAESProviderActive(), StartAESProviderProxyInstance(), TestAESProvider_LargeFile() (+17 more)

### Community 38 - "listobjects_conformance_test.go"
Cohesion: 0.16
Nodes (31): github.com/aws/aws-sdk-go-v2/service/s3/types.CommonPrefix, github.com/aws/aws-sdk-go-v2/service/s3/types.Object, lstBulkFixture, lstRefFixture, lstAssertElementOrder(), lstBody(), lstBulkKeys(), lstChildElements() (+23 more)

### Community 39 - "net/http.Handler"
Cohesion: 0.29
Nodes (4): net/http.Handler, CORS, NewCORS(), Server

### Community 40 - "validator_coverage_test.go"
Cohesion: 0.14
Nodes (20): LicenseClaims, LicenseValidator, LicclaimsFor(), LicclearLicenseEnv(), LicforeignKey(), LicrequireStopReturns(), LicsignWith(), LictamperPayload() (+12 more)

### Community 41 - "Ticket 015: Configuration hygiene"
Cohesion: 0.07
Nodes (39): Tier 6: honest measurement (baselines, parallel and small-object benchmarks), encryption.verify_upload_digests, void before it was built, D-24: keep the failure map with trusted-proxy CIDRs and eviction, D-6: refuse a plain-HTTP backend under an encrypting provider, D-7: s3_security.max_presign_expiry_seconds, E-1: max_clock_skew_seconds ignored on the Authorization-header path, E-3: integrity_verification defaults to off while the docs recommend strict, N-5: four dead s3_security knobs and the failed-attempt map (+31 more)

### Community 42 - "middleware_coverage_test.go"
Cohesion: 0.17
Nodes (11): MonrequestMetric(), TestMonHTTPMiddlewareDefaultsToStatus200(), TestMonHTTPMiddlewareRecordsRoutedRequest(), TestMonHTTPMiddlewareTracksActiveConnections(), TestMonHTTPMiddlewareUnknownEndpoint(), TestMonResponseWriterCapturesStatusCode(), TestMonResponseWriterForwardsToTheLiveWriter(), TestMonResponseWriterKeepsTheWriterCapabilities() (+3 more)

### Community 43 - "validation_coverage_test.go"
Cohesion: 0.24
Nodes (13): CfgExitProviderConfig(), CfgValidClients(), Config, TestCfgValidateEncryptionProviderList(), TestCfgValidateLicenseAndEncryption(), TestCfgValidateMonitoringPprofBindAddress(), TestCfgValidateOptimizationsBoundaries(), TestCfgValidatePropagatesSubValidatorErrors() (+5 more)

### Community 44 - "object/metadata_coverage_test.go"
Cohesion: 0.15
Nodes (18): MockS3Backend, ObjMiscnewHandlerWithPrefix(), copyWithPooledBuffer(), ObjMiscdigest(), ObjMiscpayload(), TestObjMiscCleanMetadataEdgeInputs(), TestObjMiscCleanMetadataHonoursACustomPrefix(), TestObjMiscCleanMetadataStripsOnlyThePrefixedKeys() (+10 more)

### Community 45 - "NewTestContext"
Cohesion: 0.18
Nodes (13): NewTestContext(), downloadAndVerifyWithSDK(), performMultipartUploadWithSDK(), TestStreamingMultipartUpload(), TestStreamingVsStandardPerformance(), TestDeleteObjectFunctionality(), TestListBucketsOperation(), TestListBucketsPassthrough() (+5 more)

### Community 46 - "Load"
Cohesion: 0.20
Nodes (30): InitConfig(), Load(), LoadAndStartLicense(), setDefaults(), TestLoad_MissingTargetEndpoint(), TestLoad_ValidExitConfig(), CfgNoLicense(), CfgResetViper() (+22 more)

### Community 47 - "envexpand_test.go"
Cohesion: 0.14
Nodes (23): TestCfgExpandConfigEnvVarsErrorPerField(), TestCfgExpandConfigEnvVarsExpandsEveryField(), expandConfigEnvVars(), expandEnvVars(), Config, TestExpandConfigEnvVars_MissingProviderVarReturnsError(), TestExpandConfigEnvVars_MissingVarReturnsError(), TestExpandConfigEnvVars_MultipleClientsWithMixedRefs() (+15 more)

### Community 48 - "orchestration/metadata_coverage_test.go"
Cohesion: 0.31
Nodes (15): Manager, OrcMetaAssertOnlyAllowedKeys(), OrcMetaConfig(), OrcMetaNewManager(), OrcMetaPrefixedKeys(), OrcMetaPrefixPtr(), OrcMetaSHA256(), TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten() (+7 more)

### Community 49 - "main_coverage_test.go"
Cohesion: 0.18
Nodes (24): collectLicenseInfo(), LicTcaptureStdout(), LicTextractToken(), LicTkey(), LicTwithStdin(), LicTwritePEM(), TestLicTCollectLicenseInfo(), TestLicTEndToEnd() (+16 more)

### Community 50 - "TamSetup"
Cohesion: 0.35
Nodes (9): TamEnv, TamShape, TamAssertRefused(), TamDigest(), TamInspect(), TamSetup(), TestSegmentChainRefusesTamperedBytes(), TestSegmentChainRefusesTamperedMetadata() (+1 more)

### Community 51 - "runProxy"
Cohesion: 0.15
Nodes (14): initConfig(), runProxy(), github.com/prometheus/client_golang/prometheus.Gatherer, github.com/prometheus/client_golang/prometheus.Labels, github.com/spf13/cobra.Command, MondefaultMetric(), MongatherMetric(), TestMonGetKubernetesLabels() (+6 more)

### Community 52 - "monitoring/server_coverage_test.go"
Cohesion: 0.16
Nodes (17): net.Listener, Server, MonfreeAddr(), Monserve(), TestMonNewServerConfiguration(), TestMonServerEndpointsSurviveWriteFailures(), TestMonServerHealthEndpoint(), TestMonServerInfoEndpoint() (+9 more)

### Community 53 - "Checksum"
Cohesion: 0.23
Nodes (3): Codec, Checksum, Codec

### Community 54 - "comprehensive_chunked_test.go"
Cohesion: 0.18
Nodes (18): ChunkedReader, createAWSChunkedDataMultiChunk(), createAWSChunkedEncodedBody(), downloadObjectSimple(), generateTestData(), NewChunkedReader(), parseChunkedDataManually(), TestChunkedEncodingCornerCases() (+10 more)

### Community 55 - "setupMultipartTestEnv"
Cohesion: 0.22
Nodes (23): github.com/stretchr/testify/mock.Arguments, NewCreateHandler(), alignedPlaintext(), assertDetachedContext(), setupMultipartTestEnv(), TestAbortHandler_AbortSurvivesCancelledRequestContext(), TestAbortHandler_Handle(), TestCompleteHandler_AbortSurvivesClientDisconnect() (+15 more)

### Community 56 - "http_middleware_coverage_test.go"
Cohesion: 0.20
Nodes (10): MwechoHandler(), MwtestLogger(), TestMwCORSMiddleware(), TestMwLoggerDefaultsToOKWithoutExplicitWriteHeader(), TestMwLoggerMiddleware(), TestMwRequestTracker(), TestMwResponseWriterForwardsToTheLiveWriter(), TestMwResponseWriterKeepsTheWriterCapabilities() (+2 more)

### Community 57 - "testLogger"
Cohesion: 0.09
Nodes (36): bufio.Reader, bytes.Reader, NewChunkedDecoderBase(), ReqbuildHTTPChunked(), TestReqHTTPChunkedDecoder_ImplementsInterface(), TestReqHTTPChunkedDecoder_ProcessChunkedData_Malformed(), TestReqHTTPChunkedDecoder_ProcessChunkedData_MissingTrailingCRLF(), TestReqHTTPChunkedDecoder_ProcessChunkedData_NoHugePreallocation() (+28 more)

### Community 58 - "canonicalQueryString"
Cohesion: 0.20
Nodes (10): net/url.Values, canonicalQueryString(), canonicalURI(), S3AuthenticationService, isPresignedRequest(), parseCredentialScope(), TestCanonicalQueryString(), TestCanonicalURI() (+2 more)

### Community 59 - "github.com/aws/aws-sdk-go-v2/service/s3.Client"
Cohesion: 0.16
Nodes (23): StreamingReader, github.com/aws/aws-sdk-go-v2/service/s3.Client, cleanupTestFile(), downloadLargeFile(), generateLargeFileTestData(), NewStreamingReader(), TestComprehensiveMultipartUpload(), TestMultipartUploadCorruption() (+15 more)

### Community 60 - "minio_test_helper.go"
Cohesion: 0.16
Nodes (19): CleanupTestBucket(), ClearBucketObjects(), CompareObjectData(), contains(), createMinIOClient(), createProxyClient(), CreateProxyClientWithEndpoint(), findInString() (+11 more)

### Community 61 - "handler_coverage_test.go"
Cohesion: 0.21
Nodes (17): HlthfailingWriter, HlthrecordingWriter, HlthnewFailingWriter(), HlthnewTestLogger(), TestHlthHealthHealthyResponse(), TestHlthHealthShutdownStateHandlerVariants(), TestHlthHealthShutdownStateIsReEvaluatedPerRequest(), TestHlthLogHealthRequests() (+9 more)

### Community 62 - "TestExitProvider_ReadsBackAnEncryptedObject"
Cohesion: 0.41
Nodes (11): assertStoredEncrypted(), assertStoredPlaintext(), getViaClient(), randomPayload(), storedObject(), TestExitProvider_ClientDrivenMultipart(), TestExitProvider_ReadsBackAMultipartObject(), TestExitProvider_ReadsBackAnEncryptedObject() (+3 more)

### Community 63 - "Ticket 012: Performance improvements round 2"
Cohesion: 0.13
Nodes (21): The 42% crypto floor was 10 points of backend TLS, Per-tier measurement protocol (pprof through a shared network namespace), Rejected then reversed: segmented AEAD format change, Ticket 012: Performance improvements round 2, Tier 1.2: the 30s blanket Read/WriteTimeout (N-8), Tier 1.3: dead code and per-GET Info logs, Tier 1.4 / D-29: pooled copy buffer versus io.ReaderFrom, Tier 2.2: destructive aws-chunked body sniff (+13 more)

### Community 64 - "LiccaptureLogs"
Cohesion: 0.20
Nodes (19): github.com/sirupsen/logrus/hooks/test.Hook, github.com/sirupsen/logrus.Level, LiclevelOf(), TestLicFormatTimeRemainingSubHour(), TestLicLogLicenseInfoExhaustedTimeRemaining(), TestLicLogLicenseInfoExpiringSoon(), TestLicLogLicenseInfoFullDetails(), TestLicLogLicenseInfoInvalidResult() (+11 more)

### Community 65 - "calculateTimeRemaining"
Cohesion: 0.17
Nodes (14): sync/atomic.Bool, sync.Once, jwt.RegisteredClaims, LicenseValidator, calculateTimeRemaining(), checkClaims(), TestLicCalculateTimeRemainingBoundaries(), TestLicCheckClaimsRejectsATokenWithoutAnExpiryClaim() (+6 more)

### Community 66 - "presignTestService"
Cohesion: 0.19
Nodes (20): TestMwPresignedRejections(), S3AuthenticationService, requireAuthErr(), signWithSDK(), TestAuthenticateRequest_ClockSkew(), TestAuthenticateRequest_HeaderTampering(), TestAuthenticateRequest_MalformedHeaders(), TestAuthenticateRequest_SDKSignedHeaders() (+12 more)

### Community 67 - "package.json"
Cohesion: 0.10
Nodes (20): author, description, devDependencies, conventional-changelog-conventionalcommits, semantic-release, @semantic-release/changelog, @semantic-release/git, @semantic-release/github (+12 more)

### Community 68 - "CiphertextSize"
Cohesion: 0.27
Nodes (10): CiphertextSize(), crc32Combine(), TestSegEncryptReaderRoundTrip(), gf2MatrixSquare(), gf2MatrixTimes(), PlaintextSize(), segmentCount(), TestSegOversizeRefused() (+2 more)

### Community 69 - "NewAESKeyEncryptor"
Cohesion: 0.07
Nodes (36): KeyEncryptionType, AESProvider, ExitProvider, FacFactoryWithAES(), TestFacCreateAESKeyEncryptorKEKPathMatchesBase64Path(), TestFacCreateKeyEncryptorFromConfigTypes(), TestFacGetKeyEncryptor(), TestFacKeyEncryptionTypeConstants() (+28 more)

### Community 70 - "RtPxserver"
Cohesion: 0.30
Nodes (11): Server, RtPxauthHeader(), RtPxserver(), RtPxsignedRequest(), TestRtPxDetermineErrorCodeMapping(), TestRtPxMiddlewareChainStreamsBodyUnchanged(), TestRtPxMiddlewareWrappersInitialiseOnDemand(), TestRtPxS3AuthMiddlewareAcceptsSignedRequest() (+3 more)

### Community 71 - "Provider comparison: RSA, AES, None"
Cohesion: 0.20
Nodes (11): Helm repo index on gh-pages, Release Helm Chart to GitHub Pages job, aes-envelope provider (config/aes-example.yaml), Multi-provider config (aes-current plus rsa-backup), ${VAR} environment variable references, Helm deployment and the missing private-key value, Provider comparison: RSA, AES, None, H-8 The AES KEK fingerprint is a plain hash of the key (+3 more)

### Community 72 - "Ticket 013: Storage format v2 — segmented AES-GCM"
Cohesion: 0.10
Nodes (36): Tier 4.3: GOMEMLIMIT and GOMAXPROCS container tuning, D-32: authenticated DEK wrap and HKDF key admission for the aes KEK, Rejected alternatives: CTR+per-segment HMAC, stored part layout, refuse ranges, AAD = formatID + clientObjectKey + index, The bucket stays out of the AAD (D-33), One client part is one backend part, checked at Complete, Three rules of the hostile-backend threat model, KEK fingerprint becomes HKDF-Expand over the KEK (+28 more)

### Community 73 - "NewServer"
Cohesion: 0.05
Nodes (60): bytes.Buffer, net.Addr, writeChunks(), backendClientOptions(), RtPxconfig(), RtPxnewFailingListener(), RtPxstringPtr(), TestRtPxHealthReportsShutdownState() (+52 more)

### Community 74 - "Server"
Cohesion: 0.22
Nodes (3): RequestTracker, NewRequestTracker(), Server

### Community 75 - "Release 4.0.0"
Cohesion: 0.18
Nodes (14): BREAKING: metadata_key_prefix must match ^[a-z0-9-]+$, Fix: a client can no longer write into the proxy metadata namespace, BREAKING: /debug/pprof on its own loopback listener, Release 4.0.0, Envelope encryption: KEK and DEK layers, Start with the knowledge graph (graphify), s3ep-* metadata keys, Tink provider is an unreachable stub (+6 more)

### Community 76 - "H-5 integrity_verification does not refuse a tampered aes-ctr object"
Cohesion: 0.16
Nodes (18): Decisions live in ADRs; tickets are deleted, Auto-multipart and the metadata self-copy, GET request flow, Integrity verification modes (off, lax, strict, hybrid), orchestration.Manager facade, PUT request flow, Integrity verification: detection, not refusal, Objects without s3ep-* metadata are served as-is (+10 more)

### Community 77 - "Ticket 022: S3 surface fidelity"
Cohesion: 0.15
Nodes (19): Tier 3.3: HEAD and List report the ciphertext size, The rsa provider type is removed in 5.0.0, start-after, fetch-owner and encoding-type are silently dropped, handleHeadBucket is a listing in disguise, A real ListBucketResult document instead of the marshalled SDK struct, No per-key HeadObject in a listing, under any circumstances, Listing sizes computed by the proxy, never read from the backend, Ticket 018: ListObjectsV2 — a real S3 document and plaintext sizes (+11 more)

### Community 78 - "Performance baseline — pre-v2"
Cohesion: 0.18
Nodes (10): In-process crypto floor, Instruments, Key unwrap, Machine, Performance baseline — pre-v2, Proxy resident memory, Ranged read — proxy against direct backend, Small objects — request rate (+2 more)

### Community 79 - "The client-driven upload"
Cohesion: 0.20
Nodes (10): A session outlives its request, so something has to end it, Back pressure, Five things that are not obvious, Multipart uploads, The client-driven upload, The internal producer, The part table is the authority, Under the exit provider there is no session at all (+2 more)

### Community 80 - "Testing"
Cohesion: 0.20
Nodes (10): Coverage, Integration suites, Not a layer: the performance baseline, Running them, Testing, The layers, Two suites start the proxy in process, What CI runs (+2 more)

### Community 81 - "net/http.Header"
Cohesion: 0.34
Nodes (17): github.com/aws/aws-sdk-go-v2/service/s3.Options, net/http.Header, HdrCaptureResponseBody(), HdrCaptureResponseHeaders(), HdrCleanupBucket(), HdrGetHeaders(), HdrHeadHeaders(), HdrIsObjectHeader() (+9 more)

### Community 82 - "config_test.go"
Cohesion: 0.27
Nodes (9): TestGetActiveProvider(), TestGetActiveProvider_NoAlias(), TestGetActiveProvider_NotFound(), TestGetAllProviders(), TestValidateEncryption_MissingActiveProvider(), TestValidateEncryption_MissingAESKey(), TestValidateEncryption_UnsupportedType(), TestValidateEncryption_ValidAES() (+1 more)

### Community 83 - "time.Time"
Cohesion: 0.21
Nodes (6): time.Time, Handler, AWSV4Signer, NewAWSV4Signer(), SignHTTPRequestForS3(), SignHTTPRequestForS3WithCredentials()

### Community 84 - "Handler"
Cohesion: 0.14
Nodes (5): ACLHandler, Handler, TaggingHandler, IsAWSProtocolQueryParam(), TestReqIsAWSProtocolQueryParam()

### Community 85 - "What this run says"
Cohesion: 0.20
Nodes (9): 1. The segment chain is 3.4× faster than the path it replaces, 2. Upload falls off a cliff at exactly the threshold; download is at parity, 3. The proxy barely gets faster when the client asks for more at once, 4. Ranged reads cost little today, and alignment costs nothing, 5. Memory: the container limit is nowhere near reached, 6. RSA unwrap is four orders of magnitude off the local key provider, Two measurement bugs were found and fixed before this run, What this run cannot tell you (+1 more)

### Community 86 - "partCodec"
Cohesion: 0.40
Nodes (9): Codec, partCodec(), sealInParts(), TestSegOpenTrailerRejectsTampering(), TestSegPartWriterOffsetIsAuthenticated(), TestSegPartWriterRefusesShortMiddlePart(), TestSegPartWriterRefusesUnalignedOffset(), TestSegPartWriterRoundTrip() (+1 more)

### Community 88 - "range_conformance_test.go"
Cohesion: 0.36
Nodes (14): rngCase, rngFixture, rngObserved, rngCasesFor(), rngNewFixture(), rngPayload(), rngRawGet(), rngViaMinIO() (+6 more)

### Community 89 - "comprehensive_singlepart_test.go"
Cohesion: 0.29
Nodes (18): PerformanceMetrics, calculateThroughput(), cleanupSinglePartTestFile(), downloadSinglePartFile(), downloadSinglePartFileWithMetrics(), formatDataSize(), formatThroughput(), generateSinglePartTestData() (+10 more)

### Community 90 - "NewHandler"
Cohesion: 0.20
Nodes (10): TestBucketHandle_BaseOperationsStillReachTheBackend(), TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed(), TestBucketHandle_UnroutedSubResourceIsNotABaseOperation(), TestHandleCreateBucket(), TestHandleDeleteBucket(), NewHandler(), TestMainBucketHandler_NewHandlers(), NewLifecycleHandler() (+2 more)

### Community 91 - "Request paths"
Cohesion: 0.22
Nodes (9): Before the handler, DELETE, GET, HEAD, PUT, Ranged GET, Request paths, The multipart verbs (+1 more)

### Community 92 - "s3auth_coverage_test.go"
Cohesion: 0.26
Nodes (13): S3AuthenticationService, MwauthService(), MwhmacSHA256(), MwsignDateHeaderRequest(), TestMwAuthenticateRequestDateHeaderPath(), TestMwAuthenticateRequestRejections(), TestMwAuthErrorsCarryTheS3ErrorCodeMarkers(), TestMwBuildCanonicalHeaders() (+5 more)

### Community 93 - "NewValidator"
Cohesion: 0.33
Nodes (8): LicenseValidator, NewValidator(), TestLicenseClaims(), TestNewValidator(), TestValidateLicense_EmptyToken(), TestValidateLicense_InvalidToken(), TestValidateProviderType_NoLicense(), TestValidateProviderType_WithLicense()

### Community 94 - "ADR 0024: An upload forwards while it receives"
Cohesion: 0.25
Nodes (8): ADR 0024: An upload forwards while it receives, Alternatives Considered, Consequences, Context, Decision, References, Residual risks, Status

### Community 95 - "ADR 0025: Leaving is a supported mode"
Cohesion: 0.25
Nodes (8): ADR 0025: Leaving is a supported mode, Alternatives Considered, Consequences, Context, Decision, References, Residual risks, Status

### Community 96 - "The storage format"
Cohesion: 0.25
Nodes (8): Layout, Parts are segment-aligned, Ranged reads, Testing convention for this package, The storage format, The three invariants everything rests on, What marks an object as ours, What the reader guarantees, and what it does not

### Community 97 - "bucket_acl_test.go"
Cohesion: 0.17
Nodes (14): github.com/aws/aws-sdk-go-v2/service/s3/types.AccessControlPolicy, github.com/aws/aws-sdk-go-v2/service/s3/types.BucketCannedACL, mapCannedACLForBucket(), parseACLXMLForTest(), TestACLXMLParsing(), TestCannedACLMapping(), TestHandleBucketACL_GET_NoClient(), parseACLXML() (+6 more)

### Community 98 - "backendOptions"
Cohesion: 0.39
Nodes (6): backendOptions(), TestBackendClientOptions_ChecksumsOnlyWhenRequired(), TestBackendClientOptions_InsecureSkipVerify(), TestBackendClientOptions_NoEndpointLeavesDefaults(), TestBackendClientOptions_PathStyleAndEndpoint(), discardWriter

### Community 99 - "NewWebsiteHandler"
Cohesion: 0.43
Nodes (7): NewWebsiteHandler(), TestWebsiteHandler_ComplexConfigurations(), TestWebsiteHandler_DocumentSuffixValidation(), TestWebsiteHandler_Handle(), TestWebsiteHandler_HandleErrors(), TestWebsiteHandler_RoutingRuleTypes(), TestWebsiteHandler_XMLValidation()

### Community 100 - "Semantic Release job"
Cohesion: 0.17
Nodes (13): Build Docker Image job, SBOM, provenance and Docker Scout scan, Coverage badge committed with the release, e2e-velero as a release gate, Pinned golangci-lint v2 module path, GoSec Security Scan job, Vulnerability Check job, Code Linting job (+5 more)

### Community 101 - "auth_test.go"
Cohesion: 0.25
Nodes (13): SimpleTestContext, createValidAWS4Signature(), hmacSHA256(), NewSimpleTestContext(), TestAuthentication(), testClockSkewProtection(), testEnterpriseSecurityConfiguration(), testRateLimiting() (+5 more)

### Community 102 - "Local performance baseline"
Cohesion: 0.25
Nodes (8): Comparing two commits, How big a change has to be to be real, Local performance baseline, Running it, The instruments, The second proxy that `uploadpath` needs, Things that will bite you, What a run writes

### Community 103 - "Ticket index"
Cohesion: 0.16
Nodes (18): N-1: an object without proxy metadata is InvalidObjectState 403, none-provider-fingerprint forgery under an encrypting provider, Blocked on v2: tests written now would pin behaviour v2 deletes, Responses composed from an allowlist, pinned by a unit test, Mock files without a _test.go suffix counted as production code, Ticket 019: Handler-level unit coverage, C-1: the security counters were a remote kill switch, C-2: a forged chunk header could allocate gigabytes, or panic (+10 more)

### Community 104 - "MockS3Backend"
Cohesion: 0.15
Nodes (8): github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketInput, github.com/aws/aws-sdk-go-v2/service/s3.CreateBucketOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteBucketOutput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectInput, github.com/aws/aws-sdk-go-v2/service/s3.DeleteObjectOutput, github.com/stretchr/testify/mock.Mock, MockS3Backend

### Community 105 - "NewPprofServer"
Cohesion: 0.23
Nodes (8): net/http.Server, TestPprofNewServerConfiguration(), TestPprofServerReportsItsFailures(), TestPprofServerServesOnlyProfiling(), TestPprofServerStartServesAndShutsDownOnContextCancel(), NewPprofServer(), PprofServer, Server

### Community 106 - "encryption_validation_helper.go"
Cohesion: 0.27
Nodes (14): EncryptionValidationConfig, EncryptionValidationResult, AssertDataIsEncrypted(), AssertDataIsNotEncrypted(), calculateShannonEntropy(), CompareEncryptionStrength(), ConfigForDataSize(), containsForbiddenPatterns() (+6 more)

### Community 107 - "SegmentedSession"
Cohesion: 0.14
Nodes (5): sync.Mutex, Manager, SegmentedSession, FinalPart, sessionPart

### Community 108 - "Ticket 010: Performance Improvements - Streaming Throughput"
Cohesion: 0.05
Nodes (59): Baseline Client CPU Top-20 Profile, Client v4 Chunked SHA-256 Signing Cost (28% CPU), Baseline Client alloc_objects Profile, Baseline Client alloc_space Profile, Client io.ReadAll of the 1 GB GET Body (2.56 GB, 71%), Baseline Proxy alloc_objects Top-15, decryptionReader.Read Object-Alloc Hotspot (16.2%, rank 2), logrus Entry.WithFields Object-Alloc Hotspot (23.0%, rank 1) (+51 more)

### Community 112 - "performance_test.go"
Cohesion: 0.19
Nodes (18): testing.B, benchGetResponse(), BenchmarkGetResponseCopy(), copyWithSize(), benchReader, hidingWriter, ComparisonResult, PerformanceResult (+10 more)

### Community 114 - "net.Conn"
Cohesion: 0.23
Nodes (3): bufio.ReadWriter, net.Conn, responseWriter

### Community 115 - "Errors"
Cohesion: 0.29
Nodes (7): Aborting a body, Choosing a status class, Errors, How a backend error is classified, The refusals worth knowing, What never reaches a client, Where this is still wrong

### Community 116 - "NewNotificationHandler"
Cohesion: 0.48
Nodes (6): NewNotificationHandler(), TestNotificationHandler_ComplexConfigurations(), TestNotificationHandler_EventTypes(), TestNotificationHandler_Handle(), TestNotificationHandler_HandleErrors(), TestNotificationHandler_XMLValidation()

### Community 117 - "NewReplicationHandler"
Cohesion: 0.48
Nodes (6): NewReplicationHandler(), TestReplicationHandler_ComplexConfigurations(), TestReplicationHandler_Handle(), TestReplicationHandler_HandleErrors(), TestReplicationHandler_ReplicationMetrics(), TestReplicationHandler_XMLValidation()

### Community 118 - "Vault as a key provider — open decisions, parked"
Cohesion: 0.25
Nodes (11): Tier 3.1: metadata at initiate, delete the self-CopyObject, >5 GiB failure, Tier 5.1: GCM GET unwraps the DEK twice, P-1: the DEK is unwrapped twice on every GCM GET, Vault availability becomes proxy availability, The demo Vault needs fixing regardless, The fingerprint identifies mount and key name, never the version, Key custody is what this buys, and only that, A rewrap campaign is a full server-side rewrite, not a metadata edit (+3 more)

### Community 119 - "NewTaggingHandler"
Cohesion: 0.48
Nodes (6): NewTaggingHandler(), TestTaggingHandler_Handle(), TestTaggingHandler_HandleErrors(), TestTaggingHandler_MaxTagLimits(), TestTaggingHandler_SpecialCharacterHandling(), TestTaggingHandler_XMLTagValidation()

### Community 120 - "Breaking Change Guard"
Cohesion: 0.38
Nodes (7): ADR 0018: a major release is declared by a label, check-breaking-changes.sh detector, Breaking Change Guard, Pull-request title and body inspection, release:major label, npm clean-install --ignore-scripts under a write token, Version Dry Run job

### Community 121 - "The three rules"
Cohesion: 0.22
Nodes (10): No backward compatibility, s3_security block in the shipped examples, No rate limiting, Operations refused with 501 or 422, H-7 Dead security configuration knobs, The S3 backend is hostile, ListParts still pretends, Handlers refuse rather than pretend (+2 more)

### Community 122 - "Performance baseline — segment-codec, item 1"
Cohesion: 0.29
Nodes (6): In-process crypto floor, Instruments, Key unwrap, Machine, Performance baseline — segment-codec, item 1, Stack

### Community 123 - "Where the upload deficit actually is"
Cohesion: 0.29
Nodes (6): The proxy is faster than the backend when it streams, The self-copy is not the cause, What follows for the storage format change, What the write path does, and what it does not, What this run does not tell you, Where the upload deficit actually is

### Community 124 - "Performance baseline — upload path decomposition"
Cohesion: 0.29
Nodes (6): Backend self-copy (single-leg profiling harness), Instruments, Machine, Performance baseline — upload path decomposition, Stack, Upload write paths — streaming against auto-multipart

### Community 125 - "Performance baseline — pre-v2-uploadpath"
Cohesion: 0.29
Nodes (6): Backend self-copy (single-leg profiling harness), Instruments, Machine, Performance baseline — pre-v2-uploadpath, Stack, Upload write paths — streaming against auto-multipart

### Community 126 - "validator.go"
Cohesion: 0.28
Nodes (8): crypto/rsa.PublicKey, TestLicLoadLicenseFromFile(), LoadLicense(), LoadLicenseFromEnv(), LoadLicenseFromFile(), parseEmbeddedPublicKey(), TestLoadLicenseFromEnv(), TestParseEmbeddedPublicKey()

### Community 127 - "Integration Tests job"
Cohesion: 0.20
Nodes (11): Integration Tests job, Performance tests run in isolation, TLS integration run (checksum-trailer framing), aes-envelope provider over TLS (config/aes-tls-example.yaml), TLS listener example (config/aes-tls-example.yaml), Client checksums are dropped, never forwarded, Pre-signed URL support, Clock skew comes from two different places (+3 more)

### Community 128 - "install.sh"
Cohesion: 0.40
Nodes (10): check_prerequisites(), create_namespace(), get_version(), install_chart(), log_error(), log_info(), log_warn(), main() (+2 more)

### Community 129 - "A Configuration Key Exists Only If Code Reads It"
Cohesion: 0.15
Nodes (17): A Control That Exists Only in Configuration Is Worse Than No Control, An End-to-End Suite Proves One Client, Never the Scope, A Configuration Key Exists Only If Code Reads It, No Rate Limiting and No Per-Address Blocking, Pre-Signed URL Expiry Cap and Uniform Clock Skew, No Wall Clock on a Transfer, shutdown_timeout Is the Only Server-Side Transfer Budget, The License Expiry Is Discovered by a Build, Not by an Environment (+9 more)

### Community 130 - "Authenticated Segment Chain (s3ep-gcm-seg-v2)"
Cohesion: 0.20
Nodes (10): Integrity Is Not Separable From Decryption, Every Served Byte Is Proxy-Verified at Read Granularity, Provider Selection by s3ep-kek-fingerprint, Bounded Ranged Read Over Segments, Authenticated Segment Chain (s3ep-gcm-seg-v2), Authenticated AES-256-GCM Key Wrap with Per-Wrap Salt, The KMS Fingerprint Identifies the Key, Not Its Material, HashiCorp Vault Transit as the First KMS Backend (+2 more)

### Community 131 - "Hostile Backend Threat Model"
Cohesion: 0.28
Nodes (9): Hostile Backend Threat Model, An Error Behind a Non-Error Status Becomes 500, The Multipart <Location> Names the Proxy, Not the Backend, The Backend Account Never Appears in a Response, Every Response Is Composed by the Proxy, Listings Are Real S3 Documents Built by the Proxy, No Client Checksum Reaches the Backend, No Plaintext Checksum in Metadata, Encryption at Rest Is Asserted by Reading the Backend Directly (+1 more)

### Community 132 - "compare.py"
Cohesion: 0.48
Nodes (6): human(), key(), load(), machine_line(), main(), Compare two performance baseline runs. ./test/perf/compare.py perf-…

### Community 133 - "Ticket 014: Verify client upload checksums"
Cohesion: 0.29
Nodes (11): Tier 1.1: disable AWS SDK flexible checksums, Sealed plaintext CRC32C served as x-amz-checksum-crc32c, The client-to-proxy leg is where plaintext still exists, CRC64NVME slicing-by-8 table rebuild trap, Never forwarded, never stored, never echoed, P-5: one body reader for every handler, Later: a plaintext response checksum, Ticket 014: Verify client upload checksums (+3 more)

### Community 137 - "conditional_requests_test.go"
Cohesion: 0.45
Nodes (10): condOutcome, condPrecondition, condCodeOf(), condGet(), condHead(), condPayload(), condPutObject(), condStatusOf() (+2 more)

### Community 139 - "A KMS-Backed KEK Is Its Own Provider Type"
Cohesion: 0.22
Nodes (10): Content-Keyed DEK Cache, Key Rotation Is a Configuration Procedure, Associated Data Binds Format Id, Client Object Key and Index, A KMS-Backed KEK Is Its Own Provider Type, Server-Side Copy Refused With 422 NotSupportedWithEncryption, Profiling on Its Own Loopback Listener, Response Wrappers Preserve Flush, Hijack and ReaderFrom, Performance Is Measured Before and After, Never Asserted (+2 more)

### Community 140 - "Forward It or Refuse It, Never Silently Drop It"
Cohesion: 0.24
Nodes (10): The Proxy Serves Any S3 Client, Forward It or Refuse It, Never Silently Drop It, SSE-C Refused With 501 Until Every Verb Carries the Key, Uniform Storage-Header Forwarding on Every Upload Path, A Client Metadata Key Inside the Namespace Is Refused, Listing Parameters Honoured or Refused, max-keys Validated, Every Declared Client Checksum Is Verified Against the Plaintext, Multi-Object Delete Must Carry a Verified Body Digest (+2 more)

### Community 146 - "Performance"
Cohesion: 0.33
Nodes (6): Before you change a hot path, Performance, Reporting, The after column this release owes, What ruins a comparison, What the instrument can and cannot separate

### Community 149 - "Writer"
Cohesion: 0.16
Nodes (7): sealSink, Writer, io.Writer, writerOnly, Codec, Codec, EncryptReader

### Community 150 - "responseWriter"
Cohesion: 0.28
Nodes (3): Logger, NewLogger(), responseWriter

### Community 151 - "Combined Coverage job"
Cohesion: 0.29
Nodes (8): Combined coverage merge (GOCOVERDIR), Combined Coverage job, Test and Release workflow, Unit Tests job, Assign on Renovate pipeline failure, Renovate Application job, The Go version lives in exactly two files, Combined unit and integration coverage commands

### Community 152 - "The segment codec, measured"
Cohesion: 0.33
Nodes (5): A 1.7× that was nearly a 1.0×, Not measured here, The prediction was 3.4×. The measurement is 1.75×., The segment codec, measured, What this does and does not change

### Community 154 - "Handler"
Cohesion: 0.22
Nodes (3): StripAWSChunked(), TestStripAWSChunked(), Handler

### Community 155 - "The "before" column for the producer restructuring"
Cohesion: 0.40
Nodes (5): Against the battery run of the same morning, The "before" column for the producer restructuring, What is new against the run of the same morning, What the shape of that column says, What this run does not tell you

### Community 156 - "TestLargeMultipart500MB"
Cohesion: 0.38
Nodes (4): simplePRNG, TestLargeMultipart500MB(), generateDeterministicData(), newSimplePRNG()

### Community 157 - "coverage-summary.py"
Cohesion: 0.43
Nodes (6): main(), module_path(), percent(), Per-package coverage table for the CI report. Reads the text profiles that…, {location: (statements, count)} for one text-format profile., read_profile()

### Community 169 - "MockS3Backend"
Cohesion: 0.16
Nodes (7): github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLoggingInput, github.com/aws/aws-sdk-go-v2/service/s3.GetBucketLoggingOutput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesInput, github.com/aws/aws-sdk-go-v2/service/s3.GetObjectAttributesOutput, github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyInput, github.com/aws/aws-sdk-go-v2/service/s3.UploadPartCopyOutput, MockS3Backend

### Community 182 - "github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketInput"
Cohesion: 0.48
Nodes (3): github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketInput, github.com/aws/aws-sdk-go-v2/service/s3.HeadBucketOutput, BktcaptureHead()

### Community 201 - "An Unworkable Configuration Refuses to Start"
Cohesion: 0.22
Nodes (10): One 256-bit Data Key per Object, An Object Is Readable From Itself, Key Admission Rules (No Passphrases), One Local Key Provider (type aes), Custody by Injection Is Not a KMS, The Metadata Prefix Is the Proxy's Exclusive Namespace, Prefix Shape Rule ^[a-z0-9][a-z0-9-]{2,}-$, An Unworkable Configuration Refuses to Start (+2 more)

### Community 205 - "DEK cache key (fingerprint:objectKey)"
Cohesion: 0.47
Nodes (6): DEK cache key (fingerprint:objectKey), Option A: include encryptedDEK digest in the cache key, Option B: invalidate the DEK cache on write, Option C: key the cache by encryptedDEK only, TestLargeMultipart500MB reproduction, Ticket 011: DEK cache returns stale DEK after re-upload

### Community 206 - "check-breaking-changes.sh"
Cohesion: 0.47
Nodes (5): add_message(), die(), FOOTER_PATTERN, HEADER_PATTERN, check-breaking-changes.sh script

### Community 209 - "e2e-up.sh"
Cohesion: 0.53
Nodes (5): k(), KUBECONFIG, log(), need(), e2e-up.sh script

### Community 210 - "bucket_policy_test.go"
Cohesion: 0.60
Nodes (5): analyzePolicySecurity(), TestBucketPolicyComplexStructures(), TestBucketPolicySecurityAnalysis(), TestBucketPolicyValidation(), validatePolicyJSON()

### Community 211 - "Velero E2E (kind) job"
Cohesion: 0.40
Nodes (5): Velero E2E (kind) job, Testing strategy: unit, integration, Velero e2e, Development workflow and pull-request process, Velero kopia repository password warning, License expiry stops the proxy

### Community 212 - ".handleBucket"
Cohesion: 0.50
Nodes (3): testTrackingHandler, Handler, TestBucketListingWithQueryParameters()

### Community 213 - "Reporting a vulnerability"
Cohesion: 0.13
Nodes (15): Documentation States What the Code Verifies (D10), The ADR Is Written in the Session the Decision Is Taken, An ADR Carries No References Into the Code, ADR Index and Ground Rules, Entry points, Everything else, `internal/orchestration/` — the encryption facade the handlers call, `internal/proxy/` — the HTTP surface (+7 more)

### Community 214 - "Authenticated Trailer (Length and Sealed CRC32C)"
Cohesion: 0.40
Nodes (5): Authenticated Trailer (Length and Sealed CRC32C), Tail-First Whole-Object Read with If-Match, Bounded Short-Part Buffer for the Trailer, The Proxy Serves Its Own Sealed CRC32C on Whole-Object Reads, Memory Is Held by a Test on a Hard Bound

### Community 219 - "Fail Closed on Foreign Objects (InvalidObjectState 403)"
Cohesion: 0.50
Nodes (4): Fail Closed on Foreign Objects (InvalidObjectState 403), Well-Formedness Guard on the Stored-to-Plaintext Size Function, Every Reported Size Describes the Plaintext, There Is No Migration; the Data Is Uploaded Again From Its Source

## Ambiguous Edges - Review These
- `Proxy ConfigMap Template` → `Development Values Profile`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/values-development.yaml · relation: shares_data_with
- `Proxy ConfigMap Template` → `Monitoring Values Profile`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/values-monitoring.yaml · relation: shares_data_with
- `Helm Unittest Deployment Suite` → `Default Chart Values`  [AMBIGUOUS]
  deploy/helm/s3-encryption-proxy/tests/deployment_test.yaml · relation: references
- `runtime.memclrNoHeapPointers at 11.71 % of proxy CPU in Tier 4.1 (3.28 % in Tier 2)` → `Tier 2 proxy CPU profile (15 s, 5.48 s samples, crypto + syscalls dominant)`  [AMBIGUOUS]
  docs/tickets/010-tier4.1/proxy-cpu-top20.txt · relation: references

## Knowledge Gaps
- **258 isolated node(s):** `HEADER_PATTERN`, `FOOTER_PATTERN`, `version-dry-run.sh script`, `github.com/guided-traffic/s3-encryption-proxy`, `dekCacheEntry` (+253 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 487 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **51 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `Proxy ConfigMap Template` and `Development Values Profile`?**
  _Edge tagged AMBIGUOUS (relation: shares_data_with) - confidence is low._
- **What is the exact relationship between `Proxy ConfigMap Template` and `Monitoring Values Profile`?**
  _Edge tagged AMBIGUOUS (relation: shares_data_with) - confidence is low._
- **What is the exact relationship between `Helm Unittest Deployment Suite` and `Default Chart Values`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `runtime.memclrNoHeapPointers at 11.71 % of proxy CPU in Tier 4.1 (3.28 % in Tier 2)` and `Tier 2 proxy CPU profile (15 s, 5.48 s samples, crypto + syscalls dominant)`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **Why does `Manager` connect `github.com/sirupsen/logrus.Entry` to `multipart_coverage_test.go`, `CreateTestBucket`, `NewMetadataManager`, `Server`, `SegmentedSession`, `context.Context`, `Handler`, `Handler`, `setupMultipartTestEnv`, `providers_coverage_test.go`, `NewManager`, `NewHandler`, `Config`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **Why does `parseChunkedDataManually()` connect `comprehensive_chunked_test.go` to `io.Reader`, `testing.T`?**
  _High betweenness centrality (0.013) - this node is a cross-community bridge._
- **Why does `OrcMetaCachingManager()` connect `providers_coverage_test.go` to `testing.T`?**
  _High betweenness centrality (0.010) - this node is a cross-community bridge._