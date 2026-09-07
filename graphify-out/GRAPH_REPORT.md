# Graph Report - .  (2026-09-07)

## Corpus Check
- Large corpus: 309 files · ~459,572 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder, or use --no-semantic to run AST-only.

## Summary
- 4261 nodes · 16468 edges · 46 communities detected
- Extraction: 50% EXTRACTED · 49% INFERRED · 0% AMBIGUOUS · INFERRED: 8140 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_S3 Error Response Layer|S3 Error Response Layer]]
- [[_COMMUNITY_MinIO Integration Test Suite|MinIO Integration Test Suite]]
- [[_COMMUNITY_Envelope Crypto Providers|Envelope Crypto Providers]]
- [[_COMMUNITY_Orchestration Manager and Multipart|Orchestration Manager and Multipart]]
- [[_COMMUNITY_Multipart and Bucket Handlers|Multipart and Bucket Handlers]]
- [[_COMMUNITY_Object Handler Dispatch|Object Handler Dispatch]]
- [[_COMMUNITY_Ticket Backlog and License Tool|Ticket Backlog and License Tool]]
- [[_COMMUNITY_Ticket Decisions and Findings|Ticket Decisions and Findings]]
- [[_COMMUNITY_HMAC Integrity and Streaming IO|HMAC Integrity and Streaming IO]]
- [[_COMMUNITY_Proxy Server and Middleware Wiring|Proxy Server and Middleware Wiring]]
- [[_COMMUNITY_Configuration Loading and Validation|Configuration Loading and Validation]]
- [[_COMMUNITY_Bucket Sub-Resource Routing|Bucket Sub-Resource Routing]]
- [[_COMMUNITY_License Validation and Startup|License Validation and Startup]]
- [[_COMMUNITY_Object PUT and Auto-Multipart|Object PUT and Auto-Multipart]]
- [[_COMMUNITY_Request Body Decoding|Request Body Decoding]]
- [[_COMMUNITY_SigV4 Authentication|SigV4 Authentication]]
- [[_COMMUNITY_Velero Backup e2e Scenarios|Velero Backup e2e Scenarios]]
- [[_COMMUNITY_Root and Health Handlers|Root and Health Handlers]]
- [[_COMMUNITY_Provider Manager and Fingerprints|Provider Manager and Fingerprints]]
- [[_COMMUNITY_Monitoring Metrics Middleware|Monitoring Metrics Middleware]]
- [[_COMMUNITY_Performance Profiling Tiers|Performance Profiling Tiers]]
- [[_COMMUNITY_Proxy Error Utilities|Proxy Error Utilities]]
- [[_COMMUNITY_Orchestration Package Architecture|Orchestration Package Architecture]]
- [[_COMMUNITY_HKDF Key Derivation|HKDF Key Derivation]]
- [[_COMMUNITY_Encryption Validation Helpers|Encryption Validation Helpers]]
- [[_COMMUNITY_Binary Test Fixture|Binary Test Fixture]]
- [[_COMMUNITY_Encryption Interfaces|Encryption Interfaces]]
- [[_COMMUNITY_Deterministic Test Data|Deterministic Test Data]]
- [[_COMMUNITY_Deprecated Handler Migration|Deprecated Handler Migration]]
- [[_COMMUNITY_Request Decoder Interface|Request Decoder Interface]]
- [[_COMMUNITY_S3 Backend Interface|S3 Backend Interface]]
- [[_COMMUNITY_Encryption Result Type|Encryption Result Type]]
- [[_COMMUNITY_Trust Boundaries and Roles|Trust Boundaries and Roles]]
- [[_COMMUNITY_Vulnerability Reporting Channels|Vulnerability Reporting Channels]]
- [[_COMMUNITY_Not Implemented Response|Not Implemented Response]]
- [[_COMMUNITY_Detailed Not Implemented Response|Detailed Not Implemented Response]]
- [[_COMMUNITY_Router File|Router File]]
- [[_COMMUNITY_Middleware Setup File|Middleware Setup File]]
- [[_COMMUNITY_Bucket Operations File|Bucket Operations File]]
- [[_COMMUNITY_Single Part Operations File|Single Part Operations File]]
- [[_COMMUNITY_Credential Rotation Restart|Credential Rotation Restart]]
- [[_COMMUNITY_AES-GCM FIPS Hot Symbol|AES-GCM FIPS Hot Symbol]]
- [[_COMMUNITY_CRC32 Checksum Hot Symbol|CRC32 Checksum Hot Symbol]]
- [[_COMMUNITY_Tier 4.1 Alloc Profile|Tier 4.1 Alloc Profile]]
- [[_COMMUNITY_Provider Lookup By Alias|Provider Lookup By Alias]]
- [[_COMMUNITY_HMAC Calculator Reset|HMAC Calculator Reset]]

## God Nodes (most connected - your core abstractions)
1. `run()` - 626 edges
2. `contains()` - 397 edges
3. `New()` - 338 edges
4. `EnsureMinIOAndProxyAvailable()` - 83 edges
5. `NewHandler()` - 77 edges
6. `NewErrorWriter()` - 72 edges
7. `NewTestContextWithTimeout()` - 65 edges
8. `MockS3Backend` - 63 edges
9. `MockS3Backend` - 63 edges
10. `MockS3Backend` - 63 edges

## Surprising Connections (you probably didn't know these)
- `parseDuration overflows into a negative validity (pinned defect)` --semantically_similar_to--> `Ticket 020: development license expiry and a CI check`  [INFERRED] [semantically similar]
  cmd/license-tool/main_coverage_test.go → docs/tickets/020-dev-license-expiry.md
- `Tier 1.2 blanket 30 s Read/WriteTimeout kills slow transfers` --semantically_similar_to--> `Graceful shutdown with active-request tracking`  [INFERRED] [semantically similar]
  docs/tickets/012-performance-audit-round2.md → cmd/s3-encryption-proxy/main.go
- `One deadline for the whole shutdown wait` --semantically_similar_to--> `Tier 1.2 blanket 30 s Read/WriteTimeout kills slow transfers`  [INFERRED] [semantically similar]
  cmd/s3-encryption-proxy/main.go → docs/tickets/012-performance-audit-round2.md
- `TestMpuThreePartRoundTrip()` --conceptually_related_to--> `Ticket 022: S3 surface fidelity`  [AMBIGUOUS]
  test/integration/s3-methods/multipart_conformance_test.go → docs/tickets/022-s3-surface-fidelity.md
- `TestRngMalformedRangeHeader()` --conceptually_related_to--> `Ticket 013: Storage format v2`  [AMBIGUOUS]
  test/integration/s3-methods/range_conformance_test.go → docs/tickets/013-storage-format-v2.md

## Hyperedges (group relationships)
- **PUT Request Upload Flow** — readme_managerv2_encrypt, readme_singlepart, readme_providers, readme_factory, readme_metadata [EXTRACTED 1.00]
- **Multipart Upload Session Lifecycle** — readme_initiate_session, readme_process_part, readme_finalize_session, readme_abort_session, readme_hmac_manager [EXTRACTED 1.00]
- **GET Request Download Flow** — readme_managerv2_decrypt, readme_get_algorithm, readme_singlepart, readme_providers, readme_factory, readme_hmac_manager [EXTRACTED 1.00]
- **Rule 2: a control that exists only in configuration or documentation** — security_architecture_three_rules, security_architecture_h7, security_architecture_refusing_handlers, 015_n5_dead_knobs, 016_checksum_config_annotation, security_architecture_helm_propagation_gap, 020_misleading_error [EXTRACTED 0.95]
- **The hostile-backend integrity chain that storage format v2 closes** — security_architecture_hostile_backend, security_architecture_h1, security_architecture_h5, security_architecture_h6, readme_integrity_verification, 013_storage_format_v2_ticket, 013_fail_closed [EXTRACTED 0.95]
- **Envelope encryption: KEK, DEK, fingerprint and the stored metadata set** — claude_encryption_providers_architecture, security_architecture_key_hierarchy, security_architecture_object_metadata, security_architecture_kek_rotation, claude_metadata_allowlist, 013_metadata_v2, 013_kek_fingerprint_change [INFERRED 0.85]
- **The silent 200: the proxy answers success to a request it does not honour** — 022_s3_surface_fidelity_silent_200, 022_s3_surface_fidelity_item1_s8, tickets_readme_s8, 024_coverage_round_findings_x2, 024_coverage_round_findings_h7, 024_coverage_round_findings_x1, 022_s3_surface_fidelity_threat_rule_2 [EXTRACTED 0.95]
- **Everything that must ride the one format break** — 013_storage_format_v2, 023_major_v4_members, 022_s3_surface_fidelity_item8_rsa_fingerprint, tickets_readme_d20, tickets_readme_d21, tickets_readme_d28, 024_coverage_round_findings_s1, 024_coverage_round_findings_s5, 025_tink_kms_hcvault [EXTRACTED 0.90]
- **The tier-by-tier profile loop of ticket 010** — 010_baseline_snapshot, 010_tier1_snapshot, 010_tier1_3_snapshot, 010_tier2_snapshot, 010_baseline_rerun_recipe, pprof_io_readall, orchestration_multipartoperations_processpartordered, pprof_runtime_memmove [EXTRACTED 0.90]
- **The UploadPart path that buffers every part in memory (io.ReadAll = 64.6% of allocations, unchanged from tier 2 to tier 4.1)** — parser_readbody, chunked_decoder_requireschunkeddecoding, upload_handlestreaminguploadpart, multipart_processpartordered, io_readall, tier41_proxy_allocs_top20 [INFERRED 0.85]
- **Loopback-only pprof containment: profiles carry DEKs and plaintext, so the bind address is a startup gate rather than a doc note (D-22)** — config_monitoringconfig, config_validatemonitoring, config_requireloopbackaddress, pprof_newpprofserver, server_newserver, validation_coverage_test_testcfgvalidatemonitoringpprofbindaddress [EXTRACTED 0.90]
- **Fail-closed licence lifecycle: load, verify against the compiled-in key, monitor hourly, exit(1) on expiry, and stop without hanging when unlicensed (D-25)** — validator_loadlicense, validator_validatelicense, validator_checkclaims, validator_startruntimemonitoring, validator_gracefulshutdown, validator_stop, config_loadandstartlicense [EXTRACTED 0.90]
- **Multipart session lifecycle (DEK, IV, ordered parts, HMAC, teardown)** — orchestration_multipartsession, orchestration_partbuffer, orchestration_multipartoperations_initiatesession, orchestration_multipartoperations_processpart, orchestration_multipartoperations_processpartordered, orchestration_multipartoperations_processpartdatainorder, orchestration_multipartoperations_processbufferedpartsdata, orchestration_multipartoperations_finalizesession, orchestration_multipartoperations_abortsession, orchestration_multipartoperations_cleanupsession, orchestration_multipartoperations_cleanupexpiredsessions [EXTRACTED 0.95]
- **HMAC-SHA256 integrity path from upload to verified download** — validation_hmacmanager_createcalculator, validation_hmaccalculator_add, orchestration_multipartoperations_processpartdatainorder, validation_hmacmanager_finalizecalculator, orchestration_metadatamanager_sethmac, orchestration_metadatamanager_gethmac, validation_hmacmanager_verifyintegrity, orchestration_hmacgateddecryptionreader_read, orchestration_hmacvalidatingreader_read [INFERRED 0.90]
- **none-provider sentinel fingerprint short-circuits every crypto path** — orchestration_providermanager_isnoneprovider, orchestration_manager_isnoneproviderdata, orchestration_multipartoperations_createnoneprovidersession, orchestration_multipartoperations_processnoneproviderpartstream, orchestration_manager_createrangedecryptionreader, orchestration_manager_encryptdata, orchestration_providermanager_decryptdek [INFERRED 0.85]
- **Multipart upload lifecycle over one manager session** — create_handle, upload_handlestreaminguploadpart, complete_handle, abort_handle, manager_manager, list_handlelistparts [EXTRACTED 0.95]
- **Bucket sub-resource dispatch and the base-operation guard** — router_setuproutes, handler_handle, handler_knownsubresources, handler_basebucketparams, acl_handle, cors_handle, logging_handle, subresource_matrix_coverage_test_testbktsubresourcemethodmatrixneverreachesbasebucketoperation [EXTRACTED 0.90]
- **Escaped S3 XML response contract for multipart** — xml_writexmldocument, xml_initiatemultipartuploadresult, xml_listpartsresult, xml_completemultipartuploadresult, create_handle, list_handlelistparts, complete_handle [EXTRACTED 0.90]
- **GET path: SigV4 check, dispatch, DEK unwrap, streaming decrypt, pooled copy** — s3auth_robust_authenticaterequest, logging_middleware, handler_handle, operations_handlegetobject, helpers_extractencryptionmetadata, singlepart_createstreamingdecryptionreaderwithsize, operations_writegetobjectresponse, helpers_copywithpooledbuffer [INFERRED 0.85]
- **Ranged read: plaintext offsets onto CTR keystream, GCM falls back to full decryption** — range_handlegetobjectrange, range_contentrangestart, rangeread_createrangedecryptionreader, range_writerangeresponse, range_serverangebyfulldecryption, range_parsebyterange, ciphertext_size_computeplaintextsize [EXTRACTED 0.95]
- **Auto-multipart PUT: incremental HMAC, disconnect-proof abort and self-copy metadata** — operations_handleputobject, operations_ishmacenabled, operations_putobjectautomultipart, manager_initiatemultipartupload, manager_uploadpart, manager_completemultipartupload, utils_cleanupcontext, parser_plaintextcontentlength [EXTRACTED 0.95]
- **aws-chunked framing decode pipeline (header detection, buffered and streaming paths, plaintext length accounting)** — parser_readbody, parser_streamingreader, streaming_aws_decoder_isawschunkedrequest, streaming_aws_decoder_streamingawschunkedreader, parser_decodedcontentlength, parser_plaintextcontentlength, framing_test_allframings, operations_putobjectstreamingreader [INFERRED 0.90]
- **Pre-signed SigV4 URL validation (Velero download path)** — s3auth_robust_authenticaterequest, s3auth_presigned_ispresignedrequest, s3auth_presigned_authenticatepresigned, s3auth_presigned_validatepresignexpiry, s3auth_presigned_buildpresignedcanonicalrequest, s3auth_presigned_parsecredentialscope, s3auth_presigned_canonicalquerystring, s3auth_robust_calculatesignature, queryparams_isawsprotocolqueryparam [EXTRACTED 0.95]
- **S3 error rendering: one mapper, two duplicated writers** — error_mapping_maperror, error_mapping_codestatus, error_mapping_codeforstatus, error_mapping_internalmarkers, errors_writes3error, errors_writeerrordocument, utils_handles3error, utils_s3errorresponse, errors_s3error [EXTRACTED 0.95]
- **KEK providers implementing one KeyEncryptor contract** — rsa_rsaprovider, aes_aesprovider, tink_tinkprovider, none_noneprovider, interfaces_keyencryptor, factory_keyencryptiontype [EXTRACTED 0.95]
- **Envelope encryption path: content type picks the DEK provider, the KEK wraps it, metadata records the pairing** — factory_determinecontenttypefromhttpcontenttype, factory_createenvelopeencryptor, envelope_encryptdatastream, aes_gcm_encryptstream, aes_ctr_encryptstream, rsa_encryptdek, rsa_fingerprint, factory_getkeyencryptor, ciphertext_size_computeciphertextsize [INFERRED 0.85]
- **Integrity chain: DEK to HKDF integrity key to HMAC-SHA256 verification** — aes_ctr_generatedek, hkdf_deriveintegritykey, hmac_manager_createcalculator, hmac_calculator_newhmaccalculator, hmac_calculator_addfromstream, hmac_manager_verifyintegrity, hkdf_coverage_test_valfilehmacsalt [INFERRED 0.85]
- **Encryption at rest asserted by reading the backend directly** — scenarios_atrest_test_testv8_encryptionatrest, scenarios_atrest_test_testv8b_datamoverpayloadencryptedatrest, encryption_at_rest_test_testenceveryputpathstoresciphertext, encryption_at_rest_test_encassertencryptedatrest, comprehensive_multipart_test_verifydataintegrity, comprehensive_singlepart_test_verifysinglepartencryptionmetadata, comprehensive_singlepart_ctr_test_verifyctrsinglepartencryptionmetadata, comprehensive_chunked_test_testchunkeduploaddecoding, delete_objects_batch_test_delhasencryptionmetadata [INFERRED 0.85]
- **Tests pinned to the 5 MiB streaming threshold (GCM below, CTR above)** — workloads_writetestfiles, encryption_at_rest_test_encstreamingthreshold, range_read_test_testrangereadsonencryptedobjects, comprehensive_singlepart_ctr_test_testcomprehensivesinglepartctrupload, comprehensive_multipart_test_verifyfileinminio, hmac_validation_test_testsinglepartctrwithhmac, conditional_requests_test_condpayload, delete_objects_batch_test_testdelbatchdeleteremoveslargeencryptedobjects [INFERRED 0.80]
- **MinIO as the differential oracle for proxy behaviour** — encryption_at_rest_test_encoraclebucket, encryption_at_rest_test_enccompareviews, delete_objects_batch_test_delnewminiobucket, conditional_requests_test_testcondgetandheadpreconditions, minio_test_helper_createminioclient, minio_test_helper_testcontext, performance_test_testperformancecomparison [INFERRED 0.80]
- **MinIO as the differential oracle for S3 semantics** — listobjects_conformance_test_lstsetup, multipart_conformance_test_mputargets, range_conformance_test_rngrawget, object_headers_conformance_test_hdrputwithentityheaders, minio_test_helper_testcontext [EXTRACTED 0.95]
- **The 28-byte AES-GCM envelope leaking into the client-visible S3 surface** — listobjects_conformance_test_testlstlistobjectsv2sizeisciphertextdeviation, object_metadata_consistency_test_testobjectsizeisconsistentacrossheadgetandlist, range_conformance_test_testrnggcmoverheadneverleaksintorangedreads, range_conformance_test_testrngunsatisfiablerangecontentrange, object_headers_conformance_test_testhdretagispresentandstableacrossrepeatedheads [INFERRED 0.86]
- **Bare fmt.Errorf in the multipart path renders client faults as 500 InternalError** — multipart_conformance_test_testmpucompletewithemptypartlist, multipart_conformance_test_testmpuabortremovestheupload, multipart_conformance_test_testmpuuploadpartwithunknownuploadid, error_mapping_maperror, complete_handle [EXTRACTED 0.92]
- **Single-part PUT: handler to envelope encryptor** — operations_putobjectdirect, manager_encryptdatawithhttpcontenttype, manager_encryptdatawithcontenttype, singlepart_encryptgcm, singlepart_encryptctr, providers_createenvelopeencryptor, factory_createenvelopeencryptor [EXTRACTED 1.00]
- **Multipart session lifecycle: initiate, process part, finalize, cleanup** — multipart_initiatesession, multipart_processpart, multipart_processpartdatainorder, multipart_finalizesession, multipart_cleanupsession, hmac_manager_createcalculator, hmac_manager_finalizecalculator, aes_ctr_newaesctrstatefulencryptor [EXTRACTED 1.00]
- **GET decrypt path with HMAC integrity check** — singlepart_decryptdatawithmetadata, manager_decryptdata, singlepart_decryptgcmstream, singlepart_decryptctrstream, providers_decryptdek, hmac_manager_verifyintegrity, streaming_io_hmacvalidatingreader_read [EXTRACTED 1.00]
- **Proxy boot: runProxy builds the server, which wires the encryption manager, then starts it** — main_runproxy, proxy_newserver, manager_newmanager, manager_getloadedproviders, proxy_server_setshutdownstatehandler, proxy_server_setrequesttracker, main_runproxy_5, proxy_server_start [INFERRED 0.90]
- **setupRoutes registers every handler package (root, object, multipart, health, bucket) - the 28-edge god node of this layer** — router_setuproutes, root_handler_newhandler, object_handler_newhandler, multipart_handler_newhandler, health_handler_newhandler, bucket_handler_newhandler, multipart_handler_getcreatehandler, multipart_handler_getuploadhandler, multipart_handler_getcompletehandler, bucket_handler_getaclhandler, object_handler_getaclhandler [INFERRED 0.90]
- **Middleware chain: setupMiddleware constructs tracker/logger/CORS/S3 auth, the Server wrappers delegate to their Middleware methods** — middleware_setup_setupmiddleware, tracking_newrequesttracker, tracking_sethandlers, logging_newlogger, cors_newcors, s3auth_robust_news3authenticationservice, middleware_setup_corsmiddleware, cors_middleware, middleware_setup_loggingmiddleware, logging_middleware, middleware_setup_requesttrackingmiddleware, tracking_middleware [INFERRED 0.90]
- **CLI bootstrap: flags, cobra init hook, viper config load** — main_main, main_init, cobra_oninitialize, main_initconfig, config_initconfig, cobra_command_execute [INFERRED 0.90]
- **Config load plus license validation before any server starts** — main_runproxy, config_loadandstartlicense, validator_validatelicense, metrics_setlicenseinfo, validator_stop [INFERRED 0.90]
- **Server construction and concurrent start of proxy plus monitoring** — main_runproxy, proxy_newserver, proxy_server_setshutdownstatehandler, proxy_server_setrequesttracker, monitoring_newserver, main_runproxy_4, monitoring_server_start, main_runproxy_5, proxy_server_start, main_runproxy_6, metrics_setserverinfo [INFERRED 0.90]

## Communities

### Community 0 - "S3 Error Response Layer"
Cohesion: 0.01
Nodes (104): Item 2: dead code the sweep exposed, Two XML response writers producing different bytes, NewACLHandler(), AccelerateHandler, ACLHandler, CORSHandler, LifecycleHandler, LocationHandler (+96 more)

### Community 1 - "MinIO Integration Test Suite"
Cohesion: 0.02
Nodes (363): Ticket 018: ListObjectsV2 document, ChunkedReader, PerformanceMetrics, StreamingReader, getKeys(), IsAESProviderActive(), StartAESProviderProxyInstance(), TestAESProvider_LargeFile() (+355 more)

### Community 2 - "Envelope Crypto Providers"
Cohesion: 0.02
Nodes (284): Tier 1.1 in-place XOR in the AES-CTR stateful encryptor, I-2: the wrapped DEK aliased the buffer being zeroized, AESProvider (AES-CTR KEK wrap), KekAESKeyA / KekAESKeyB (distinct KEKs), KekBytePattern(), KekNewAES(), TestKekAESDecryptDEKRejectsForeignKeyID(), TestKekAESDecryptDEKTooShort() (+276 more)

### Community 3 - "Orchestration Manager and Multipart"
Cohesion: 0.03
Nodes (224): TestBucketLocationCompliance(), TestBucketLocationDataResidency(), TestBucketLocationDisasterRecovery(), TestBucketLocationSecurityAnalysis(), TestBucketLocationValidation(), TestBucketSubResourceDocumentation(), TestBucketSubResourceImplementation(), putMultipartTwoParts() (+216 more)

### Community 4 - "Multipart and Bucket Handlers"
Cohesion: 0.02
Nodes (251): NewAbortHandler(), NewAccelerateHandler(), TestAccelerateHandler_AccelerateStatuses(), TestAccelerateHandler_AccelerationBenefits(), TestAccelerateHandler_BucketNamingRequirements(), TestAccelerateHandler_ContentTypeHandling(), TestAccelerateHandler_Handle(), TestAccelerateHandler_HandleErrors() (+243 more)

### Community 5 - "Object Handler Dispatch"
Cohesion: 0.03
Nodes (217): TestHandleBucketACL_GET_NoClient(), ComputePlaintextSize(), TestHandleDeleteObject_InputValidation(), TestHandleDeleteObject_S3Error(), TestHandleDeleteObject_Success(), TestHandleDeleteObject_VersionID(), TestHandleDeleteObjectIntegration_BaseObjectOperations(), ObjMiscdeleteObjects() (+209 more)

### Community 6 - "Ticket Backlog and License Tool"
Cohesion: 0.02
Nodes (201): Measure the baseline first, compare every tier against it, Ticket 010: streaming throughput performance improvements, Tier 1.3 eliminate per-Read logrus allocations, Tier 2.1 single-pass HMAC via io.TeeReader in EncryptCTR, Tier 4.2 pooled io.CopyBuffer on the GET path, Ticket 011: DEK cache returns a stale DEK after re-upload, Option A: include a digest of the encrypted DEK in the cache key, Option B: invalidate the cache on every write path (+193 more)

### Community 7 - "Ticket Decisions and Findings"
Cohesion: 0.02
Nodes (176): Ticket 011: DEK cache stale on re-upload, Ticket 012: Performance audit round 2, Ticket 013: Storage format v2, Ticket 014: Upload checksum verification, Ticket 015: Configuration hygiene, Ticket 016: Helm chart fixes, Ticket 017: Filename encryption, Ticket 019: Handler unit coverage (+168 more)

### Community 8 - "HMAC Integrity and Streaming IO"
Cohesion: 0.04
Nodes (126): H-1: integrity_verification strict does not protect an AES-CTR download, NewStreamingReader(), hashStringMap(), sha256Hex(), TestValDeriveIntegrityKeyMatchesManagerDerivation(), TestValHKDFConfigGetHashFunction(), HKDFConfig.getHashFunction, HMACCalculator.AddFromStream (128KB streaming) (+118 more)

### Community 9 - "Proxy Server and Middleware Wiring"
Cohesion: 0.02
Nodes (125): monitoring.pprof_enabled wires net/http/pprof onto the monitoring mux, S-3: pprof on the unauthenticated monitoring port exposes plaintext and keys, backendOptions(), TestBackendClientOptions_ChecksumsOnlyWhenRequired(), TestBackendClientOptions_InsecureSkipVerify(), TestBackendClientOptions_NoEndpointLeavesDefaults(), TestBackendClientOptions_PathStyleAndEndpoint(), benchGetResponse() (+117 more)

### Community 10 - "Configuration Loading and Validation"
Cohesion: 0.03
Nodes (142): TestCfgGetActiveProviderErrorPaths(), TestCfgGetActiveProviderReturnsLivePointer(), TestCfgGetAllProvidersReflectsSlice(), TestCfgGetProviderByAliasIsCaseSensitive(), TestCfgGetS3SecurityConfigAppliesDefaults(), TestCfgIsS3ClientAuthEnabled(), TestCfgIsValidProviderType(), TestCfgStreamingAccessors() (+134 more)

### Community 11 - "Bucket Sub-Resource Routing"
Cohesion: 0.05
Nodes (95): AbortHandler (AbortMultipartUpload), ACLHandler.Handle (?acl dispatch), handleGetACL (GetBucketAcl), handleMockACL (fabricated answer without backend), handlePutACL (PutBucketAcl, canned or XML body), BktclosingBody, BkterrorDoc, BktfailingReader (+87 more)

### Community 12 - "License Validation and Startup"
Cohesion: 0.03
Nodes (94): Tier 1.2 blanket 30 s Read/WriteTimeout kills slow transfers, A-1: every unlicensed shutdown hangs forever, atomic.LoadInt64(), Main Entrypoint Call Graph (diagram), Call graph: proxy/HTTP layer (gocallvis; 64 functions, 57 calls; hubs setupRoutes, utils.HandleS3Error, setupMiddleware), LoadAndStartLicense(), validateLicenseAndEncryption(), LicenseClaims (+86 more)

### Community 13 - "Object PUT and Auto-Multipart"
Cohesion: 0.05
Nodes (116): multipart.AbortHandler.Handle, AbortHandler.Handle (DELETE ?uploadId), AWSChunkedDecoder.RequiresChunkedDecoding, ComputeCiphertextSize(), TestComputeCiphertextSize(), TestComputePlaintextSize_EdgeCases(), TestComputePlaintextSize_InvertsComputeCiphertextSize(), multipart.CompleteHandler.Handle (+108 more)

### Community 14 - "Request Body Decoding"
Cohesion: 0.04
Nodes (101): ChunkedDecoder interface, ChunkedDecoderBase, NewChunkedDecoderBase(), allFramings (every aws-chunked variant), chunkedHeaders(), crc32Trailer(), framing (wire-format table type), newChunkedRequest() (+93 more)

### Community 15 - "SigV4 Authentication"
Cohesion: 0.05
Nodes (74): truncate(), discardWriter, S3AuthenticationService, SecurityMetrics, SignatureInfo, awsProtocolQueryPrefix (x-amz-), IsAWSProtocolQueryParam(), TestReqIsAWSProtocolQueryParam() (+66 more)

### Community 16 - "Velero Backup e2e Scenarios"
Cohesion: 0.09
Nodes (82): backendClient(), backendObject (stored object as the backend sees it), caTrustingHTTPClient(), hasEncryptionMetadata(), listBackendObjects(), metadataValue(), proxyClient(), readBackendObject() (+74 more)

### Community 17 - "Root and Health Handlers"
Cohesion: 0.04
Nodes (65): ACLHandler (bucket ?acl), BaseSubResourceHandler (shared sub-handler deps), BucketLoggingStatus, Grantee, LoggingEnabled, TargetGrant, CORSHandler (bucket ?cors), NewCORSHandler() (+57 more)

### Community 18 - "Provider Manager and Fingerprints"
Cohesion: 0.07
Nodes (47): config.Config.GetAllProviders, dekCacheEntry, MockKeyEncryptor, OrcMetaCountingKEK, ProviderInfo, ProviderManager, ProviderSummary, buildDEKCacheKey() (+39 more)

### Community 19 - "Monitoring Metrics Middleware"
Cohesion: 0.04
Nodes (50): io.copyBuffer (72% cum CPU on the download path), monitoring.ActiveConnections, MondefaultMetric(), MongatherMetric(), TestMonGetKubernetesLabels(), TestMonGetObjectSizeCategory(), TestMonPrometheusFmtBool(), TestMonRecordDownloadThroughput() (+42 more)

### Community 20 - "Performance Profiling Tiers"
Cohesion: 0.07
Nodes (50): Baseline client CPU top-20, Baseline client alloc_objects top-20, Baseline client alloc_space top, Baseline proxy alloc_objects top-15 (1.01 M objects), Baseline proxy alloc_space top-20 (17.97 GB), Baseline proxy CPU top-20, Per-tier profile capture recipe, Ticket 010 baseline snapshot (2026-04-23) (+42 more)

### Community 21 - "Proxy Error Utilities"
Cohesion: 0.08
Nodes (43): Item 3: two implementations of one error document, proxy.Server.handleBucketAccelerate, proxy.Server.handleBucketACL, proxy.Server.handleBucketCORS, proxy.Server.handleBucketLocation, proxy.Server.handleBucketLogging, proxy.Server.handleBucketPolicy, proxy.Server.handleBucketRequestPayment (+35 more)

### Community 22 - "Orchestration Package Architecture"
Cohesion: 0.09
Nodes (39): AbortSession, Buffer Pools (Memory Optimization), BuildMetadataForEncryption, CreateDecryptionReader, CreateEncryptionReader, DecryptCTR, DecryptGCM, DEK Caching (+31 more)

### Community 23 - "HKDF Key Derivation"
Cohesion: 0.12
Nodes (21): AESCTRDataEncryptor.GenerateDEK (256-bit), TestValDeriveIntegrityKeyPackageLevel(), TestValHKDFConfigDerivationProperties(), ValderiveReference(), ValFileHMACInfo (pinned wire-format info), ValFileHMACSalt (pinned wire-format salt), DeriveIntegrityKey(), HKDFConfig.DeriveIntegrityKeyWithRandomSalt (+13 more)

### Community 24 - "Encryption Validation Helpers"
Cohesion: 0.24
Nodes (15): AssertDataIsEncrypted(), AssertDataIsNotEncrypted(), calculateShannonEntropy(), CompareEncryptionStrength(), ConfigForDataSize(), containsForbiddenPatterns(), containsReadableStrings(), DefaultEncryptionValidationConfig() (+7 more)

### Community 25 - "Binary Test Fixture"
Cohesion: 0.21
Nodes (14): Non-text Content-Type carrier (image/jpeg) for metadata and header passthrough checks, start-demo.sh manual browse check: same object via encrypted proxy vs direct MinIO explorer, Two collared aracaris perched on a mossy branch (rainforest bokeh), Encryption-at-rest assertion: backend bytes must not equal the fixture bytes, test/example-files/ fixture corpus (text.txt, local_random_10mb/100mb/1gb/2gb, papagei.jpg), papagei.jpg binary test fixture, Already-compressed high-entropy payload, hostile to accidental plaintext survival, test/integration/ MinIO-backed integration suite (assumed consumer) (+6 more)

### Community 26 - "Encryption Interfaces"
Cohesion: 0.29
Nodes (6): DataEncryptor, EncryptionProvider, EncryptionType, EnvelopeEncryptor, IVProvider, KeyEncryptor

### Community 27 - "Deterministic Test Data"
Cohesion: 0.6
Nodes (3): simplePRNG, generateDeterministicData(), newSimplePRNG()

### Community 28 - "Deprecated Handler Migration"
Cohesion: 1.0
Nodes (0): 

### Community 29 - "Request Decoder Interface"
Cohesion: 1.0
Nodes (1): Decoder

### Community 30 - "S3 Backend Interface"
Cohesion: 1.0
Nodes (1): S3BackendInterface

### Community 31 - "Encryption Result Type"
Cohesion: 1.0
Nodes (1): EncryptionResult

### Community 32 - "Trust Boundaries and Roles"
Cohesion: 1.0
Nodes (2): Roles and what each is trusted for, Trust boundaries: proxy to backend is the one that matters

### Community 33 - "Vulnerability Reporting Channels"
Cohesion: 1.0
Nodes (2): Issues and discussions as the only support channels, Reporting a vulnerability, and the missing SECURITY.md

### Community 34 - "Not Implemented Response"
Cohesion: 1.0
Nodes (2): proxy.Server.writeNotImplementedResponse, utils.WriteNotImplementedResponse

### Community 35 - "Detailed Not Implemented Response"
Cohesion: 1.0
Nodes (2): proxy.Server.writeDetailedNotImplementedResponse, utils.WriteDetailedNotImplementedResponse

### Community 36 - "Router File"
Cohesion: 1.0
Nodes (0): 

### Community 37 - "Middleware Setup File"
Cohesion: 1.0
Nodes (0): 

### Community 38 - "Bucket Operations File"
Cohesion: 1.0
Nodes (0): 

### Community 39 - "Single Part Operations File"
Cohesion: 1.0
Nodes (0): 

### Community 40 - "Credential Rotation Restart"
Cohesion: 1.0
Nodes (1): Client credential rotation needs two restarts

### Community 41 - "AES-GCM FIPS Hot Symbol"
Cohesion: 1.0
Nodes (1): crypto/internal/fips140/aes/gcm.gcmAesEnc

### Community 42 - "CRC32 Checksum Hot Symbol"
Cohesion: 1.0
Nodes (1): hash/crc32.ieeeUpdate

### Community 43 - "Tier 4.1 Alloc Profile"
Cohesion: 1.0
Nodes (1): Tier 4.1 test-side alloc_objects profile

### Community 44 - "Provider Lookup By Alias"
Cohesion: 1.0
Nodes (1): Config.GetProviderByAlias

### Community 45 - "HMAC Calculator Reset"
Cohesion: 1.0
Nodes (1): HMACCalculator.Reset

## Ambiguous Edges - Review These
- `runProxy()` → `Tier 1.2 blanket 30 s Read/WriteTimeout kills slow transfers`  [AMBIGUOUS]
  docs/tickets/012-performance-audit-round2.md · relation: conceptually_related_to
- `testCAPool()` → `TestV8_EncryptionAtRest()`  [AMBIGUOUS]
  test/integration/minio_test_helper.go · relation: conceptually_related_to
- `testSinglePartCTRWithHMAC()` → `EncStreamingThreshold (5 MiB mirror)`  [AMBIGUOUS]
  test/integration/360-degree-variants/hmac_validation_test.go · relation: shares_data_with
- `TestStreamingMultipartUpload()` → `Integration test README (streaming multipart walkthrough)`  [AMBIGUOUS]
  test/integration/README.md · relation: references
- `TestMpuThreePartRoundTrip()` → `Ticket 022: S3 surface fidelity`  [AMBIGUOUS]
  test/integration/s3-methods/multipart_conformance_test.go · relation: conceptually_related_to
- `TestRngMalformedRangeHeader()` → `Ticket 013: Storage format v2`  [AMBIGUOUS]
  test/integration/s3-methods/range_conformance_test.go · relation: conceptually_related_to
- `TestRngMultipleRanges()` → `Ticket 022: S3 surface fidelity`  [AMBIGUOUS]
  test/integration/s3-methods/range_conformance_test.go · relation: conceptually_related_to
- `EncPayload()` → `text.txt (readable plaintext fixture)`  [AMBIGUOUS]
  test/example-files/text.txt · relation: conceptually_related_to
- `TestLstListObjectsV2SizeIsCiphertextDeviation()` → `Ticket 013: Storage format v2`  [AMBIGUOUS]
  test/integration/s3-methods/listobjects_conformance_test.go · relation: conceptually_related_to
- `listBackendObjects()` → `NewCTRRangeReader()`  [AMBIGUOUS]
  test/e2e/velero/backend.go · relation: conceptually_related_to
- `applyManifest()` → `AESCTRDataEncryptor.EncryptStream (fresh 16-byte IV)`  [AMBIGUOUS]
  test/e2e/velero/exec.go · relation: conceptually_related_to
- `TestServer_CORSOptionsRequest()` → `CORSHandler.Handle (?cors dispatch)`  [AMBIGUOUS]
  internal/proxy/server_test.go · relation: conceptually_related_to
- `uriEncode()` → `STREAMING-AWS4-HMAC-SHA256-PAYLOAD marker`  [AMBIGUOUS]
  internal/proxy/middleware/s3auth_presigned.go · relation: conceptually_related_to
- `TestAuthenticateRequest_SDKSignedHeaders()` → `Handler.putObjectStreamingReader (single-part CTR stream)`  [AMBIGUOUS]
  internal/proxy/middleware/s3auth_header_test.go · relation: conceptually_related_to
- `TestMapError_ConditionalGetKeepsIts304()` → `Handler.handlePutObject (PUT routing)`  [AMBIGUOUS]
  internal/proxy/response/error_mapping_test.go · relation: conceptually_related_to
- `TestHandleS3Error_EncryptionKeyMissing()` → `Factory.GetKeyEncryptor (by fingerprint)`  [AMBIGUOUS]
  internal/proxy/utils/utils_test.go · relation: conceptually_related_to
- `IsAWSProtocolQueryParam()` → `Handler.Handle (base bucket route guard)`  [AMBIGUOUS]
  internal/proxy/handlers/object/handler.go · relation: calls
- `TestReqIsAWSProtocolQueryParam()` → `Handler.Handle (base bucket route guard)`  [AMBIGUOUS]
  internal/proxy/request/queryparams_test.go · relation: conceptually_related_to
- `NewHandler()` → `TestNewHandler()`  [AMBIGUOUS]
  internal/proxy/handlers/root/handler_test.go · relation: references
- `StripAWSChunked()` → `buildCanonicalRequest (payload hash)`  [AMBIGUOUS]
  internal/proxy/middleware/s3auth_header_test.go · relation: conceptually_related_to
- `hmacGatedDecryptionReader` → `.GetStreamingSegmentSize()`  [AMBIGUOUS]
  internal/orchestration/streaming_io.go · relation: conceptually_related_to
- `Release History (semantic-release)` → `Ticket 013: storage format v2, segmented AES-GCM`  [AMBIGUOUS]
  docs/tickets/013-storage-format-v2.md · relation: conceptually_related_to
- `Package separation: pkg/encryption, internal/orchestration, internal/validation` → `Repository layout description (stale: internal/s3, pkg/envelope)`  [AMBIGUOUS]
  CONTRIBUTING.md · relation: conceptually_related_to
- `KEK provider table (aes, rsa, none; tink unusable)` → `rootCmd cobra command`  [AMBIGUOUS]
  cmd/s3-encryption-proxy/main.go · relation: references
- `Tier 3.1 metadata at CreateMultipartUpload, fixes the >5 GiB failure` → `Ticket 018: ListObjectsV2, a real S3 document and plaintext sizes`  [AMBIGUOUS]
  docs/tickets/018-listobjectsv2-document.md · relation: conceptually_related_to
- `Object lock: hostile backend versus compromised credential` → `N-4: Velero kopia repositories default to a published password`  [AMBIGUOUS]
  docs/tickets/022-s3-surface-fidelity.md · relation: conceptually_related_to
- `Item 4: <Location> is built from client-controlled request data` → `H-7: the S3 documents are not S3 documents`  [AMBIGUOUS]
  docs/tickets/022-s3-surface-fidelity.md · relation: conceptually_related_to
- `Item 22: the sub-resource guard refused every pre-signed download` → `H-6b: SigV4 canonicalisation rejects requests AWS accepts`  [AMBIGUOUS]
  docs/tickets/024-coverage-round-findings.md · relation: conceptually_related_to
- `P-1: the DEK is unwrapped twice on every GCM GET` → `Open question: is Tink's KMS envelope worth a second envelope`  [AMBIGUOUS]
  docs/tickets/025-tink-kms-hcvault.md · relation: conceptually_related_to
- `P-3: the two headline HTTP metrics are never exported` → `D-29: pooled copy path in both modes, then measure and delete the loser`  [AMBIGUOUS]
  docs/tickets/024-coverage-round-findings.md · relation: conceptually_related_to
- `io.ReadAll (64.6% of all proxy allocations)` → `Config.GetStreamingBufferSize`  [AMBIGUOUS]
  internal/config/config.go · relation: conceptually_related_to
- `Bucket Handler (facade)` → `Orchestration Manager`  [AMBIGUOUS]
  internal/proxy/handlers/bucket/handler.go · relation: conceptually_related_to
- `HandleListParts (GET ?uploadId, stub answer)` → `Orchestration Manager`  [AMBIGUOUS]
  internal/proxy/handlers/multipart/list.go · relation: conceptually_related_to
- `bucket MockS3Backend` → `root.Handler.HandleListBuckets`  [AMBIGUOUS]
  internal/proxy/handlers/root/test_helpers_test.go · relation: shares_data_with
- `papagei.jpg binary test fixture` → `test/e2e/velero/ backup/restore e2e suite (possible consumer)`  [AMBIGUOUS]
  test/example-files/papagei.jpg · relation: references
- `papagei.jpg binary test fixture` → `start-demo.sh manual browse check: same object via encrypted proxy vs direct MinIO explorer`  [AMBIGUOUS]
  test/example-files/papagei.jpg · relation: references
- `Byte-exact encrypt/decrypt round-trip fidelity for binary payloads` → `test/integration/ MinIO-backed integration suite (assumed consumer)`  [AMBIGUOUS]
  test/example-files/papagei.jpg · relation: implements
- `Non-text Content-Type carrier (image/jpeg) for metadata and header passthrough checks` → `test/integration/ MinIO-backed integration suite (assumed consumer)`  [AMBIGUOUS]
  test/example-files/papagei.jpg · relation: conceptually_related_to

## Knowledge Gaps
- **266 isolated node(s):** `LicenseClaims`, `EncryptionValidationResult`, `EncryptionValidationConfig`, `ComparisonResult`, `PerformanceMetrics` (+261 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Deprecated Handler Migration`** (2 nodes): `TestDeprecated_HandlersMigrated()`, `handlers_test.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Request Decoder Interface`** (2 nodes): `request_decoder.go`, `Decoder`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `S3 Backend Interface`** (2 nodes): `S3BackendInterface`, `s3_backend.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Encryption Result Type`** (2 nodes): `EncryptionResult`, `types.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Trust Boundaries and Roles`** (2 nodes): `Roles and what each is trusted for`, `Trust boundaries: proxy to backend is the one that matters`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Vulnerability Reporting Channels`** (2 nodes): `Issues and discussions as the only support channels`, `Reporting a vulnerability, and the missing SECURITY.md`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Not Implemented Response`** (2 nodes): `proxy.Server.writeNotImplementedResponse`, `utils.WriteNotImplementedResponse`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Detailed Not Implemented Response`** (2 nodes): `proxy.Server.writeDetailedNotImplementedResponse`, `utils.WriteDetailedNotImplementedResponse`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Router File`** (1 nodes): `router.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Middleware Setup File`** (1 nodes): `middleware_setup.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Bucket Operations File`** (1 nodes): `operations.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Single Part Operations File`** (1 nodes): `singlepart.go`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Credential Rotation Restart`** (1 nodes): `Client credential rotation needs two restarts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `AES-GCM FIPS Hot Symbol`** (1 nodes): `crypto/internal/fips140/aes/gcm.gcmAesEnc`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CRC32 Checksum Hot Symbol`** (1 nodes): `hash/crc32.ieeeUpdate`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Tier 4.1 Alloc Profile`** (1 nodes): `Tier 4.1 test-side alloc_objects profile`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Provider Lookup By Alias`** (1 nodes): `Config.GetProviderByAlias`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `HMAC Calculator Reset`** (1 nodes): `HMACCalculator.Reset`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `runProxy()` and `Tier 1.2 blanket 30 s Read/WriteTimeout kills slow transfers`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `testCAPool()` and `TestV8_EncryptionAtRest()`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `testSinglePartCTRWithHMAC()` and `EncStreamingThreshold (5 MiB mirror)`?**
  _Edge tagged AMBIGUOUS (relation: shares_data_with) - confidence is low._
- **What is the exact relationship between `TestStreamingMultipartUpload()` and `Integration test README (streaming multipart walkthrough)`?**
  _Edge tagged AMBIGUOUS (relation: references) - confidence is low._
- **What is the exact relationship between `TestMpuThreePartRoundTrip()` and `Ticket 022: S3 surface fidelity`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `TestRngMalformedRangeHeader()` and `Ticket 013: Storage format v2`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `TestRngMultipleRanges()` and `Ticket 022: S3 surface fidelity`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._