# Segmented GCM Vector

> 10 nodes · cohesion 0.40

## Key Concepts

- **NewCodec()** (11 connections) — `pkg/encryption/dataencryption/segmented_gcm.go`
- **vecCodec()** (8 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **segmented_gcm_vector_test.go** (7 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **vecBytes()** (6 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorWholeObjectReadsBack()** (5 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorObjectIsBoundToItsKey()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorSegmentIsBoundToItsIndex()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorTrailerFieldsAreWhereTheyWere()** (4 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **TestSegVectorAssociatedData()** (3 connections) — `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`
- **Codec** (1 connections)

## Relationships

- [Config Accessors and Dashboard Contract](Config_Accessors_and_Dashboard_Contract.md) (7 shared connections)
- [Segment Encrypt Reader Tests](Segment_Encrypt_Reader_Tests.md) (3 shared connections)
- [Segmented Manager Streaming IO](Segmented_Manager_Streaming_IO.md) (2 shared connections)
- [Segmented GCM](Segmented_GCM.md) (2 shared connections)
- [Cryptofloor](Cryptofloor.md) (1 shared connections)
- [Segment Seal and Open Internals](Segment_Seal_and_Open_Internals.md) (1 shared connections)
- [Segmented GCM Part](Segmented_GCM_Part.md) (1 shared connections)

## Source Files

- `pkg/encryption/dataencryption/segmented_gcm.go`
- `pkg/encryption/dataencryption/segmented_gcm_vector_test.go`

## Audit Trail

- EXTRACTED: 28 (80%)
- INFERRED: 7 (20%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*