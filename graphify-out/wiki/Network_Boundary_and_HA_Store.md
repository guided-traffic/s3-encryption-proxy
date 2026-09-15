# Network Boundary and HA Store

> 34 nodes · cohesion 0.09

## Key Concepts

- **Several Backends Kept In Sync** (34 connections) — `docs/tickets/037-multiple-backends.md`
- **s3-encryption-operator: Proxy Instances Provisioned By Custom Resources** (30 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **ADR 0030 The network boundary belongs to the administrator** (18 connections) — `README.md`
- **Every Reconcile That Rolls A Pod Aborts The Uploads It Holds** (5 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **One Seal Teed To N Backends, Or N Seals** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **The Write Policy: How Many Backends A 200 Requires** (4 connections) — `docs/tickets/037-multiple-backends.md`
- **Does The Operator Mint Credentials Or Only Carry Them** (4 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **The Store Credential And Sentinel Address List Are Plural From The First Release** (3 connections) — `docs/tickets/036-high-availability.md`
- **Entity Tags, Conditional Requests And VersionId Are Backend-Local** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Only A before_response Refusal Can Fall Back** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **A Read Fallback On An Integrity Refusal** (3 connections) — `docs/tickets/037-multiple-backends.md`
- **Configuration Is Read At Start And Only At Start** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **What Deleting A Custom Resource Does To Key Material** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **The Operator Is A Separate Program With Its Own Chart** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **What An Unauthenticated Endpoint Of A Provisioned Instance May Carry** (3 connections) — `docs/tickets/038-s3-encryption-operator.md`
- **Monitoring listener: metrics and /status** (3 connections) — `README.md`
- **The Unauthenticated Monitoring Listener Is Fenced by the Cluster or Not at All** (2 connections) — `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- **The Chart Ships No NetworkPolicy at All** (2 connections) — `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- **The Scrape Names No Licensee and Carries No Countdown** (2 connections) — `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- **A Backend Health Notion For The Write Policy** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **A Fallback Resurrects A Deleted Object** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **A Failed Read Attempt Is A Discarded Transfer** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **A Fan-Out Client Versus A Backend Set The Handlers See** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **The Surface Is 66 Backend Call Sites Across 27 Files** (2 connections) — `docs/tickets/037-multiple-backends.md`
- **The Backend Credential Has No External-Secret Path** (2 connections) — `docs/tickets/038-s3-encryption-operator.md`
- *... and 9 more nodes in this community*

## Relationships

- [Proxy-Owned Part Layout](Proxy-Owned_Part_Layout.md) (17 shared connections)
- [Contributor Guide and KMS Provider ADR](Contributor_Guide_and_KMS_Provider_ADR.md) (12 shared connections)
- [KEK Providers and Key Rotation](KEK_Providers_and_Key_Rotation.md) (8 shared connections)
- [Release 5.0.0 Breaking Changes](Release_5.0.0_Breaking_Changes.md) (6 shared connections)
- [Response Composition Rules](Response_Composition_Rules.md) (4 shared connections)
- [Hostile Backend Threat Model](Hostile_Backend_Threat_Model.md) (3 shared connections)
- [Any-S3-Client Scope and E2E Rules](Any-S3-Client_Scope_and_E2E_Rules.md) (3 shared connections)
- [Forward-or-Refuse and CI Gates](Forward-or-Refuse_and_CI_Gates.md) (3 shared connections)
- [Documentation and Release Process Rules](Documentation_and_Release_Process_Rules.md) (2 shared connections)
- [PUT Routing and Short-Part Budget](PUT_Routing_and_Short-Part_Budget.md) (2 shared connections)
- [SigV4 Authentication Rules](SigV4_Authentication_Rules.md) (1 shared connections)

## Source Files

- `README.md`
- `SECURITY_ARCHITECTURE.md`
- `docs/adr/0030-the-network-boundary-belongs-to-the-administrator.md`
- `docs/tickets/036-high-availability.md`
- `docs/tickets/037-multiple-backends.md`
- `docs/tickets/038-s3-encryption-operator.md`

## Audit Trail

- EXTRACTED: 57 (52%)
- INFERRED: 53 (48%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*