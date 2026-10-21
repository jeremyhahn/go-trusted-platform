# Wire Protocol

> **Status: PLANNED** · Scope: design only, no implementation · Last verified: 2026-10-20

## Protocol Stack

```
┌──────────────────┬───────────────────────────────────────────────┐
│  Application     │  DKG / FROST / Currency / DHT Operations      │
├──────────────────┼───────────────────────────────────────────────┤
│  Messaging       │  Protocol Buffers (protobuf)                  │
├──────────────────┼───────────────────────────────────────────────┤
│  Security        │  TLS 1.3 / Noise Protocol                     │
├──────────────────┼───────────────────────────────────────────────┤
│  Transport       │  QUIC (preferred) / TCP                       │
├──────────────────┼───────────────────────────────────────────────┤
│  Network         │  Kademlia DHT (discovery + routing)           │
├──────────────────┼───────────────────────────────────────────────┤
│  Physical        │  IPv6 (direct) / IPv4 via Gateway             │
└──────────────────┴───────────────────────────────────────────────┘
```

## Message Framing

All messages are length-prefixed:

```
┌─────────────┬──────────────────────────────────────────────┐
│ Length (4B) │              Protobuf Payload                 │
│  Big Endian │                                               │
└─────────────┴──────────────────────────────────────────────┘
```

## Core Message Types

See `pkg/protocol/messages.proto` for complete definitions.

### DKG Messages

| Message | Purpose |
|---------|---------|
| `DKGAttestationRequest` | Request TPM attestation |
| `DKGAttestationResponse` | TPM quote response |
| `DKGKeyExchange` | ECDH key exchange |
| `DKGCommitment` | Polynomial commitments |
| `DKGShare` | Encrypted share |
| `DKGComplaint` | Invalid share complaint |
| `DKGCertificate` | CertEq agreement |
| `DKGResult` | Final DKG output |

### FROST Messages

| Message | Purpose |
|---------|---------|
| `FROSTCommitment` | Pre-generated nonce commitment |
| `FROSTSigningRequest` | Request signatures from signers |
| `FROSTSignatureShare` | Partial signature response |
| `FROSTSignature` | Aggregated final signature |

### Certificate Messages

| Message | Purpose |
|---------|---------|
| `CertificateRequest` | CSR with TPM attestation |
| `Certificate` | Signed certificate |

### AI Arbitration Messages

FINAL DESIGN: Message types for AI-based arbitration system.

#### Message Type Summary

| Message | Purpose | Sender | Receiver |
|---------|---------|--------|----------|
| `AIArbitrationRequest` | Initiate arbitration process | Dispute party | AI arbitrator |
| `AIArbitrationDecision` | AI arbitrator decision | AI arbitrator | Dispute parties |
| `EvidencePacket` | Submit evidence to dispute | Dispute party | System |
| `EvidenceSubmission` | Batch evidence submission | Dispute party | System |
| `AIArbitrationAppeal` | Appeal AI decision | Dispute party | System |
| `HumanEscalation` | Escalate to human review | System | Arbitrator pool |
| `HumanArbiterAssignment` | Assign human arbitrators | System | Arbitrators |
| `HumanArbitrationDecision` | Human arbitrator decision | Human arbitrator | Dispute parties |
| `DecisionExecution` | Execute arbitration decision | System | Escrow/Contract |
| `DecisionAnnouncement` | Broadcast final decision | System | All parties |
| `ModelCertificationRequest` | Request model approval | Model provider | Governance |
| `ModelApprovalStatus` | Governance approval decision | Governance | Model provider |
| `ModelWhitelistUpdate` | Update model whitelist | Governance | All nodes |

```protobuf
// AIArbitrationRequest initiates an arbitration process
message AIArbitrationRequest {
  bytes request_id = 1;                // Unique request identifier (UUID v7)
  bytes dispute_id = 2;                // Dispute requiring arbitration
  bytes contract_id = 3;               // Contract being disputed
  bytes requester_id = 4;              // Party requesting arbitration
  DisputeType dispute_type = 5;        // Type of dispute
  bytes evidence_summary_hash = 6;     // Hash of all submitted evidence
  int64 evidence_count = 7;            // Number of evidence items
  int64 timestamp = 8;                 // Unix timestamp (nanoseconds)
  bytes signature = 9;                 // Ed25519 signature over request
  int64 deadline = 10;                 // Decision deadline (nanoseconds)
  bytes nonce = 11;                    // Freshness nonce (16 bytes)
}

enum DisputeType {
  DISPUTE_TYPE_UNKNOWN = 0;
  DISPUTE_TYPE_SLA_BREACH = 1;         // Service level breach
  DISPUTE_TYPE_PAYMENT = 2;            // Payment disagreement
  DISPUTE_TYPE_DELIVERABLE = 3;        // Deliverable quality dispute
  DISPUTE_TYPE_TERMINATION = 4;        // Contract termination dispute
  DISPUTE_TYPE_SCOPE = 5;              // Scope disagreement
}

// AIArbitrationDecision represents an AI arbitrator's decision
message AIArbitrationDecision {
  bytes decision_id = 1;               // Unique decision identifier (UUID v7)
  bytes dispute_id = 2;                // Dispute being arbitrated
  bytes arbitrator_id = 3;             // AI arbitrator agent ID
  bytes model_hash = 4;                // SHA256 of model weights used
  ArbitrationOutcome outcome = 5;      // Provider wins, consumer wins, or split
  float confidence = 6;                // Decision confidence (0.0-1.0)
  bytes reasoning_hash = 7;            // SHA256 of reasoning JSON
  bytes tpm_quote = 8;                 // REQUIRED: TPM quote proving integrity (validated before decision acceptance)
  int64 timestamp = 9;                 // Unix timestamp (nanoseconds)
  bytes signature = 10;                // Ed25519 signature over decision
  float split_ratio = 11;              // If split outcome, provider ratio (0.0-1.0)
  bool requires_human_review = 12;    // True if confidence < AIConfidenceThreshold (0.75)
  string review_reason = 13;           // Reason for human review requirement
  bytes request_nonce = 14;            // Nonce from original request
  int64 evidence_reviewed = 15;        // Count of evidence items reviewed
  bytes evidence_merkle_root = 16;     // Merkle root of evidence set
}

enum ArbitrationOutcome {
  OUTCOME_UNKNOWN = 0;
  OUTCOME_PROVIDER_WINS = 1;
  OUTCOME_CONSUMER_WINS = 2;
  OUTCOME_SPLIT = 3;
}

// EvidencePacket represents evidence submission with TPM attestation
message EvidencePacket {
  bytes evidence_id = 1;               // SHA256(collector || contract || dispute || content_hash)
  bytes dispute_id = 2;                // Bound to specific dispute
  bytes contract_id = 3;               // Bound to specific contract
  bytes submitter_id = 4;              // Party submitting evidence (IDevID hash)
  EvidenceType type = 5;               // Evidence type (log, metric, document, etc.)
  bytes content_hash = 6;              // SHA256 of content
  bytes content = 7;                   // Actual evidence data (max 10MB)
  int64 timestamp = 8;                 // Unix timestamp (nanoseconds)
  bytes signature = 9;                 // Ed25519 signature over packet
  TPMEvidenceAttestation tpm_attestation = 10;  // Optional TPM attestation
  bool immutable = 11;                 // Once true, evidence cannot be modified
  int64 immutable_at = 12;             // Timestamp when immutability was set
  bytes immutable_proof = 13;          // TPM quote proving immutability timestamp
}

enum EvidenceType {
  EVIDENCE_TYPE_UNKNOWN = 0;
  EVIDENCE_TYPE_SERVICE_LOG = 1;       // Service execution logs
  EVIDENCE_TYPE_SLA_METRIC = 2;        // Measured SLA metrics
  EVIDENCE_TYPE_TRANSACTION = 3;       // Payment/escrow transaction
  EVIDENCE_TYPE_DOCUMENT = 4;          // Supporting document
  EVIDENCE_TYPE_ATTESTATION = 5;       // TPM attestation
  EVIDENCE_TYPE_COMMUNICATION = 6;     // Contract communications
}

// TPMEvidenceAttestation provides hardware-rooted proof
message TPMEvidenceAttestation {
  bytes quote = 1;                     // TPM2_Quote result
  map<int32, bytes> pcr_values = 2;    // PCR values at attestation time
  bytes nonce = 3;                     // Freshness nonce (32 bytes)
  bytes aik_cert_hash = 4;             // Hash of AIK certificate
  bytes aik_signature = 5;             // AIK signature over quote
  int32 pcr_index = 6;                 // PCR where evidence hash was extended
  bytes extended_hash = 7;             // Hash extended to PCR
  int64 attestation_time = 8;          // Unix timestamp (nanoseconds)
  bytes clock_info = 9;                // TPM clock info for ordering
}

// EvidenceSubmission represents submission of evidence to a dispute
message EvidenceSubmission {
  bytes submission_id = 1;             // Unique submission identifier (UUID v7)
  bytes dispute_id = 2;                // Dispute this evidence relates to
  bytes contract_id = 3;               // Contract being disputed
  bytes submitter_id = 4;              // Party submitting evidence
  repeated bytes evidence_ids = 5;     // List of EvidencePacket IDs
  int64 submission_count = 6;          // Number of evidence items
  int64 timestamp = 7;                 // Unix timestamp (nanoseconds)
  bytes signature = 8;                 // Ed25519 signature
  bool final_submission = 9;           // True if no more evidence will be submitted
  bytes nonce = 10;                    // Freshness nonce (16 bytes)
}

// AIArbitrationAppeal represents an appeal to human arbitrators
message AIArbitrationAppeal {
  bytes appeal_id = 1;                 // Unique appeal identifier (UUID v7)
  bytes dispute_id = 2;                // Dispute being appealed
  bytes decision_id = 3;               // AI decision being appealed
  bytes appellant_id = 4;              // Party filing appeal
  AppealReason reason = 5;             // Reason for appeal
  string justification = 6;            // Text justification (max 4KB)
  repeated bytes new_evidence_ids = 7; // New evidence submitted with appeal
  int64 timestamp = 8;                 // Unix timestamp (nanoseconds)
  bytes signature = 9;                 // Ed25519 signature
  bytes nonce = 10;                    // Freshness nonce (16 bytes)
  int64 appeal_deadline = 11;          // Deadline for appeal response
}

enum AppealReason {
  APPEAL_REASON_UNKNOWN = 0;
  APPEAL_REASON_LOW_CONFIDENCE = 1;    // AI confidence < AIConfidenceThreshold (0.75)
  APPEAL_REASON_DISAGREE_OUTCOME = 2;  // Party disagrees with outcome
  APPEAL_REASON_BIAS_ALLEGATION = 3;   // Alleged bias in decision
  APPEAL_REASON_NEW_EVIDENCE = 4;      // New evidence submitted
  APPEAL_REASON_PROCEDURAL_ERROR = 5;  // Process violation
  APPEAL_REASON_MODEL_UNAUTHORIZED = 6; // Model not on whitelist
}

// HumanEscalation represents escalation to human review
message HumanEscalation {
  bytes escalation_id = 1;             // Unique escalation identifier (UUID v7)
  bytes dispute_id = 2;                // Dispute requiring human review
  bytes decision_id = 3;               // AI decision being escalated
  EscalationTrigger trigger = 4;       // Why escalation occurred
  bytes arbitrator_pool_id = 5;        // Human arbitrator pool assignment
  int64 timestamp = 6;                 // Unix timestamp (nanoseconds)
  bytes signature = 7;                 // System signature
  int64 review_deadline = 8;           // Human review deadline
  float ai_confidence = 9;             // Original AI confidence
  bytes evidence_merkle_root = 10;     // Evidence set at escalation
  bytes nonce = 11;                    // Freshness nonce (16 bytes)
}

enum EscalationTrigger {
  ESCALATION_TRIGGER_UNKNOWN = 0;
  ESCALATION_TRIGGER_LOW_CONFIDENCE = 1;     // AI confidence < threshold
  ESCALATION_TRIGGER_APPEAL_FILED = 2;       // Party filed appeal
  ESCALATION_TRIGGER_COMPLEX_DISPUTE = 3;    // Dispute complexity high
  ESCALATION_TRIGGER_HIGH_VALUE = 4;         // Dispute value > threshold
  ESCALATION_TRIGGER_MODEL_FAILURE = 5;      // Model returned error
  ESCALATION_TRIGGER_POLICY_VIOLATION = 6;   // Contract policy requires human
}

// HumanArbiterAssignment assigns human arbitrators to dispute
message HumanArbiterAssignment {
  bytes assignment_id = 1;             // Unique assignment identifier (UUID v7)
  bytes escalation_id = 2;             // Escalation being addressed
  bytes dispute_id = 3;                // Dispute being arbitrated
  repeated bytes arbiter_ids = 4;      // Assigned human arbitrators (IDevIDs)
  int64 panel_size = 5;                // Number of arbitrators (1, 3, or 5)
  int64 timestamp = 6;                 // Unix timestamp (nanoseconds)
  bytes signature = 7;                 // System signature
  int64 decision_deadline = 8;         // Deadline for human decision
  bytes nonce = 9;                     // Freshness nonce (16 bytes)
}

// HumanArbitrationDecision represents human arbitrator decision
message HumanArbitrationDecision {
  bytes decision_id = 1;               // Unique decision identifier (UUID v7)
  bytes escalation_id = 2;             // Escalation this addresses
  bytes dispute_id = 3;                // Dispute being arbitrated
  bytes arbiter_id = 4;                // Human arbitrator ID
  ArbitrationOutcome outcome = 5;      // Decision outcome
  string reasoning = 6;                // Human reasoning (max 16KB)
  bytes reasoning_hash = 7;            // SHA256 of reasoning
  int64 timestamp = 8;                 // Unix timestamp (nanoseconds)
  bytes signature = 9;                 // Arbiter's Ed25519 signature
  float split_ratio = 10;              // If split outcome, provider ratio
  bool is_final = 11;                  // True if no further appeals allowed
  bytes tpm_quote = 12;                // REQUIRED for high-value disputes (>100,000 units), recommended for all
  bytes nonce = 13;                    // Freshness nonce (16 bytes)
}

// DecisionExecution represents execution of arbitration decision
message DecisionExecution {
  bytes execution_id = 1;              // Unique execution identifier (UUID v7)
  bytes decision_id = 2;               // Decision being executed
  bytes dispute_id = 3;                // Dispute being resolved
  ExecutionAction action = 4;          // Action being taken
  bytes escrow_transaction_id = 5;     // Escrow release transaction
  int64 amount_provider = 6;           // Amount to provider (microunits)
  int64 amount_consumer = 7;           // Amount to consumer (microunits)
  int64 timestamp = 8;                 // Unix timestamp (nanoseconds)
  bytes signature = 9;                 // System signature
  ExecutionStatus status = 10;         // Execution status
  string error_message = 11;           // Error if execution failed
  bytes nonce = 12;                    // Freshness nonce (16 bytes)
}

enum ExecutionAction {
  EXECUTION_ACTION_UNKNOWN = 0;
  EXECUTION_ACTION_RELEASE_PROVIDER = 1;      // Release escrow to provider
  EXECUTION_ACTION_REFUND_CONSUMER = 2;       // Refund escrow to consumer
  EXECUTION_ACTION_SPLIT_ESCROW = 3;          // Split escrow per ratio
  EXECUTION_ACTION_TERMINATE_CONTRACT = 4;    // Terminate contract
  EXECUTION_ACTION_CONTINUE_CONTRACT = 5;     // Continue contract
}

enum ExecutionStatus {
  EXECUTION_STATUS_UNKNOWN = 0;
  EXECUTION_STATUS_PENDING = 1;        // Awaiting execution
  EXECUTION_STATUS_IN_PROGRESS = 2;    // Currently executing
  EXECUTION_STATUS_COMPLETED = 3;      // Successfully completed
  EXECUTION_STATUS_FAILED = 4;         // Execution failed
  EXECUTION_STATUS_REVERSED = 5;       // Execution was reversed
}

// ModelCertificationRequest requests approval for AI model
message ModelCertificationRequest {
  bytes request_id = 1;                // Unique request identifier (UUID v7)
  bytes model_hash = 2;                // SHA256 of model weights
  ModelType model_type = 3;            // Model family (Claude, GPT, etc.)
  string model_version = 4;            // Specific version string
  string model_name = 5;               // Human-readable name
  bytes provider_id = 6;               // Model provider IDevID
  bytes certification_data = 7;        // Certification test results
  bytes benchmark_results = 8;         // Performance benchmark data
  bytes bias_audit_hash = 9;           // Hash of bias audit report
  int64 timestamp = 10;                // Unix timestamp (nanoseconds)
  bytes signature = 11;                // Provider signature
  float max_confidence_requested = 12; // Requested max confidence
  bytes nonce = 13;                    // Freshness nonce (16 bytes)
}

// ModelApprovalStatus represents governance decision on model
message ModelApprovalStatus {
  bytes approval_id = 1;               // Unique approval identifier (UUID v7)
  bytes request_id = 2;                // Request being responded to
  bytes model_hash = 3;                // SHA256 of model weights
  ApprovalAction action = 4;           // APPROVE, REJECT, CONDITIONAL
  bytes governance_proof = 5;          // Proof of governance vote
  int64 effective_epoch = 6;           // When approval takes effect
  int64 valid_from = 7;                // Validity period start
  int64 valid_until = 8;               // Validity period end
  float max_confidence = 9;            // Maximum allowed confidence score
  repeated string conditions = 10;     // Approval conditions
  int64 timestamp = 11;                // Unix timestamp (nanoseconds)
  bytes signature = 12;                // Governance signature
  string rejection_reason = 13;        // Reason if rejected
  bytes nonce = 14;                    // Freshness nonce (16 bytes)
}

enum ApprovalAction {
  APPROVAL_ACTION_UNKNOWN = 0;
  APPROVAL_ACTION_APPROVE = 1;         // Approve for use
  APPROVAL_ACTION_REJECT = 2;          // Reject certification
  APPROVAL_ACTION_CONDITIONAL = 3;     // Approve with conditions
  APPROVAL_ACTION_SUSPEND = 4;         // Temporarily suspend
}

// ModelWhitelistUpdate represents model approval/revocation
message ModelWhitelistUpdate {
  bytes update_id = 1;                 // Unique update identifier (UUID v7)
  bytes model_hash = 2;                // SHA256 of model weights
  ModelAction action = 3;              // ADD, REMOVE, UPDATE, REVOKE
  ModelType model_type = 4;            // Model family (Claude, GPT, etc.)
  string model_version = 5;            // Specific version string
  bytes governance_proof = 6;          // Proof of governance approval
  int64 effective_epoch = 7;           // When update takes effect
  int64 valid_from = 8;                // Validity period start
  int64 valid_until = 9;               // Validity period end
  float max_confidence = 10;           // Maximum allowed confidence score
  bytes signature = 11;                // CA operator signature
  int64 timestamp = 12;                // Unix timestamp (nanoseconds)
  string revocation_reason = 13;       // Reason if revoked
  bytes nonce = 14;                    // Freshness nonce (16 bytes)
}

enum ModelAction {
  MODEL_ACTION_UNKNOWN = 0;
  MODEL_ACTION_ADD = 1;                // Add to whitelist
  MODEL_ACTION_REMOVE = 2;             // Remove from whitelist
  MODEL_ACTION_UPDATE = 3;             // Update existing entry
  MODEL_ACTION_REVOKE = 4;             // Immediately revoke
}

enum ModelType {
  MODEL_TYPE_UNKNOWN = 0;
  MODEL_TYPE_CLAUDE = 1;
  MODEL_TYPE_GPT = 2;
  MODEL_TYPE_GEMINI = 3;
  MODEL_TYPE_LLAMA = 4;
  MODEL_TYPE_MISTRAL = 5;
  MODEL_TYPE_CUSTOM = 255;
}

// DecisionAnnouncement broadcasts final arbitration decision
message DecisionAnnouncement {
  bytes announcement_id = 1;           // Unique announcement identifier (UUID v7)
  bytes decision_id = 2;               // Decision being announced
  bytes dispute_id = 3;                // Dispute resolved
  ArbitrationOutcome outcome = 4;      // Final outcome
  DecisionType decision_type = 5;      // AI or Human decision
  int64 timestamp = 6;                 // Unix timestamp (nanoseconds)
  bytes merkle_proof = 7;              // Merkle proof for audit log
  bytes signature = 8;                 // System signature
  bool appealable = 9;                 // True if appeal period active
  int64 appeal_deadline = 10;          // Deadline to file appeal
  bytes nonce = 11;                    // Freshness nonce (16 bytes)
}

enum DecisionType {
  DECISION_TYPE_UNKNOWN = 0;
  DECISION_TYPE_AI = 1;                // AI arbitrator decision
  DECISION_TYPE_HUMAN = 2;             // Human arbitrator decision
  DECISION_TYPE_PANEL = 3;             // Multi-arbitrator panel
  DECISION_TYPE_DEFAULT = 4;           // Default judgment (timeout)
}
```

## DHT Topics

```
/trustedDHT/
├── dkg/{session_id}/
│   ├── attestations/
│   ├── keyexchange/
│   ├── commitments/
│   ├── shares/{recipient_id}/
│   ├── complaints/
│   └── certificates/
│
├── frost/{pool_id}/
│   ├── epoch/{epoch}/pk
│   └── commitments/{signer_id}/
│
├── signing/{request_id}/
│   ├── request
│   └── shares/{signer_id}/
│
├── certificates/{node_id}/
│
├── currency/
│   ├── balances/{wallet_id}/
│   ├── transactions/{tx_id}/
│   └── tips/
│
├── ct_log/{epoch}/{index}/
│
└── ai-arbitration/                      [FINAL DESIGN]
    ├── disputes/{dispute_id}/
    │   ├── evidence/                     Evidence submissions
    │   └── decisions/                    Arbitration decisions
    ├── appeals/{appeal_id}/              Appeal records
    ├── processes/{process_id}/           Arbitration process tracking
    ├── model-whitelist/
    │   ├── approved/                     Current approved models
    │   └── updates/                      Model list updates
    └── audit/                            Audit logs
```

## Transport Options

### Direct P2P

Preferred for low latency:

```go
func (t *Transport) SendDirect(peer NodeID, msg proto.Message) error {
    conn := t.getConnection(peer)
    if conn == nil {
        return ErrNoDirectConnection
    }

    data, _ := proto.Marshal(msg)
    frame := lengthPrefix(data)

    return conn.Write(frame)
}
```

### DHT Relay

Fallback when direct connection unavailable:

```go
func (t *Transport) SendViaRelay(peer NodeID, msg proto.Message) error {
    topic := fmt.Sprintf("/messages/%s", peer)
    data, _ := proto.Marshal(msg)

    return t.dht.Publish(topic, data)
}
```

### Broadcast (PubSub)

For DKG commitments and announcements:

```go
func (t *Transport) Broadcast(topic string, msg proto.Message) error {
    data, _ := proto.Marshal(msg)
    return t.pubsub.Publish(topic, data)
}
```

## Rate Limiting

Rate limits are enforced per transport to prevent abuse and ensure fair resource allocation.

### Direct P2P

| Limit Type | Value |
|------------|-------|
| Messages per peer | 100/second |
| Total messages | 1000/second |

### Gateway HTTP

| Client Type | Limit |
|-------------|-------|
| Unauthenticated | 60 requests/minute |
| Authenticated | 600 requests/minute |
| Per gateway total | 6000 requests/minute |

### gRPC

| Limit Type | Value |
|------------|-------|
| Calls per connection | 100/second |
| Concurrent streams | 10 |

### QUIC

| Limit Type | Value |
|------------|-------|
| Messages | 200/second |
| Concurrent streams | 50 |

### WebSocket

| Limit Type | Value |
|------------|-------|
| Messages | 60/minute |
| Connections per IP | 10 |

### AI Arbitration Operations (FINAL DESIGN)

| Operation | Rate Limit | Per Party |
|-----------|------------|-----------|
| Evidence submission | 10/hour | Per dispute party |
| Arbitration request | 3/day | Per party |
| Arbitration decisions | 1/dispute | Per arbitrator |
| Appeal filing | 1/dispute | Per party |
| Human escalation | 1/dispute | System controlled |
| Decision execution | 1/decision | System controlled |
| Model certification requests | 10/month | Per provider |
| Model whitelist updates | 1/day | Governance controlled |

## Security

### Encryption Requirements

TLS 1.3 is required for all transports. The following cryptographic parameters are enforced:

#### Cipher Suites (in preference order)

| Cipher Suite | Status |
|--------------|--------|
| `TLS_AES_256_GCM_SHA384` | Preferred |
| `TLS_CHACHA20_POLY1305_SHA256` | Allowed |
| `TLS_AES_128_GCM_SHA256` | Allowed |

#### Cryptographic Algorithms

| Purpose | Algorithm | Status |
|---------|-----------|--------|
| Signatures | Ed25519 | Preferred |
| Key Exchange | X25519 | Preferred |

#### Forbidden Configurations

The following are explicitly forbidden and rejected during connection establishment:

- TLS 1.2 and below
- CBC mode ciphers
- RSA key exchange
- MD5 hash algorithm
- SHA-1 hash algorithm

### P2P Authentication

All peer-to-peer connections require mutual TLS 1.3 authentication with hardware-backed identity verification:

1. **TLS Handshake**: Both peers initiate TLS 1.3 with mutual authentication enabled
2. **Certificate Exchange**: Each peer presents its IDevID certificate (IEEE 802.1AR compliant)
3. **Certificate Chain Validation**: Full chain validation against trusted platform CA
4. **TPM Quote Exchange**: Post-handshake, peers exchange TPM quotes using a fresh random nonce
5. **Platform State Verification**: Quote validation confirms expected PCR values and firmware state

```
┌─────────┐                           ┌─────────┐
│ Peer A  │                           │ Peer B  │
└────┬────┘                           └────┬────┘
     │                                     │
     │──── TLS 1.3 ClientHello ───────────>│
     │<─── TLS 1.3 ServerHello ────────────│
     │                                     │
     │──── IDevID Certificate ────────────>│
     │<─── IDevID Certificate ─────────────│
     │                                     │
     │──── [Handshake Complete] ──────────>│
     │                                     │
     │──── TPM Quote Request (nonce) ─────>│
     │<─── TPM Quote Response ─────────────│
     │                                     │
     │<─── TPM Quote Request (nonce) ──────│
     │──── TPM Quote Response ────────────>│
     │                                     │
     │     [Connection Authenticated]      │
     │                                     │
```

### Replay Attack Prevention

All messages include replay protection fields to prevent message replay and ensure freshness.

#### Required Message Fields

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | UUID v7 | Unique identifier with embedded timestamp |
| `timestamp` | int64 | Unix timestamp in nanoseconds |
| `session_id` | bytes | Session binding identifier |
| `nonce` | bytes(16) | 16 bytes of cryptographically random data |

#### Validation Rules

| Check | Requirement |
|-------|-------------|
| Timestamp validity | Within +/- 30 seconds of receiver's clock |
| Request ID uniqueness | Not seen within previous 5 minutes |
| Deduplication | Bloom filter with 5-minute TTL |

Messages failing any validation check are rejected immediately. The bloom filter provides efficient O(1) deduplication while the 5-minute window ensures memory-bounded operation.

### Security Summary

| Protection | Implementation |
|------------|----------------|
| **Encryption** | TLS 1.3 with approved cipher suites |
| **Authentication** | Mutual TLS with IDevID certificates and TPM quotes |
| **Replay Prevention** | UUID v7 request IDs, nanosecond timestamps, bloom filter dedup |
| **Integrity** | Protobuf with cryptographic signatures |

### AI Arbitrator TPM Attestation Requirements

TPM attestation is **REQUIRED** for all AI arbitration decisions. AI arbitrators MUST run on trusted nodes with valid TPM quotes to ensure decision integrity and prevent tampering.

#### Mandatory Requirements

| Requirement | Description |
|-------------|-------------|
| Trusted node | AI arbitrator MUST execute on a node with valid IDevID certificate |
| TPM quote | Every `AIArbitrationDecision` MUST include a valid `tpm_quote` field |
| Attestation timing | TPM quote MUST be generated at decision time, not cached |
| Quote validation | Receiving nodes MUST validate TPM quote before accepting decision |

#### Attestation Validation Process

Before accepting any AI arbitration decision, the receiving node MUST:

1. **Verify TPM quote signature** against the arbitrator's AIK certificate
2. **Validate PCR values** match expected trusted platform state
3. **Check quote freshness** using the `request_nonce` from original request
4. **Confirm model hash** in decision matches a whitelisted model
5. **Verify timestamp** is within acceptable skew (30 seconds)

```
┌─────────────────┐                         ┌─────────────────┐
│  AI Arbitrator  │                         │  Receiving Node │
└────────┬────────┘                         └────────┬────────┘
         │                                           │
         │  1. Generate decision                     │
         │  2. Extend decision hash to PCR[16]       │
         │  3. Generate TPM2_Quote(nonce, PCR[16])   │
         │  4. Sign decision with IDevID key         │
         │                                           │
         │──── AIArbitrationDecision ───────────────>│
         │     (includes tpm_quote)                  │
         │                                           │
         │                      5. Validate AIK cert chain
         │                      6. Verify TPM quote signature
         │                      7. Check PCR[16] contains decision hash
         │                      8. Validate nonce freshness
         │                      9. Confirm model on whitelist
         │                                           │
         │<─── Decision Accepted/Rejected ───────────│
         │                                           │
```

#### Rejection Conditions

Decisions are rejected if any attestation check fails:

| Check | Error Code | Action |
|-------|------------|--------|
| Missing TPM quote | `ERR_TPM_QUOTE_REQUIRED` | Reject, escalate to human review |
| Invalid quote signature | `ERR_TPM_SIGNATURE_INVALID` | Reject, flag arbitrator for audit |
| PCR mismatch | `ERR_TPM_PCR_MISMATCH` | Reject, quarantine arbitrator |
| Stale nonce | `ERR_NONCE_EXPIRED` | Reject, request fresh decision |
| Unlisted model | `ERR_MODEL_NOT_WHITELISTED` | Reject, escalate to human review |

## Timeouts

| Operation | Timeout |
|-----------|---------|
| Direct message | 5 sec |
| DHT relay | 10 sec |
| Broadcast | 30 sec |
| DKG phase | 60 sec |
| Signing request | 5 sec |
| AI arbitration request | 30 sec |
| AI arbitration decision | 300 sec (5 min) |
| Evidence submission | 10 sec |
| Appeal filing | 15 sec |
| Human escalation | 30 sec |
| Decision execution | 60 sec |
| Model certification request | 120 sec |

## AI Arbitration Protocol Specifications

### Message Ordering Guarantees

The AI arbitration system provides specific ordering and delivery guarantees for lifecycle messages.

#### Delivery Semantics

| Message Type | Delivery Guarantee | Retry Policy |
|--------------|-------------------|--------------|
| AIArbitrationRequest | At-most-once | Non-idempotent: 3 retries max, then manual intervention |
| EvidenceSubmission | At-most-once | Non-idempotent: 3 retries max, then manual intervention |
| AIArbitrationDecision | Exactly-once | Idempotent: 5 retries with exponential backoff |
| AIArbitrationAppeal | At-most-once | Non-idempotent: 3 retries max, then manual intervention |
| HumanEscalation | Exactly-once | Idempotent: 5 retries with exponential backoff |
| DecisionExecution | Exactly-once | Idempotent: 5 retries with exponential backoff |
| DecisionAnnouncement | Best-effort broadcast | Idempotent: 5 retries with exponential backoff |
| ModelCertificationRequest | At-most-once | Non-idempotent: 3 retries max, then manual intervention |
| ModelWhitelistUpdate | Exactly-once | Idempotent: 5 retries with exponential backoff |

#### Retry Policy

All message retries follow a standardized policy based on operation idempotency:

**Idempotent Operations** (safe to retry):
- Maximum retries: 5
- Backoff strategy: Exponential with jitter
- Intervals: 1s, 2s, 4s, 8s, 16s (total max wait: 31 seconds)
- On exhaustion: Alert operator, continue operation in degraded mode

**Non-Idempotent Operations** (may cause side effects):
- Maximum retries: 3
- Backoff strategy: Linear with jitter
- Intervals: 1s, 2s, 3s (total max wait: 6 seconds)
- On exhaustion: Require manual intervention, log for audit

**Alert and Circuit Breaker Thresholds**:
- Alert threshold: Generate alert after 3 consecutive failures for any operation
- Circuit breaker: Stop all retries after 10 failures within 1 minute window
- Circuit recovery: Attempt single probe after 30 seconds, resume if successful

#### Sequencing Requirements

Messages within an arbitration lifecycle MUST be processed in the following order:

```
1. AIArbitrationRequest (initiates dispute)
   ↓
2. EvidenceSubmission (0 to N submissions, order independent)
   ↓
3. AIArbitrationDecision (one decision per arbitrator)
   ↓
4. [OPTIONAL] AIArbitrationAppeal (if party disagrees)
   ↓
5. [OPTIONAL] HumanEscalation (if appeal filed or low confidence)
   ↓
6. [OPTIONAL] HumanArbiterAssignment (assigns human arbitrators)
   ↓
7. [OPTIONAL] HumanArbitrationDecision (human decision)
   ↓
8. DecisionExecution (executes final decision)
   ↓
9. DecisionAnnouncement (broadcasts outcome)
```

**Ordering Violations**: Messages received out of sequence are rejected with error code `ERR_INVALID_SEQUENCE`.

**Duplicate Detection**: All messages include a `nonce` field and UUID v7 identifier. Duplicates detected within the deduplication window are silently dropped.

#### Message Deduplication

Message deduplication ensures exactly-once semantics for critical operations, including persistence across node reboots.

**Deduplication Windows**:
| Message Category | Window Duration | Persistence |
|------------------|-----------------|-------------|
| Ephemeral messages (announcements, broadcasts) | 1 hour | In-memory only |
| Critical messages (decisions, executions, whitelist updates) | 24 hours | Durable storage |

**Persistence Requirements**:
- Message IDs MUST be persisted to durable storage for critical message types
- On node startup, load the last N message IDs from storage (configurable, default: 10,000)
- Storage format: LevelDB or equivalent key-value store with message_id as key, timestamp as value
- Expired entries pruned on startup and periodically (every 15 minutes)

**Sequence Number Ordering**:
- Each dispute maintains a monotonically increasing sequence number
- Messages include `sequence_number` derived from UUID v7 timestamp component
- Out-of-order messages held in buffer for up to 30 seconds awaiting predecessors
- Messages arriving more than 30 seconds late are rejected with `ERR_SEQUENCE_EXPIRED`

**Reboot Recovery Protocol**:
1. Load persisted message ID set from durable storage
2. Request missed messages from peers using last known sequence number
3. Validate recovered messages against loaded dedup set
4. Resume normal operation after recovery window (configurable, default: 60 seconds)

**Timeout Handling**: If a required message is not received within the specified timeout:

- **AIArbitrationDecision timeout**: Escalate to human review automatically
- **HumanArbitrationDecision timeout**: Assign new arbitrator panel
- **DecisionExecution timeout**: Apply standard retry policy (5 retries with exponential backoff), then alert governance

### Evidence Submission Protocol

#### Submission Requirements

| Parameter | Value | Enforcement |
|-----------|-------|-------------|
| Maximum evidence size | 10 MB | Hard limit, rejected if exceeded |
| Maximum submissions per hour | 10 | Per party, per dispute |
| Maximum total evidence per dispute | 100 items | System-wide limit |
| Evidence retention period | 7 years | Cryptographic proof required |
| Immutability deadline | 24 hours | Evidence locked after deadline |

#### Rate Limiting

Evidence submission is rate-limited to prevent DoS attacks:

```
Per-party limit:     10 submissions/hour
Per-dispute limit:   100 total submissions
Burst allowance:     5 immediate submissions
```

Violations result in:
- First violation: Warning logged
- Second violation: 1-hour cooldown
- Third violation: Party flagged for governance review

#### Evidence Format Validation

All evidence submissions MUST pass validation:

| Check | Requirement | Error Code |
|-------|-------------|------------|
| Content hash matches | SHA256(content) == content_hash | `ERR_HASH_MISMATCH` |
| Signature verification | Valid Ed25519 signature | `ERR_INVALID_SIGNATURE` |
| Dispute binding | dispute_id matches active dispute | `ERR_INVALID_DISPUTE` |
| Contract binding | contract_id matches dispute contract | `ERR_INVALID_CONTRACT` |
| Size limit | content.size <= 10 MB | `ERR_SIZE_EXCEEDED` |
| Type validation | EvidenceType in allowed set | `ERR_INVALID_TYPE` |
| Immutability check | If immutable, reject modifications | `ERR_IMMUTABLE` |

#### TPM Attestation Requirements

Evidence with TPM attestation receives higher trust weight:

```protobuf
TPMEvidenceAttestation {
  quote:          TPM2_Quote over evidence_hash
  pcr_values:     PCR state at attestation time
  nonce:          Fresh 32-byte random nonce
  aik_signature:  AIK signature proving TPM authenticity
  pcr_index:      PCR where evidence_hash extended (typically PCR[16])
  extended_hash:  SHA256(previous_pcr || evidence_hash)
  clock_info:     TPM clock for ordering
}
```

**TPM Evidence Weight**: Evidence with valid TPM attestation carries 2x weight in AI arbitration analysis.

#### Evidence Retention Protocol

All evidence is retained with cryptographic proof:

1. **Submission**: Evidence stored with Merkle tree insertion
2. **Commitment**: Merkle root published to DHT every 1 hour
3. **Proof Generation**: Merkle proof generated for each evidence item
4. **Immutability**: After 24 hours or `final_submission` flag, evidence becomes immutable
5. **Retention**: Evidence retained for 7 years minimum
6. **Deletion**: Evidence can only be deleted after retention period with governance approval

#### Evidence Retention Enforcement

The platform enforces evidence retention through a multi-layered storage and verification system.

##### Storage Requirements

| Component | Specification | Purpose |
|-----------|---------------|---------|
| DHT replication factor | 7 nodes minimum | Fault tolerance and availability |
| Archival nodes | 3 designated archive nodes per region | Long-term preservation |
| Storage encryption | AES-256-GCM with hardware-backed keys | Data protection at rest |
| Geographic distribution | Evidence replicated across 3+ geographic regions | Disaster recovery |
| Storage verification | SHA-256 integrity check on read/write | Data integrity assurance |

##### Automatic Rotation and Archival Schedule

| Phase | Timing | Action |
|-------|--------|--------|
| Hot storage | 0-90 days | Full DHT replication (7 nodes), immediate access |
| Warm storage | 91 days - 2 years | Reduced DHT replication (5 nodes), archive copy created |
| Cold storage | 2-7 years | Archive nodes only (3 nodes), on-demand retrieval |
| Expiration review | 7 years + 30 days | Governance review before deletion |
| Deletion | Post-approval | Secure erasure with audit trail |

##### Periodic Verification Audits

Evidence existence is verified through automated audits:

| Audit Type | Frequency | Scope |
|------------|-----------|-------|
| Existence check | Every 24 hours | Verify evidence exists on required nodes |
| Integrity audit | Weekly | SHA-256 hash verification against stored hash |
| Replication audit | Monthly | Verify minimum replication factor maintained |
| Archive sync | Quarterly | Full reconciliation between DHT and archive nodes |
| Compliance audit | Annually | Third-party verification of retention compliance |

**Audit Process**:
1. Select random sample of evidence items (10% minimum)
2. Request evidence from all replica nodes
3. Verify content hash matches stored `content_hash`
4. Verify Merkle proof against published root
5. Log audit results to immutable audit trail

##### Node Retention Penalties

Nodes failing to maintain evidence face graduated penalties:

| Violation | First Offense | Second Offense | Third Offense |
|-----------|---------------|----------------|---------------|
| Missing evidence | Warning + 72h remediation window | 30-day reputation penalty (-0.5) | Node suspension from evidence storage pool |
| Integrity failure | Immediate quarantine + investigation | 90-day suspension + governance review | Permanent ban from storage pool |
| Replication failure | 48h remediation window | 14-day reputation penalty (-0.3) | Removal from storage pool (180 days) |
| Audit non-response | 24h grace period | 7-day reputation penalty (-0.2) | Escalation to governance |

**Remediation Requirements**:
- Node must restore evidence from peer replicas within remediation window
- Proof of restoration submitted via signed attestation
- Repeated violations trigger mandatory security audit

#### Evidence Types and Retention Periods

Different evidence types have specific retention requirements based on legal and operational needs.

| Evidence Type | Retention Period | Justification |
|---------------|------------------|---------------|
| AI arbitration decisions | 7 years | Legal compliance, audit trail, precedent reference |
| Transaction records | 7 years | Financial regulations, dispute resolution |
| Dispute evidence | 7 years | Legal proceedings, appeals, compliance |
| Contract artifacts | 7 years + contract term | Contractual obligations, historical reference |
| Human arbitration decisions | 7 years | Legal compliance, accountability |
| Model certification records | 7 years | Governance accountability, model lineage |
| Ephemeral messages | 30 days | Operational debugging, short-term diagnostics |
| Debug logs | 90 days | System troubleshooting, performance analysis |
| Session metadata | 180 days | Security forensics, access auditing |
| TPM attestation records | 7 years | Hardware integrity verification, security audit |

**Retention Override Conditions**:
- Active litigation: Retention extended until case closure + 1 year
- Regulatory hold: Retention extended per regulatory directive
- Governance directive: Custom retention as specified

#### Audit Trail and Temporal Proofs

The platform provides cryptographic proof that evidence existed at specific points in time.

##### Merkle Proofs for Historical Evidence

Each evidence item can generate a verifiable existence proof:

```
EvidenceProof {
  evidence_id:        SHA256 identifier of evidence
  evidence_hash:      SHA256 of content
  merkle_root:        Root hash at proof time
  merkle_path:        Path from leaf to root (sibling hashes)
  proof_timestamp:    Unix timestamp (nanoseconds)
  epoch_number:       Epoch when root was published
  dag_reference:      DAG node containing epoch commitment
  signature:          System signature over proof
}
```

**Proof Verification Process**:
1. Retrieve `merkle_path` for evidence item
2. Compute root hash by hashing evidence with path siblings
3. Compare computed root with published `merkle_root` at `epoch_number`
4. Verify `dag_reference` contains matching root commitment
5. Validate system `signature` over proof structure

##### Cross-Reference with DAG for Timestamping

Evidence timestamps are anchored to the platform's DAG (Directed Acyclic Graph) for immutable ordering:

| Component | Purpose | Verification Method |
|-----------|---------|---------------------|
| Evidence Merkle root | Commits evidence set state | Published to DHT hourly |
| DAG epoch node | Anchors Merkle root to DAG | Contains signed root hash |
| DAG chain proof | Links epoch to genesis | Traversable hash chain |
| External anchor (optional) | Bitcoin/Ethereum timestamp | Cross-chain verification |

**Timestamping Flow**:
```
T+0:      Evidence submitted
T+1h:     Merkle root computed for epoch
T+1h+1m:  Root published to DAG as epoch commitment
T+1h+5m:  DAG node propagated to all nodes
T+24h:    (Optional) External blockchain anchor for high-value disputes
```

##### Historical Evidence Queries

Supported query types for temporal verification:

| Query | Description | Response |
|-------|-------------|----------|
| `ProveExistence(evidence_id, timestamp)` | Prove evidence existed at time | EvidenceProof |
| `GetHistoricalRoot(epoch)` | Retrieve Merkle root for epoch | Root hash + DAG reference |
| `VerifyChain(evidence_id, epoch_start, epoch_end)` | Verify continuous existence | Proof chain |
| `GetAuditLog(evidence_id)` | Full audit history | Timestamped event log |

#### Evidence Retrieval Process

Historical evidence retrieval follows a structured authorization and delivery process.

##### Authorization Requirements

| Requester Type | Evidence Access | Authorization Method |
|----------------|-----------------|----------------------|
| Dispute party | Own dispute evidence | IDevID signature verification |
| AI arbitrator | Assigned dispute evidence | Assignment proof + TPM attestation |
| Human arbitrator | Assigned dispute evidence | Assignment proof + IDevID signature |
| Governance auditor | All evidence (read-only) | Multi-signature governance authorization |
| Regulatory authority | Specified evidence | Legal order + governance approval |
| System audit | Integrity verification only | Automated, no content access |

**Authorization Request Format**:
```protobuf
EvidenceRetrievalRequest {
  request_id:       UUID v7 (unique identifier)
  evidence_ids:     List of requested evidence IDs
  requester_id:     IDevID of requesting party
  authorization:    Authorization proof (assignment, signature, legal order)
  purpose:          Retrieval purpose (audit, review, legal, archive)
  timestamp:        Unix timestamp (nanoseconds)
  signature:        Ed25519 signature over request
  nonce:            Freshness nonce (16 bytes)
}
```

##### Response Time SLAs

| Storage Tier | Target Response Time | Maximum Response Time | Escalation |
|--------------|---------------------|----------------------|------------|
| Hot storage (0-90 days) | 100ms | 1 second | Alert if exceeded |
| Warm storage (91 days - 2 years) | 5 seconds | 30 seconds | Warning logged |
| Cold storage (2-7 years) | 5 minutes | 1 hour | Async delivery acceptable |
| Archive retrieval | 1 hour | 24 hours | Governance notification if delayed |

**SLA Enforcement**:
- Response times measured from request receipt to first byte delivered
- Nodes failing SLAs repeatedly trigger storage pool reassignment
- Monthly SLA compliance reports published to governance

##### Retrieval Response Format

```protobuf
EvidenceRetrievalResponse {
  response_id:      UUID v7 (unique identifier)
  request_id:       References original request
  evidence_items:   List of EvidencePacket (content included)
  merkle_proofs:    Existence proofs for each item
  retrieval_time:   Unix timestamp (nanoseconds)
  storage_tier:     Hot, Warm, or Cold
  signature:        System signature over response
  partial:          True if response is paginated
  next_cursor:      Pagination cursor (if partial)
}
```

##### Retrieval Failure Handling

| Failure Type | Response | Recovery Action |
|--------------|----------|-----------------|
| Evidence not found | `ERR_EVIDENCE_NOT_FOUND` | Check archive nodes, trigger replication recovery |
| Authorization denied | `ERR_UNAUTHORIZED` | Log attempt, notify governance if repeated |
| Storage node unavailable | `ERR_STORAGE_UNAVAILABLE` | Failover to replica nodes |
| Integrity check failed | `ERR_INTEGRITY_FAILURE` | Quarantine node, recover from replicas |
| SLA timeout | `ERR_TIMEOUT` | Async delivery notification, escalate if critical |

### Decision Publishing Protocol

#### Decision Announcement Format

Final arbitration decisions are announced via `DecisionAnnouncement` message:

```protobuf
DecisionAnnouncement {
  announcement_id:   UUID v7 (unique identifier)
  decision_id:       References final decision
  dispute_id:        Dispute resolved
  outcome:           ArbitrationOutcome (Provider/Consumer/Split)
  decision_type:     AI, Human, or Panel
  timestamp:         Unix nanoseconds
  merkle_proof:      Audit log Merkle proof
  signature:         Ed25519 system signature
  appealable:        True if appeal period active
  appeal_deadline:   Timestamp (if appealable)
}
```

#### Signature Requirements

All decisions MUST be cryptographically signed:

| Decision Type | Signature Requirement |
|---------------|----------------------|
| AI Decision | Ed25519 signature from arbitrator agent's IDevID key |
| Human Decision | Ed25519 signature from human arbitrator's IDevID key |
| Panel Decision | Multi-signature (threshold 2-of-3 or 3-of-5) |
| System Decision | Ed25519 signature from platform CA key |

**Signature Validation**: Signatures are validated against:
1. IDevID certificate chain to trusted CA
2. TPM quote proving key custody
3. Timestamp within valid certificate period
4. Nonce freshness (within 30 seconds)

#### Distribution Mechanism

Decisions are distributed via multiple channels for reliability:

| Channel | Delivery Method | Guarantee |
|---------|----------------|-----------|
| Primary | DHT publish to `/ai-arbitration/disputes/{dispute_id}/decisions/` | Best-effort |
| Fallback | Direct P2P to dispute parties | Confirmed delivery |
| Audit | Certificate Transparency log entry | Permanent record |
| Archive | Merkle tree commitment to blockchain | Immutable proof |

**Distribution Timeline**:
```
T+0s:    Decision signed
T+1s:    Published to DHT
T+2s:    Direct notification to parties
T+5s:    CT log submission
T+60s:   Merkle root commitment
T+3600s: Appeal deadline (if appealable)
```

### Human Review Escalation Protocol

#### Escalation Triggers

Human escalation occurs automatically when:

| Trigger | Threshold | Action |
|---------|-----------|--------|
| Low confidence | AI confidence < AIConfidenceThreshold (0.75) | Immediate escalation |
| Appeal filed | Party files AIArbitrationAppeal | Escalation within 1 hour |
| Complex dispute | Evidence count > 50 items | Auto-escalate |
| High value | Escrow amount > 100,000 units | Auto-escalate |
| Model failure | AI returns error | Immediate escalation |
| Policy violation | Contract requires human review | Immediate escalation |

> **Note**: All confidence thresholds reference `AIConfidenceThreshold` from `00-CONSTANTS.md`. The unified threshold value is **0.75** across all AI decision contexts.

#### Escalation Message Flow

```
HumanEscalation
   ↓
HumanArbiterAssignment (assigns 1, 3, or 5 arbitrators)
   ↓
[Evidence Review Period: 72 hours]
   ↓
HumanArbitrationDecision (each arbitrator submits decision)
   ↓
[If panel, majority vote determines outcome]
   ↓
DecisionExecution
   ↓
DecisionAnnouncement
```

#### Human Arbiter Assignment

Arbitrators are assigned from trusted pool:

| Dispute Value | Panel Size | Decision Method |
|---------------|------------|-----------------|
| < 10,000 units | 1 arbitrator | Single decision |
| 10,000 - 100,000 | 3 arbitrators | Majority vote (2-of-3) |
| > 100,000 units | 5 arbitrators | Majority vote (3-of-5) |

**Assignment Criteria**:
- Arbitrator must have valid IDevID certificate
- No conflict of interest with dispute parties
- Minimum reputation score of 4.0/5.0
- Available within 24 hours
- Expertise match with dispute type

#### Human Decision Requirements

Human arbitrators MUST provide:

| Field | Requirement |
|-------|-------------|
| Reasoning | Minimum 100 characters, maximum 16KB |
| Outcome | Provider wins, Consumer wins, or Split |
| Split ratio | If split, ratio between 0.0 and 1.0 |
| Signature | Ed25519 signature from arbiter's IDevID |
| TPM quote | REQUIRED for high-value disputes (>100,000 units); recommended for all others |

**Decision Finality**: Human panel decisions with 3+ arbitrators are final and not appealable.

### Model Approval and Certification Protocol

#### Certification Request Process

AI model providers submit `ModelCertificationRequest`:

```protobuf
ModelCertificationRequest {
  request_id:               UUID v7
  model_hash:               SHA256 of model weights
  model_type:               Claude, GPT, Gemini, etc.
  model_version:            Semantic version string
  model_name:               Human-readable name
  provider_id:              Provider's IDevID hash
  certification_data:       Test results (bias, performance, safety)
  benchmark_results:        Standard benchmark scores
  bias_audit_hash:          Hash of third-party bias audit report
  max_confidence_requested: Requested maximum confidence (0.0-1.0)
  signature:                Provider's Ed25519 signature
}
```

#### Governance Review Process

Governance reviews certification requests:

1. **Submission**: Provider submits ModelCertificationRequest
2. **Validation**: System validates request format and signatures
3. **Testing**: Governance runs independent tests (72 hours)
4. **Vote**: Governance members vote on approval (7 days)
5. **Decision**: ModelApprovalStatus published
6. **Activation**: If approved, model added to whitelist at effective_epoch

#### Approval Conditions

Models may be approved with conditions:

| Condition Type | Description |
|----------------|-------------|
| `max_confidence_override` | Lower confidence limit than requested |
| `dispute_type_restriction` | Only allowed for specific dispute types |
| `human_review_required` | All decisions require human review |
| `probationary_period` | Limited approval duration (e.g., 90 days) |
| `audit_frequency` | Quarterly re-audit required |

#### Model Revocation

Models can be revoked via `ModelWhitelistUpdate` with action `MODEL_ACTION_REVOKE`:

**Immediate Revocation Triggers**:
- Critical security vulnerability discovered
- Bias beyond acceptable thresholds detected
- Provider certificate revoked
- Governance emergency action
- Failed audit during probationary period

**Revocation Impact**:
- Model cannot process new arbitration requests
- In-flight decisions must complete
- Historical decisions remain valid
- Provider notified within 1 hour
- Public announcement within 24 hours

#### Model Whitelist Synchronization

The model whitelist is synchronized across all nodes:

```
/ai-arbitration/model-whitelist/approved/
  ├── {model_hash_1}  → ModelApprovalStatus
  ├── {model_hash_2}  → ModelApprovalStatus
  └── {model_hash_N}  → ModelApprovalStatus

/ai-arbitration/model-whitelist/updates/
  └── {epoch}/        → ModelWhitelistUpdate[]
```

**Update Propagation**:
- Updates published to DHT immediately
- All nodes MUST apply updates within 1 epoch (typically 1 hour)
- Nodes failing to apply updates are marked non-compliant
- Compliance verified via periodic audit

---

**Document Version:** 1.4
**Last Updated:** 2026-01-10
**Status:** FINAL DESIGN - AI Arbitration Protocol Complete with Full Lifecycle
**Revision History:**
- v1.4 (2026-01-10): Evidence retention enforcement specification:
  - Added Evidence Retention Enforcement section with multi-layered storage requirements
  - Defined DHT replication factor (7 nodes), archival nodes (3 per region), geographic distribution
  - Added automatic rotation/archival schedule (hot/warm/cold storage tiers)
  - Specified periodic verification audits (daily, weekly, monthly, quarterly, annually)
  - Defined node retention penalties with graduated enforcement (warning to permanent ban)
  - Added Evidence Types and Retention Periods table (7 years for critical, 30-90 days for ephemeral)
  - Added Audit Trail and Temporal Proofs section with Merkle proof specifications
  - Defined cross-reference with DAG for immutable timestamping
  - Added historical evidence query types (ProveExistence, GetHistoricalRoot, VerifyChain, GetAuditLog)
  - Added Evidence Retrieval Process with authorization requirements by requester type
  - Defined response time SLAs by storage tier (100ms hot to 24h archive)
  - Added EvidenceRetrievalRequest and EvidenceRetrievalResponse message formats
  - Specified retrieval failure handling with error codes and recovery actions
- v1.3 (2026-01-10): Protocol consistency and correctness fixes:
  - Unified retry policy: idempotent operations (5 retries, exponential backoff), non-idempotent (3 retries, manual intervention)
  - Added circuit breaker (10 failures/minute) and alert threshold (3 consecutive failures)
  - Changed TPM attestation from optional to REQUIRED for all AI arbitration decisions
  - Added AI Arbitrator TPM Attestation Requirements section with validation process
  - Unified confidence threshold to 0.75 across all contexts (references AIConfidenceThreshold from 00-CONSTANTS.md)
  - Added Message Deduplication section with persistence requirements for reboot recovery
  - Defined deduplication windows: 1 hour (ephemeral), 24 hours (critical messages)
  - Added sequence number ordering and reboot recovery protocol
- v1.2 (2026-01-10): Added complete AI arbitration lifecycle messages and protocols:
  - AIArbitrationRequest, EvidenceSubmission, AIArbitrationAppeal messages
  - HumanEscalation, HumanArbiterAssignment, HumanArbitrationDecision messages
  - DecisionExecution, DecisionAnnouncement messages
  - ModelCertificationRequest, ModelApprovalStatus messages
  - Message ordering guarantees and delivery semantics
  - Evidence submission protocol with rate limiting and validation
  - Decision publishing protocol with signature requirements
  - Human review escalation protocol with assignment criteria
  - Model approval and certification protocol with governance process
  - Comprehensive timeout specifications for all AI arbitration operations
- v1.1 (2026-01-10): Added FINAL DESIGN AI arbitration message types, DHT topics, and rate limits
- v1.0 (2025-12-15): Initial wire protocol specification
