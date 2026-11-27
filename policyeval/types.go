// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

// OperandSource enumerates all data sources for policy evaluation.
// Environmental operands (0-16) are carried over from shapeshift/conditions.
// Authorization operands (17-24) are new in the policy engine.
// Approval operands (25-26) support workflow approval gates.
type OperandSource int

const (
	// Environmental operands (from shapeshift/conditions)
	OpPrice            OperandSource = iota // env::price
	OpUtilization                           // env::utilization
	OpCallCount                             // env::call_count
	OpUniqueCallers                         // env::unique_callers
	OpValueOutflow                          // env::value_outflow
	OpGasTotal                              // env::gas_total
	OpImmuneState                           // env::immune_state
	OpConfidenceScore                       // env::confidence_score
	OpBlockHeight                           // env::block_height
	OpConsensusTime                         // env::consensus_time
	OpStorageGet                            // env::storage_get(key)
	OpCurrentShape                          // env::current_shape
	OpShapeActiveSince                      // env::shape_active_since
	OpShapeTimeIn                           // env::shape_time_in(shape)
	OpCustomMetric                          // env::custom_metric(name)
	OpErrorCount                            // env::error_count
	OpFeedConfidence                        // env::feed_confidence

	// Authorization operands (NEW)
	OpActorIdentity   // actor::identity() -- caller's ADI URL
	OpActorRole       // actor::role("admin") -- bool: caller has role?
	OpActorHasKey     // actor::has_key("keyPage1") -- bool: caller's key page?
	OpScopeContract   // scope::contract() -- target contract URL
	OpScopeFunction   // scope::function() -- target function name
	OpScopeAmount     // scope::amount() -- transaction value
	OpTimeBlockHeight // time::block_height() -- current block
	OpTimeConsensus   // time::consensus_time() -- consensus timestamp

	// Approval operands
	OpApprovalCount      // approval::count("admin") -- approvals from role
	OpApprovalHas        // approval::has("acc://alice.acme") -- identity approved?
	OpApprovalSeparation // approval::separate("treasury", "compliance") -- bool: separation satisfied?
	OpApprovalCredential // approval::credential("compliance_officer") -- credential holder approved?
	OpApprovalDelegated  // approval::delegated("acc://alice.acme") -- delegated approval present?
	OpApprovalThreshold  // approval::threshold() -- current approval count / required threshold

	// Trust/feed operands (Phase 4)
	OpBridgeTrustLevel    // bridge::trust_level(adapterID) -> float64 (0-1)
	OpBridgeFinality      // bridge::finality(adapterID) -> string
	OpFeedTrustConfidence // feed::trust_confidence(feedName) -> float64
	OpFeedFreshness       // feed::freshness(feedName) -> uint64 (blocks since update)

	// DID operands (Phase 4)
	OpDIDVerified   // did::verified(didString, relationship) -> bool (1.0/0.0)
	OpDIDController // did::controller(didString) -> string
	OpDIDHasKey     // did::has_key(didString, keyHash) -> bool (1.0/0.0)

	// L0 state operands (Phase 4)
	OpL0Balance          // l0::balance(accountURL) -> float64
	OpL0CreditBalance    // l0::credits(accountURL) -> float64
	OpL0KeyPageThreshold // l0::threshold(keyPageURL) -> float64
	OpL0AccountExists    // l0::exists(accountURL) -> bool (1.0/0.0)

	// Object-scoped operands (Phase 5)
	OpObjectType     // object::type() -> string (the object's type identifier)
	OpObjectState    // object::state() -> string (current lifecycle state)
	OpObjectField    // object::field(fieldName) -> any (field value)
	OpObjectAge      // object::age() -> uint64 (blocks since creation)
	OpObjectBindings // object::bindings() -> uint64 (count of policy bindings)

	// Manifest-scoped operands (Phase 5)
	OpManifestHasCap      // manifest::has_cap(capability) -> bool (1.0/0.0)
	OpManifestObjectScope // manifest::object_scope(objectType) -> string (r/w/rw/none)

	// Contract-scoped operands (G-02 Phase 5)
	OpContractAuthority // scope::contract_authority() → contract's authority ADI
	OpContractVersion   // scope::contract_version() → contract version number
	OpContractCodeHash  // scope::contract_code_hash() → hash of contract code
	OpFunctionName      // scope::function_name() → function being called

	// Intent-scoped operands (G-02 Phase 5)
	OpIntentGoalType        // intent::goal_type() → goal type of the intent
	OpIntentAssetCount      // intent::asset_count() → number of assets in intent
	OpIntentConstraintCount // intent::constraint_count() → number of constraints

	// Workflow-scoped operands (G-02 Phase 5)
	OpWorkflowStage      // workflow::stage() → current workflow stage
	OpWorkflowStageCount // workflow::stage_count() → total stages in workflow

	// Plan-scoped operands (G-02 Phase 5)
	OpPlanStepCount      // plan::step_count() → total steps in plan
	OpPlanGasEstimate    // plan::gas_estimate() → total gas estimate
	OpPlanDriftThreshold // plan::drift_threshold() → drift threshold

	// Ghost simulation operands (G-04 Phase 5).
	OpGhostGasPredicted // ghost::gas_predicted() → uint64 total predicted gas
	OpGhostDrift        // ghost::drift() → float64 max ghost gas drift
	OpGhostFreshness    // ghost::freshness() → string ("fresh", "stale", "expired")

	// Genome operands (G-04 Genome Phase 2).
	OpGenomeQuarantined // genome::quarantined(contractURL) → bool (1.0/0.0)
	OpGenomeVersion     // genome::version(contractURL, componentID) → string

	// Rewind operands (G-04 Rewind Phase 4).
	OpRewindWindow       // rewind::window() → uint64 (finality window in blocks)
	OpRewindPendingCount // rewind::pending_count() → uint64

	// Universal trust operands (Phase G08)
	OpTrustLevel      // trust::level(profileID) -> float64 (0.0-1.0)
	OpTrustFinality   // trust::finality(profileID) -> string
	OpTrustFreshness  // trust::freshness(profileID) -> float64 (seconds since update)
	OpTrustDomain     // trust::domain(profileID) -> string
	OpTrustAssumption // trust::assumption(profileID) -> string
	OpTrustProofType  // trust::proof_type(profileID) -> string
	OpTrustState      // trust::state(profileID) -> string (active/degraded/suspended/revoked)

	// Grant-scoped operands (Phase G09)
	OpGrantActive        // grant::active(granteeURL, capability) -> bool (1.0/0.0)
	OpGrantCount         // grant::count(granteeURL) -> float64
	OpGrantExpiresWithin // grant::expires_within(granteeURL, blocks) -> bool (1.0/0.0)
	OpGrantDelegated     // grant::delegated(granteeURL) -> bool (1.0/0.0)
	OpGrantDepth         // grant::depth(granteeURL) -> float64

	// Role-scoped operands (G-10)
	OpRoleScope           // role::scope(identity, role) -> string (scope type of the binding)
	OpRoleEffectiveUntil  // role::effective_until(identity, role) -> uint64 (expiry block)
	OpRoleIsEmergency     // role::is_emergency(identity, role) -> bool (1.0/0.0)
	OpRoleGrantedBy       // role::granted_by(identity, role) -> string (grantor identity)
	OpRoleCount           // role::count(identity) -> uint64 (number of active roles)
	OpRoleSeparationCheck // role::separation_check(identity, role1, role2) -> bool (1.0 compatible, 0.0 incompatible)

	// Settlement-scoped operands (Phase G-12)
	OpSettlementAmount       // settlement::amount -> uint64
	OpSettlementMethod       // settlement::method -> string ("atomic", "phased", "netting", "bridge")
	OpSettlementCrossDomain  // settlement::cross_domain -> bool (1.0/0.0)
	OpSettlementNettingGroup // settlement::netting_group -> string (group ID or "")
	OpSettlementLegCount     // settlement::leg_count -> uint64
	OpSettlementDeadline     // settlement::deadline -> uint64 (block height)

	// Escrow-scoped operands (Phase G-12)
	OpEscrowAmount         // escrow::amount -> uint64
	OpEscrowHasArbiter     // escrow::has_arbiter -> bool (1.0/0.0)
	OpEscrowDeadlineBlocks // escrow::deadline_blocks -> uint64
	OpEscrowPartyCount     // escrow::party_count -> uint64
	OpEscrowAssetCount     // escrow::asset_count -> uint64

	// Disclosure-scoped operands (G-13)
	OpDisclosureActive  // disclosure::active(targetID, actor) -> bool (1.0/0.0)
	OpDisclosureCount   // disclosure::count(targetID) -> float64 (active grants)
	OpDisclosurePurpose // disclosure::purpose(grantID) -> string
	OpDisclosureHasZKP  // disclosure::has_zkp(grantID) -> bool (1.0/0.0)
	OpDisclosureGrantor // disclosure::grantor(grantID) -> string
	OpDisclosureExpiry  // disclosure::expiry(grantID) -> float64 (remaining blocks)

	// Anchoring operands (G-14)
	OpAnchorArtifactType   // anchor::artifact_type() -> string
	OpAnchorValueThreshold // anchor::value_threshold() -> float64
	OpAnchorIntervalBlocks // anchor::interval_blocks() -> uint64
	OpAnchorLastAnchorAge  // anchor::last_anchor_age() -> uint64 (blocks since last anchor)
	OpAnchorPendingCount   // anchor::pending_count() -> uint64
	OpAnchorCreditBudget   // anchor::credit_budget() -> uint64 (remaining credits)
	OpAnchorBatchSize      // anchor::batch_size() -> uint64 (current batch accumulation)

	// Wall-clock deadline operands (idle-execution-fabric step 6). Appended at the
	// end of the enum so no existing operand's numeric value shifts. These are the
	// wall-clock (consensus-time seconds) siblings of the block-height deadline
	// operands above: under the idle-unless-mutated model a settlement deadline must
	// expire by real elapsed time, not by state-version activity. IsSettlementOperand
	// / IsEscrowOperand include them explicitly.
	OpSettlementDeadlineSeconds // settlement::deadline_seconds -> uint64 (wall-clock unix seconds)
	OpEscrowDeadlineSeconds     // escrow::deadline_seconds -> uint64 (wall-clock unix seconds)

	// Wall-clock disclosure grant-expiry operand (idle-execution-fabric runbook 9).
	// Appended so no existing operand's numeric value shifts. disclosure::expiry is
	// state-version (remaining blocks) and never counts down while idle — a privacy
	// grant that should lapse stays valid forever on a quiet node. This is its
	// wall-clock sibling (remaining seconds). IsDisclosureOperand includes it.
	OpDisclosureExpirySeconds // disclosure::expiry_seconds(grantID) -> float64 (remaining seconds)

	// Explicit-request anchoring operand. Appended so no existing operand's numeric
	// value shifts. anchor::forced() is true (1.0) only when a plan step that is itself
	// marked Forced (workflow.AnchorStepParams.Forced: the ANCHOR_FORCE and
	// SYSTEM_ANCHOR_PERIODIC goals) asked for the anchor, through
	// AnchorOrchestrator.RequestStepAnchor, and false (0.0) for every other plan
	// anchor step and for every automatic, periodic, event-hook and system-origin trigger. IsAnchorOperand
	// includes it explicitly.
	OpAnchorForced // anchor::forced() -> bool (1.0/0.0)

	// Access operand (appended, so no earlier operand's value shifts). access::allowed("resource", "action") is true when the node's access controller, deciding for
	// the VERIFIED actor with the roles the governed role registry says it holds and the access catalog in force, allows that action on that resource. It is the one
	// way the governed policy path asks the access controller (B.AUTH.ACCESSCONTROLLER.WIRED): the controller is not a second decision point beside policy.
	OpAccessAllowed // access::allowed(resource, action) -> bool (1.0/0.0)
)

// operandNameMapForRegistry is the canonical operand → name lookup.
// It is shared by OperandSourceName and the OperandRegistry so that the
// "every operand has a meta record" coverage test can iterate it.
var operandNameMapForRegistry = map[OperandSource]string{
	OpPrice: "env::price", OpUtilization: "env::utilization",
	OpCallCount: "env::call_count", OpUniqueCallers: "env::unique_callers",
	OpValueOutflow: "env::value_outflow", OpGasTotal: "env::gas_total",
	OpImmuneState: "env::immune_state", OpConfidenceScore: "env::confidence_score",
	OpBlockHeight: "env::block_height", OpConsensusTime: "env::consensus_time",
	OpStorageGet: "env::storage_get", OpCurrentShape: "env::current_shape",
	OpShapeActiveSince: "env::shape_active_since", OpShapeTimeIn: "env::shape_time_in",
	OpCustomMetric: "env::custom_metric", OpErrorCount: "env::error_count",
	OpFeedConfidence: "env::feed_confidence",
	OpActorIdentity:  "actor::identity", OpActorRole: "actor::role",
	OpActorHasKey: "actor::has_key", OpScopeContract: "scope::contract",
	OpScopeFunction: "scope::function", OpScopeAmount: "scope::amount",
	OpTimeBlockHeight: "time::block_height", OpTimeConsensus: "time::consensus_time",
	OpApprovalCount: "approval::count", OpApprovalHas: "approval::has",
	OpApprovalSeparation: "approval::separate",
	OpApprovalCredential: "approval::credential",
	OpApprovalDelegated:  "approval::delegated", OpApprovalThreshold: "approval::threshold",
	OpBridgeTrustLevel: "bridge::trust_level", OpBridgeFinality: "bridge::finality",
	OpFeedTrustConfidence: "feed::trust_confidence", OpFeedFreshness: "feed::freshness",
	OpDIDVerified: "did::verified", OpDIDController: "did::controller",
	OpDIDHasKey: "did::has_key",
	OpL0Balance: "l0::balance", OpL0CreditBalance: "l0::credits",
	OpL0KeyPageThreshold: "l0::threshold", OpL0AccountExists: "l0::exists",
	OpObjectType: "object::type", OpObjectState: "object::state",
	OpObjectField: "object::field", OpObjectAge: "object::age",
	OpObjectBindings: "object::bindings",
	OpManifestHasCap: "manifest::has_cap", OpManifestObjectScope: "manifest::object_scope",
	OpContractAuthority: "scope::contract_authority", OpContractVersion: "scope::contract_version",
	OpContractCodeHash: "scope::contract_code_hash", OpFunctionName: "scope::function_name",
	OpIntentGoalType: "intent::goal_type", OpIntentAssetCount: "intent::asset_count",
	OpIntentConstraintCount: "intent::constraint_count",
	OpWorkflowStage:         "workflow::stage", OpWorkflowStageCount: "workflow::stage_count",
	OpPlanStepCount: "plan::step_count", OpPlanGasEstimate: "plan::gas_estimate",
	OpPlanDriftThreshold: "plan::drift_threshold",
	OpGhostGasPredicted:  "ghost::gas_predicted", OpGhostDrift: "ghost::drift",
	OpGhostFreshness:    "ghost::freshness",
	OpGenomeQuarantined: "genome::quarantined", OpGenomeVersion: "genome::version",
	OpRewindWindow: "rewind::window", OpRewindPendingCount: "rewind::pending_count",
	OpTrustLevel: "trust::level", OpTrustFinality: "trust::finality",
	OpTrustFreshness: "trust::freshness", OpTrustDomain: "trust::domain",
	OpTrustAssumption: "trust::assumption", OpTrustProofType: "trust::proof_type",
	OpTrustState:  "trust::state",
	OpGrantActive: "grant::active", OpGrantCount: "grant::count",
	OpGrantExpiresWithin: "grant::expires_within",
	OpGrantDelegated:     "grant::delegated", OpGrantDepth: "grant::depth",
	OpRoleScope:                 "role::scope",
	OpRoleEffectiveUntil:        "role::effective_until",
	OpRoleIsEmergency:           "role::is_emergency",
	OpRoleGrantedBy:             "role::granted_by",
	OpRoleCount:                 "role::count",
	OpRoleSeparationCheck:       "role::separation_check",
	OpSettlementAmount:          "settlement::amount",
	OpSettlementMethod:          "settlement::method",
	OpSettlementCrossDomain:     "settlement::cross_domain",
	OpSettlementNettingGroup:    "settlement::netting_group",
	OpSettlementLegCount:        "settlement::leg_count",
	OpSettlementDeadline:        "settlement::deadline",
	OpEscrowAmount:              "escrow::amount",
	OpEscrowHasArbiter:          "escrow::has_arbiter",
	OpEscrowDeadlineBlocks:      "escrow::deadline_blocks",
	OpEscrowPartyCount:          "escrow::party_count",
	OpEscrowAssetCount:          "escrow::asset_count",
	OpDisclosureActive:          "disclosure::active",
	OpDisclosureCount:           "disclosure::count",
	OpDisclosurePurpose:         "disclosure::purpose",
	OpDisclosureHasZKP:          "disclosure::has_zkp",
	OpDisclosureGrantor:         "disclosure::grantor",
	OpDisclosureExpiry:          "disclosure::expiry",
	OpDisclosureExpirySeconds:   "disclosure::expiry_seconds",
	OpAnchorArtifactType:        "anchor::artifact_type",
	OpAnchorValueThreshold:      "anchor::value_threshold",
	OpAnchorIntervalBlocks:      "anchor::interval_blocks",
	OpAnchorLastAnchorAge:       "anchor::last_anchor_age",
	OpAnchorPendingCount:        "anchor::pending_count",
	OpAnchorCreditBudget:        "anchor::credit_budget",
	OpAnchorBatchSize:           "anchor::batch_size",
	OpSettlementDeadlineSeconds: "settlement::deadline_seconds",
	OpEscrowDeadlineSeconds:     "escrow::deadline_seconds",
	OpAnchorForced:              "anchor::forced",
	OpAccessAllowed:             "access::allowed",
}

// OperandNames returns the canonical operand -> name table (the map itself, shared with the node's operand registry; callers must not
// write to it).
func OperandNames() map[OperandSource]string { return operandNameMapForRegistry }

// OperandSourceName returns a human-readable name for an operand source.
func OperandSourceName(s OperandSource) string {
	if n, ok := operandNameMapForRegistry[s]; ok {
		return n
	}
	// Legacy fallback path retained for any operand not yet migrated to
	// the canonical map.
	names := map[OperandSource]string{
		OpPrice: "env::price", OpUtilization: "env::utilization",
		OpCallCount: "env::call_count", OpUniqueCallers: "env::unique_callers",
		OpValueOutflow: "env::value_outflow", OpGasTotal: "env::gas_total",
		OpImmuneState: "env::immune_state", OpConfidenceScore: "env::confidence_score",
		OpBlockHeight: "env::block_height", OpConsensusTime: "env::consensus_time",
		OpStorageGet: "env::storage_get", OpCurrentShape: "env::current_shape",
		OpShapeActiveSince: "env::shape_active_since", OpShapeTimeIn: "env::shape_time_in",
		OpCustomMetric: "env::custom_metric", OpErrorCount: "env::error_count",
		OpFeedConfidence: "env::feed_confidence",
		OpActorIdentity:  "actor::identity", OpActorRole: "actor::role",
		OpActorHasKey: "actor::has_key", OpScopeContract: "scope::contract",
		OpScopeFunction: "scope::function", OpScopeAmount: "scope::amount",
		OpTimeBlockHeight: "time::block_height", OpTimeConsensus: "time::consensus_time",
		OpApprovalCount: "approval::count", OpApprovalHas: "approval::has",
		OpApprovalSeparation: "approval::separate",
		OpApprovalCredential: "approval::credential",
		OpApprovalDelegated:  "approval::delegated", OpApprovalThreshold: "approval::threshold",
		OpBridgeTrustLevel: "bridge::trust_level", OpBridgeFinality: "bridge::finality",
		OpFeedTrustConfidence: "feed::trust_confidence", OpFeedFreshness: "feed::freshness",
		OpDIDVerified: "did::verified", OpDIDController: "did::controller",
		OpDIDHasKey: "did::has_key",
		OpL0Balance: "l0::balance", OpL0CreditBalance: "l0::credits",
		OpL0KeyPageThreshold: "l0::threshold", OpL0AccountExists: "l0::exists",
		// Object-scoped
		OpObjectType: "object::type", OpObjectState: "object::state",
		OpObjectField: "object::field", OpObjectAge: "object::age",
		OpObjectBindings: "object::bindings",
		// Manifest-scoped
		OpManifestHasCap: "manifest::has_cap", OpManifestObjectScope: "manifest::object_scope",
		// Contract-scoped (G-02 Phase 5)
		OpContractAuthority: "scope::contract_authority", OpContractVersion: "scope::contract_version",
		OpContractCodeHash: "scope::contract_code_hash", OpFunctionName: "scope::function_name",
		// Intent-scoped
		OpIntentGoalType: "intent::goal_type", OpIntentAssetCount: "intent::asset_count",
		OpIntentConstraintCount: "intent::constraint_count",
		// Workflow-scoped
		OpWorkflowStage: "workflow::stage", OpWorkflowStageCount: "workflow::stage_count",
		// Plan-scoped
		OpPlanStepCount: "plan::step_count", OpPlanGasEstimate: "plan::gas_estimate",
		OpPlanDriftThreshold: "plan::drift_threshold",
		// Ghost-scoped (G-04 Phase 5)
		OpGhostGasPredicted: "ghost::gas_predicted", OpGhostDrift: "ghost::drift",
		OpGhostFreshness: "ghost::freshness",
		// Genome-scoped (G-04 Genome Phase 2)
		OpGenomeQuarantined: "genome::quarantined", OpGenomeVersion: "genome::version",
		// Rewind-scoped (G-04 Rewind Phase 4)
		OpRewindWindow: "rewind::window", OpRewindPendingCount: "rewind::pending_count",
		// Universal trust (Phase G08)
		OpTrustLevel: "trust::level", OpTrustFinality: "trust::finality",
		OpTrustFreshness: "trust::freshness", OpTrustDomain: "trust::domain",
		OpTrustAssumption: "trust::assumption", OpTrustProofType: "trust::proof_type",
		OpTrustState: "trust::state",
		// Grant-scoped (Phase G09)
		OpGrantActive: "grant::active", OpGrantCount: "grant::count",
		OpGrantExpiresWithin: "grant::expires_within",
		OpGrantDelegated:     "grant::delegated", OpGrantDepth: "grant::depth",
		// Role-scoped (G-10)
		OpRoleScope:           "role::scope",
		OpRoleEffectiveUntil:  "role::effective_until",
		OpRoleIsEmergency:     "role::is_emergency",
		OpRoleGrantedBy:       "role::granted_by",
		OpRoleCount:           "role::count",
		OpRoleSeparationCheck: "role::separation_check",
		// Settlement-scoped (G-12)
		OpSettlementAmount:       "settlement::amount",
		OpSettlementMethod:       "settlement::method",
		OpSettlementCrossDomain:  "settlement::cross_domain",
		OpSettlementNettingGroup: "settlement::netting_group",
		OpSettlementLegCount:     "settlement::leg_count",
		OpSettlementDeadline:     "settlement::deadline",
		// Escrow-scoped (G-12)
		OpEscrowAmount:         "escrow::amount",
		OpEscrowHasArbiter:     "escrow::has_arbiter",
		OpEscrowDeadlineBlocks: "escrow::deadline_blocks",
		OpEscrowPartyCount:     "escrow::party_count",
		OpEscrowAssetCount:     "escrow::asset_count",
		// Disclosure-scoped (G-13)
		OpDisclosureActive:        "disclosure::active",
		OpDisclosureCount:         "disclosure::count",
		OpDisclosurePurpose:       "disclosure::purpose",
		OpDisclosureHasZKP:        "disclosure::has_zkp",
		OpDisclosureGrantor:       "disclosure::grantor",
		OpDisclosureExpiry:        "disclosure::expiry",
		OpDisclosureExpirySeconds: "disclosure::expiry_seconds",
		// Anchoring (G-14)
		OpAnchorArtifactType:        "anchor::artifact_type",
		OpAnchorValueThreshold:      "anchor::value_threshold",
		OpAnchorIntervalBlocks:      "anchor::interval_blocks",
		OpAnchorLastAnchorAge:       "anchor::last_anchor_age",
		OpAnchorPendingCount:        "anchor::pending_count",
		OpAnchorCreditBudget:        "anchor::credit_budget",
		OpAnchorBatchSize:           "anchor::batch_size",
		OpSettlementDeadlineSeconds: "settlement::deadline_seconds",
		OpEscrowDeadlineSeconds:     "escrow::deadline_seconds",
		OpAnchorForced:              "anchor::forced",
		OpAccessAllowed:             "access::allowed",
	}
	if n, ok := names[s]; ok {
		return n
	}
	return "unknown"
}

// IsAuthorizationOperand returns true if the operand is an authorization check.
func IsAuthorizationOperand(s OperandSource) bool {
	return s >= OpActorIdentity && s <= OpTimeConsensus
}

// IsApprovalOperand returns true if the operand is an approval check.
func IsApprovalOperand(s OperandSource) bool {
	return s >= OpApprovalCount && s <= OpApprovalThreshold
}

// IsEnvironmentalOperand returns true if the operand is environmental.
func IsEnvironmentalOperand(s OperandSource) bool {
	return s >= OpPrice && s <= OpFeedConfidence
}

// IsObjectOperand returns true if the operand queries typed object state.
func IsObjectOperand(s OperandSource) bool {
	return s >= OpObjectType && s <= OpObjectBindings
}

// IsManifestOperand returns true if the operand queries contract manifest state.
func IsManifestOperand(s OperandSource) bool {
	return s >= OpManifestHasCap && s <= OpManifestObjectScope
}

// IsDisclosureOperand returns true if the operand queries disclosure state (G-13).
func IsDisclosureOperand(s OperandSource) bool {
	return (s >= OpDisclosureActive && s <= OpDisclosureExpiry) || s == OpDisclosureExpirySeconds
}

// IsTrustOperand returns true if the operand queries trust profile state.
func IsTrustOperand(s OperandSource) bool {
	return s >= OpTrustLevel && s <= OpTrustState
}

// IsGrantOperand returns true if the operand queries capability grant state.
func IsGrantOperand(s OperandSource) bool {
	return s >= OpGrantActive && s <= OpGrantDepth
}

// IsRoleOperand returns true if the operand queries role binding state (G-10).
func IsRoleOperand(s OperandSource) bool {
	return s >= OpRoleScope && s <= OpRoleSeparationCheck
}

// (range-check helpers below include the appended wall-clock deadline operands.)

// IsSettlementOperand returns true if the operand queries settlement instruction
// state (G-12).
func IsSettlementOperand(s OperandSource) bool {
	return (s >= OpSettlementAmount && s <= OpSettlementDeadline) || s == OpSettlementDeadlineSeconds
}

// IsEscrowOperand returns true if the operand queries escrow object state (G-12).
func IsEscrowOperand(s OperandSource) bool {
	return (s >= OpEscrowAmount && s <= OpEscrowAssetCount) || s == OpEscrowDeadlineSeconds
}

// IsAccessOperand returns true if the operand asks the access controller.
func IsAccessOperand(s OperandSource) bool { return s == OpAccessAllowed }

// IsAnchorOperand returns true if the operand queries anchoring state (G-14).
func IsAnchorOperand(s OperandSource) bool {
	return (s >= OpAnchorArtifactType && s <= OpAnchorBatchSize) || s == OpAnchorForced
}

// BinaryOp is a binary logical operator.
type BinaryOp int

const (
	BinaryAnd BinaryOp = iota
	BinaryOr
)

// UnaryOp is a unary logical operator.
type UnaryOp int

const (
	UnaryNot UnaryOp = iota
)

// ComparisonOp is a comparison operator.
type ComparisonOp int

const (
	CmpEq  ComparisonOp = iota // ==
	CmpNeq                     // !=
	CmpGt                      // >
	CmpLt                      // <
	CmpGte                     // >=
	CmpLte                     // <=
)

// LiteralType enumerates literal value types.
type LiteralType int

const (
	LitInt LiteralType = iota
	LitFloat
	LitString
	LitBool
)

// AggregationFunc enumerates windowed aggregation functions.
type AggregationFunc int

const (
	AggAvg AggregationFunc = iota
	AggMax
	AggMin
	AggStdDev
	AggSum
	AggCount
)

// ConditionOp is a bytecode instruction for the policy VM.
type ConditionOp byte

const (
	OpPushLitInt   ConditionOp = 0x01
	OpPushLitFloat ConditionOp = 0x02
	OpPushLitStr   ConditionOp = 0x03
	OpPushLitBool  ConditionOp = 0x04
	OpLoadOperand  ConditionOp = 0x10
	OpLoadAgg      ConditionOp = 0x11
	OpCmpEqBC      ConditionOp = 0x20
	OpCmpNeqBC     ConditionOp = 0x21
	OpCmpGtBC      ConditionOp = 0x22
	OpCmpLtBC      ConditionOp = 0x23
	OpCmpGteBC     ConditionOp = 0x24
	OpCmpLteBC     ConditionOp = 0x25
	OpAndBC        ConditionOp = 0x30
	OpOrBC         ConditionOp = 0x31
	OpNotBC        ConditionOp = 0x32
	OpAddBC        ConditionOp = 0x40
	OpSubBC        ConditionOp = 0x41
	OpMulBC        ConditionOp = 0x42
	OpDivBC        ConditionOp = 0x43
	OpModBC        ConditionOp = 0x44
	// String-aware opcodes (Phase 4)
	OpStrContains ConditionOp = 0x50 // pop two strings, push bool (contains)
	OpStrPrefix   ConditionOp = 0x51 // pop two strings, push bool (has prefix)
	OpStrSuffix   ConditionOp = 0x52 // pop two strings, push bool (has suffix)
	OpStrMatch    ConditionOp = 0x53 // pop pattern + string, push bool (glob match)
	OpHalt        ConditionOp = 0xFF
)

// EvalContext provides data source resolution for the bytecode VM.
// Implementors must resolve both environmental AND authorization operands.
type EvalContext interface {
	// ResolveOperand resolves an operand to a value.
	// For boolean operands (actor::role, actor::has_key, approval::has),
	// return 1.0 for true, 0.0 for false.
	// For string operands (actor::identity, scope::contract),
	// return the string value directly.
	ResolveOperand(source OperandSource, args []string) (interface{}, error)

	// ResolveAggregation resolves an aggregated operand over a window. windowSize
	// is expressed in windowUnit's dimension: canonical block height / state
	// version (AggWindowBlocks) or wall-clock seconds (AggWindowSeconds). The
	// wall-clock unit lets a rate-limit/frequency rule measure real elapsed time,
	// which is required under the idle-unless-mutated model where block height is a
	// mutation-paced state version rather than a wall-clock proxy.
	ResolveAggregation(function AggregationFunc, operandSource OperandSource,
		operandArgs []string, windowSize uint64, windowUnit AggregationWindowUnit) (float64, error)
}

// AggregationWindowUnit is the dimension an aggregation window is measured in.
type AggregationWindowUnit uint8

const (
	// AggWindowBlocks measures the window in canonical block height / state
	// version (the default; a "per N canonical state changes" window). Under the
	// idle-unless-mutated model this is activity-paced, not wall-clock-paced.
	AggWindowBlocks AggregationWindowUnit = 0
	// AggWindowSeconds measures the window in wall-clock unix seconds (a
	// "per N seconds" window), so a rate limit measures real elapsed time even
	// while the canonical version is idle.
	AggWindowSeconds AggregationWindowUnit = 1
)

// String renders the unit for the aggregation grammar / diagnostics.
func (u AggregationWindowUnit) String() string {
	if u == AggWindowSeconds {
		return "seconds"
	}
	return "blocks"
}

// CompiledCondition is the bytecode output of the policy compiler.
type CompiledCondition struct {
	Bytecode         []byte
	Literals         []interface{}
	Operands         []OperandDescriptor
	Aggregations     []AggregationDescriptor
	SourceExpression string
	EstimatedGas     uint64
}

// OperandDescriptor describes a single operand reference in bytecode.
type OperandDescriptor struct {
	Source OperandSource
	Args   []string
}

// AggregationDescriptor describes an aggregation in bytecode.
type AggregationDescriptor struct {
	Function     AggregationFunc
	Source       OperandSource
	Args         []string
	WindowBlocks uint64
	// WindowUnit is the dimension WindowBlocks is measured in (block height by
	// default, wall-clock seconds when the rule declared a `seconds` window).
	WindowUnit AggregationWindowUnit
}

// ResolveOperandSource maps "namespace::function" to an OperandSource.
// This is the canonical mapping used by the parser.
func ResolveOperandSource(namespace, funcName string) (OperandSource, bool) {
	key := namespace + "::" + funcName
	sources := map[string]OperandSource{
		// Environmental
		"env::price": OpPrice, "env::utilization": OpUtilization,
		"env::call_count": OpCallCount, "env::unique_callers": OpUniqueCallers,
		"env::value_outflow": OpValueOutflow, "env::gas_total": OpGasTotal,
		"env::immune_state": OpImmuneState, "env::confidence_score": OpConfidenceScore,
		"env::block_height": OpBlockHeight, "env::consensus_time": OpConsensusTime,
		"env::storage_get": OpStorageGet, "env::current_shape": OpCurrentShape,
		"env::shape_active_since": OpShapeActiveSince, "env::shape_time_in": OpShapeTimeIn,
		"env::custom_metric": OpCustomMetric, "env::error_count": OpErrorCount,
		"env::feed_confidence": OpFeedConfidence,
		// Authorization
		"actor::identity": OpActorIdentity, "actor::role": OpActorRole,
		"actor::has_key": OpActorHasKey, "scope::contract": OpScopeContract,
		"scope::function": OpScopeFunction, "scope::amount": OpScopeAmount,
		"time::block_height": OpTimeBlockHeight, "time::consensus_time": OpTimeConsensus,
		// Approvals
		"approval::count": OpApprovalCount, "approval::has": OpApprovalHas,
		"approval::separate":   OpApprovalSeparation,
		"approval::credential": OpApprovalCredential,
		"approval::delegated":  OpApprovalDelegated, "approval::threshold": OpApprovalThreshold,
		// Trust/feeds
		"bridge::trust_level": OpBridgeTrustLevel, "bridge::finality": OpBridgeFinality,
		"feed::trust_confidence": OpFeedTrustConfidence, "feed::freshness": OpFeedFreshness,
		// DID
		"did::verified": OpDIDVerified, "did::controller": OpDIDController,
		"did::has_key": OpDIDHasKey,
		// L0 state
		"l0::balance": OpL0Balance, "l0::credits": OpL0CreditBalance,
		"l0::threshold": OpL0KeyPageThreshold, "l0::exists": OpL0AccountExists,
		// Object-scoped
		"object::type": OpObjectType, "object::state": OpObjectState,
		"object::field": OpObjectField, "object::age": OpObjectAge,
		"object::bindings": OpObjectBindings,
		// Manifest-scoped
		"manifest::has_cap": OpManifestHasCap, "manifest::object_scope": OpManifestObjectScope,
		// Contract-scoped (G-02 Phase 5)
		"scope::contract_authority": OpContractAuthority, "scope::contract_version": OpContractVersion,
		"scope::contract_code_hash": OpContractCodeHash, "scope::function_name": OpFunctionName,
		// Intent-scoped
		"intent::goal_type": OpIntentGoalType, "intent::asset_count": OpIntentAssetCount,
		"intent::constraint_count": OpIntentConstraintCount,
		// Workflow-scoped
		"workflow::stage": OpWorkflowStage, "workflow::stage_count": OpWorkflowStageCount,
		// Plan-scoped
		"plan::step_count": OpPlanStepCount, "plan::gas_estimate": OpPlanGasEstimate,
		"plan::drift_threshold": OpPlanDriftThreshold,
		// Ghost-scoped (G-04 Phase 5)
		"ghost::gas_predicted": OpGhostGasPredicted, "ghost::drift": OpGhostDrift,
		"ghost::freshness": OpGhostFreshness,
		// Genome-scoped (G-04 Genome Phase 2)
		"genome::quarantined": OpGenomeQuarantined, "genome::version": OpGenomeVersion,
		// Rewind-scoped (G-04 Rewind Phase 4)
		"rewind::window": OpRewindWindow, "rewind::pending_count": OpRewindPendingCount,
		// Universal trust (Phase G08)
		"trust::level": OpTrustLevel, "trust::finality": OpTrustFinality,
		"trust::freshness": OpTrustFreshness, "trust::domain": OpTrustDomain,
		"trust::assumption": OpTrustAssumption, "trust::proof_type": OpTrustProofType,
		"trust::state": OpTrustState,
		// Grant-scoped (Phase G09)
		"grant::active": OpGrantActive, "grant::count": OpGrantCount,
		"grant::expires_within": OpGrantExpiresWithin,
		"grant::delegated":      OpGrantDelegated, "grant::depth": OpGrantDepth,
		// Role-scoped (G-10)
		"role::scope":            OpRoleScope,
		"role::effective_until":  OpRoleEffectiveUntil,
		"role::is_emergency":     OpRoleIsEmergency,
		"role::granted_by":       OpRoleGrantedBy,
		"role::count":            OpRoleCount,
		"role::separation_check": OpRoleSeparationCheck,
		// Settlement-scoped (G-12)
		"settlement::amount":           OpSettlementAmount,
		"settlement::method":           OpSettlementMethod,
		"settlement::cross_domain":     OpSettlementCrossDomain,
		"settlement::netting_group":    OpSettlementNettingGroup,
		"settlement::leg_count":        OpSettlementLegCount,
		"settlement::deadline":         OpSettlementDeadline,
		"settlement::deadline_seconds": OpSettlementDeadlineSeconds,
		// Escrow-scoped (G-12)
		"escrow::amount":           OpEscrowAmount,
		"escrow::has_arbiter":      OpEscrowHasArbiter,
		"escrow::deadline_blocks":  OpEscrowDeadlineBlocks,
		"escrow::deadline_seconds": OpEscrowDeadlineSeconds,
		"escrow::party_count":      OpEscrowPartyCount,
		"escrow::asset_count":      OpEscrowAssetCount,
		// Disclosure-scoped (G-13)
		"disclosure::active":         OpDisclosureActive,
		"disclosure::count":          OpDisclosureCount,
		"disclosure::purpose":        OpDisclosurePurpose,
		"disclosure::has_zkp":        OpDisclosureHasZKP,
		"disclosure::grantor":        OpDisclosureGrantor,
		"disclosure::expiry":         OpDisclosureExpiry,
		"disclosure::expiry_seconds": OpDisclosureExpirySeconds,
		// Anchoring (G-14)
		"anchor::artifact_type":   OpAnchorArtifactType,
		"anchor::value_threshold": OpAnchorValueThreshold,
		"anchor::interval_blocks": OpAnchorIntervalBlocks,
		"anchor::last_anchor_age": OpAnchorLastAnchorAge,
		"anchor::pending_count":   OpAnchorPendingCount,
		"anchor::credit_budget":   OpAnchorCreditBudget,
		"anchor::batch_size":      OpAnchorBatchSize,
		"anchor::forced":          OpAnchorForced,
		// Access (B.AUTH.ACCESSCONTROLLER.WIRED)
		"access::allowed": OpAccessAllowed,
	}
	s, ok := sources[key]
	return s, ok
}
