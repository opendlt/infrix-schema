package intentschema

// IntentGoalType identifies the category of an intent's desired outcome.
type IntentGoalType string

const (
	GoalConvert          IntentGoalType = "CONVERT"
	GoalEarnYield        IntentGoalType = "EARN_YIELD"
	GoalBorrow           IntentGoalType = "BORROW"
	GoalProvideLiquidity IntentGoalType = "PROVIDE_LIQUIDITY"
	GoalSwap             IntentGoalType = "SWAP"
	GoalStake            IntentGoalType = "STAKE"
	GoalBridge           IntentGoalType = "BRIDGE"
	GoalCompound         IntentGoalType = "COMPOUND"
	GoalCustom           IntentGoalType = "CUSTOM"

	// System-level intent types (protocol operations)
	GoalObjectCreate IntentGoalType = "OBJECT_CREATE"
	GoalObjectMutate IntentGoalType = "OBJECT_MUTATE"
	// Gap 13: GoalTransfer and GoalEscrowCreate were removed. Single-leg
	// value transfers and escrow creation both route through GoalSettlement
	// (method=atomic or method=escrow with LegKindEscrow) so the shape
	// doctrine in pkg/settlement runs on every settlement-typed object.
	GoalPolicyBind        IntentGoalType = "POLICY_BIND"
	GoalCapabilityGrant   IntentGoalType = "CAPABILITY_GRANT"
	GoalWorkflowStart     IntentGoalType = "WORKFLOW_START"
	GoalCredentialIssue   IntentGoalType = "CREDENTIAL_ISSUE"
	GoalCredentialRevoke  IntentGoalType = "CREDENTIAL_REVOKE"
	GoalVaultCreate       IntentGoalType = "VAULT_CREATE"
	GoalSettlement        IntentGoalType = "SETTLEMENT"
	GoalSettlementNetting IntentGoalType = "SETTLEMENT_NETTING"
	GoalObjectTransition  IntentGoalType = "OBJECT_TRANSITION"
	GoalPolicyChange      IntentGoalType = "POLICY_CHANGE"
	GoalContractUpgrade   IntentGoalType = "CONTRACT_UPGRADE"
	GoalPatchPropagation  IntentGoalType = "PATCH_PROPAGATION"
	GoalRevertTransaction IntentGoalType = "REVERT_TRANSACTION"

	// Role governance intent types (G-10 Phase 9)
	GoalRoleAssign    IntentGoalType = "ROLE_ASSIGN"
	GoalRoleRevoke    IntentGoalType = "ROLE_REVOKE"
	GoalRoleSuspend   IntentGoalType = "ROLE_SUSPEND"
	GoalRoleEmergency IntentGoalType = "ROLE_EMERGENCY"
	GoalRoleNormalize IntentGoalType = "ROLE_NORMALIZE"

	// Disclosure governance intent types (G-13 Phase 9)
	GoalDisclosureGrant  IntentGoalType = "DISCLOSURE_GRANT"
	GoalDisclosureRevoke IntentGoalType = "DISCLOSURE_REVOKE"

	// Contract lifecycle (Phase 4 — all contract ops enter through intent)
	GoalContractDeploy IntentGoalType = "CONTRACT_DEPLOY"
	GoalContractCall   IntentGoalType = "CONTRACT_CALL"

	// Swarm operations (Phase 4 — governable multi-contract coordination)
	GoalSwarmCreate     IntentGoalType = "SWARM_CREATE"
	GoalSwarmJoin       IntentGoalType = "SWARM_JOIN"
	GoalSwarmCoordinate IntentGoalType = "SWARM_COORDINATE"
	GoalSwarmDissolve   IntentGoalType = "SWARM_DISSOLVE"

	// Shape transitions (Phase 4 — governable adaptive contracts)
	GoalShapeTransition IntentGoalType = "SHAPE_TRANSITION"

	// Bridge operations (Gap 2 — intent universality)
	GoalBridgeSend    IntentGoalType = "BRIDGE_SEND"
	GoalBridgeReceive IntentGoalType = "BRIDGE_RECEIVE"

	// Capability revocation (Gap 2 — inverse of GoalCapabilityGrant)
	GoalCapabilityRevoke IntentGoalType = "CAPABILITY_REVOKE"

	// Policy unbinding (Gap 2 — inverse of GoalPolicyBind)
	GoalPolicyUnbind IntentGoalType = "POLICY_UNBIND"

	// Anchor force (Gap 2 — operator-triggered anchoring)
	GoalAnchorForce IntentGoalType = "ANCHOR_FORCE"

	// Trust profile management (Gap 2 — trust fabric is intent-native)
	GoalTrustProfileCreate IntentGoalType = "TRUST_PROFILE_CREATE"
	GoalTrustProfileUpdate IntentGoalType = "TRUST_PROFILE_UPDATE"

	// System-origin bootstrap intent (Gap 2 closure): creates the initial
	// operator role bindings for a fresh Infrix instance as a typed,
	// evidence-producing spine transition rather than a direct registry
	// write. Bounded by construction to first non-bootstrap block.
	GoalBootstrapRole IntentGoalType = "BOOTSTRAP_ROLE"

	// System-origin periodic anchor intent (Gap 2 closure): routes
	// block-boundary state-root and audit-checkpoint anchor writes
	// through the canonical spine so every AnchoredRecord carries an
	// originating IntentID, PlanID, and EvidenceBundle.
	GoalSystemAnchorPeriodic IntentGoalType = "SYSTEM_ANCHOR_PERIODIC"

	// System-origin approval-invalidation intent (Gap 2 full closure):
	// the InvalidationChecker originates one of these per sweep / cascade
	// event (role-revocation, trust-drift, credential-expiry, periodic
	// scan). The resulting IntentID/PlanID stamp provenance on the
	// ObjectRegistry.Transition that flips approvals to "revoked". No
	// invalidationCtx() synthesised literals.
	GoalApprovalInvalidate IntentGoalType = "APPROVAL_INVALIDATE"

	// System-origin role-expiry intent (Gap 2 full closure): emitted per
	// devnet block-close sweep when the registry is scanned for
	// EffectiveUntil-exceeded RoleBindings. Replaces the inline
	// "intent-role-expiry" / "plan-role-expiry" synthetic IntentContext.
	GoalRoleExpire IntentGoalType = "ROLE_EXPIRE"

	// System-origin capability-expiry intent (Gap 2 full closure):
	// emitted per devnet block-close sweep when CapabilityGrant objects
	// pass their ExpiresAt/ExpiresAtTime. Replaces the hostIntentCtx
	// fallback that assigned "intent-host-system" / "plan-host-system"
	// when grant provenance was absent.
	GoalCapabilityExpire IntentGoalType = "CAPABILITY_EXPIRE"

	// Sponsor governance (Gap 13 fourth-pass closure): the prior path
	// — handleRegisterSponsor RPC → in-memory sponsorRegistry mutation
	// — bypassed the spine entirely. Sponsor configuration grants gas /
	// credit-paying privilege; that grant is now an intent like every
	// other governance privilege grant.
	GoalSponsorRegister IntentGoalType = "SPONSOR_REGISTER"
	GoalSponsorUpdate   IntentGoalType = "SPONSOR_UPDATE"
	GoalSponsorRevoke   IntentGoalType = "SPONSOR_REVOKE"
	GoalSponsorPause    IntentGoalType = "SPONSOR_PAUSE"
	GoalSponsorResume   IntentGoalType = "SPONSOR_RESUME"

	// Dispute resolution (Gap 13 fourth-pass closure): every
	// SettlementShape that declares Failure.RaisesDispute creates an
	// InstructionDispute with Resolution=pending; this intent is the
	// canonical seam by which a designated arbiter binds the dispute
	// to a verdict and triggers the appropriate terminal transition.
	GoalDisputeResolve IntentGoalType = "DISPUTE_RESOLVE"

	// Gap 14 execution-pluralism peer-family goals. The memo names seven
	// execution families that must be equally normalized peers; five of
	// them were previously defined-but-unwired at the plan-step layer. A
	// user-submittable intent now exists for each peer so every family
	// can be reached through the canonical intent → plan → approval →
	// execution → outcome spine, not just through a synthetic plan.
	GoalRulePackEval        IntentGoalType = "RULE_PACK_EVAL"
	GoalVerifierRun         IntentGoalType = "VERIFIER_RUN"
	GoalExternalAdapterCall IntentGoalType = "EXTERNAL_ADAPTER_CALL"
	GoalAgentRun            IntentGoalType = "AGENT_RUN"
	GoalConfidentialExec    IntentGoalType = "CONFIDENTIAL_EXEC"

	// Gap 15 sixth-pass §15 closure — generic admin/operator action
	// envelope for state-mutating /rpc methods (feed.setPrice,
	// immune.{pause,resume,freeze,configure,quarantine,...},
	// temporal.{schedule,scheduleRecurring,cancelSchedule}, swarm.*,
	// shapeshift.register, playground.*, live.*, genome.*, compliance.*,
	// rewind.*, indexer.prune). CustomParams carries
	// {subsystem: "feed"|"immune"|..., action: "setPrice"|"pause"|...,
	// params: map[string]any}. The mediator dispatches via
	// SubsystemActionDispatcher to a per-(subsystem,action) handler
	// registry so every state mutation flows through the canonical spine
	// (intent → plan → policy → execution → outcome → evidence) rather
	// than bypassing the mediator with a direct subsystem call.
	GoalSubsystemAction IntentGoalType = "SUBSYSTEM_ACTION"

	// Spec §5.3 plugin upgrade lifecycle: the canonical governance
	// seam for proposing a plugin descriptor change. The mediator
	// computes the descriptor diff (CapabilityDiff / TrustProfileDiff
	// / PolicyHookDiff / commit-model deltas) via pkg/pluginupgrade,
	// mints a TypeCompatibilityReport in "draft" state, and adds an
	// approval gate sized by the report's RiskClass (admin /
	// policy_authority / security_officer / trust_officer / none).
	// Without this goal type, plugin descriptors could be swapped in
	// at devnet boot with no governance trail; the GoalPluginUpgrade
	// flow makes every compatibility-affecting change a first-class
	// spine event.
	//
	// CustomParams shape:
	//   {pluginId: string, pluginFamily: string,
	//    priorDescriptor: PluginDescriptor, newDescriptor: PluginDescriptor}
	GoalPluginUpgrade IntentGoalType = "PLUGIN_UPGRADE"

	// G-19 phase 5 (spec §5.1): plugin admission lifecycle. Replaces
	// boot-time code-only plugin registration with a typed system
	// intent that drives each plugin through the canonical mediator
	// + admission policy + approval pipeline. Boot wires plugins as
	// pending; the GoalPluginRegister intent transitions them to
	// LifecycleActive only after admission policy clears. A
	// misconfigured plugin (bad ImplementationHash, unknown
	// ConfidentialityProfile, missing CostProfile.Tier) fails boot
	// at admission rather than at first dispatch — tighter loop,
	// earlier failure, full evidence trail.
	//
	// CustomParams shape:
	//   {pluginId: string, pluginFamily: string,
	//    descriptor: PluginDescriptor (canonical, pre-validated)}
	GoalPluginRegister IntentGoalType = "PLUGIN_REGISTER"

	// G-24 closed-loop operational controls. Both controllers
	// (GasController, RateLimitController) observe runtime signals,
	// classify the regime, and propose typed governance intents that
	// flow through the canonical mediator + admission policy pipeline.
	// The controllers never mutate operational parameters directly —
	// every adjustment leaves an evidence trail.
	//
	// CustomParams shape (gas):
	//   {newTier: "normal"|"elevated"|"severe"|"critical",
	//    snapshot: {executeP95Ms: uint, journalLagBytes: uint, ...},
	//    reason: string}
	GoalGasScheduleUpdate IntentGoalType = "GAS_SCHEDULE_UPDATE"

	// CustomParams shape (rate-limit):
	//   {action: "bind"|"unbind"|"profile_update",
	//    actorId: string,           // for bind/unbind
	//    tier: "default"|"elevated_friction"|"throttled",
	//    reason: string,
	//    expiresAt: uint64,         // for bind, unix seconds
	//    profile: {...}}            // for profile_update
	GoalRateLimitUpdate IntentGoalType = "RATE_LIMIT_UPDATE"

	// G-25 phase 1c — operator-initiated session-key delegation.
	// The operator (via the wallet's hardware key) authorizes a
	// freshly-generated ED25519 session key to act on their behalf
	// for a narrowly-scoped purpose ("approval") and a bounded
	// lifetime (≤ 1h) so repeat operations don't require 50
	// hardware-key prompts. Compiles to a TypeCapabilityGrant
	// object with Purpose=approval, WorkflowStageScope=
	// current_session, and ExpiresAt = now + maxLifetimeSeconds.
	//
	// CustomParams shape:
	//   {sessionPubKey: hex(32-byte ED25519 pubkey),
	//    maxLifetimeSeconds: uint64 (≤ 3600),
	//    grantId: string (defaults to "session-<intentID>")}
	GoalSessionKeyDelegate IntentGoalType = "SESSION_KEY_DELEGATE"
)

// ValidGoalTypes is the set of all valid goal types.
var ValidGoalTypes = map[IntentGoalType]bool{
	GoalConvert: true, GoalEarnYield: true, GoalBorrow: true,
	GoalProvideLiquidity: true, GoalSwap: true, GoalStake: true,
	GoalBridge: true, GoalCompound: true, GoalCustom: true,
	GoalObjectCreate: true, GoalObjectMutate: true,
	GoalPolicyBind: true, GoalCapabilityGrant: true, GoalWorkflowStart: true,
	GoalCredentialIssue: true, GoalCredentialRevoke: true, GoalVaultCreate: true, GoalSettlement: true,
	GoalSettlementNetting:    true,
	GoalObjectTransition:     true,
	GoalPolicyChange:         true,
	GoalContractUpgrade:      true,
	GoalPatchPropagation:     true,
	GoalRevertTransaction:    true,
	GoalRoleAssign:           true,
	GoalRoleRevoke:           true,
	GoalRoleSuspend:          true,
	GoalRoleEmergency:        true,
	GoalRoleNormalize:        true,
	GoalDisclosureGrant:      true,
	GoalDisclosureRevoke:     true,
	GoalContractDeploy:       true,
	GoalContractCall:         true,
	GoalSwarmCreate:          true,
	GoalSwarmJoin:            true,
	GoalSwarmCoordinate:      true,
	GoalSwarmDissolve:        true,
	GoalShapeTransition:      true,
	GoalBridgeSend:           true,
	GoalBridgeReceive:        true,
	GoalCapabilityRevoke:     true,
	GoalPolicyUnbind:         true,
	GoalAnchorForce:          true,
	GoalTrustProfileCreate:   true,
	GoalTrustProfileUpdate:   true,
	GoalBootstrapRole:        true,
	GoalSystemAnchorPeriodic: true,
	GoalApprovalInvalidate:   true,
	GoalRoleExpire:           true,
	GoalCapabilityExpire:     true,
	GoalSponsorRegister:      true,
	GoalSponsorUpdate:        true,
	GoalSponsorRevoke:        true,
	GoalSponsorPause:         true,
	GoalSponsorResume:        true,
	GoalDisputeResolve:       true,
	GoalRulePackEval:         true,
	GoalVerifierRun:          true,
	GoalExternalAdapterCall:  true,
	GoalAgentRun:             true,
	GoalConfidentialExec:     true,
	GoalSubsystemAction:      true,
	GoalPluginUpgrade:        true,
	GoalPluginRegister:       true,
	// G-24 closed-loop operational controls.
	GoalGasScheduleUpdate: true,
	GoalRateLimitUpdate:   true,
	// G-25 session-key delegation.
	GoalSessionKeyDelegate: true,
}

// OptimizationTarget identifies the primary optimization goal.
type OptimizationTarget string

const (
	OptimizeMinCost   OptimizationTarget = "minimize_cost"
	OptimizeMaxOutput OptimizationTarget = "maximize_output"
	OptimizeMaxSafety OptimizationTarget = "maximize_safety"
	OptimizeBalanced  OptimizationTarget = "balanced"
	OptimizeMinSteps  OptimizationTarget = "minimize_steps"
	OptimizeCustom    OptimizationTarget = "custom"
)

// Intent is the parsed, validated user intent.
type Intent struct {
	ID              string            `json:"id"`
	UserAddress     string            `json:"userAddress"`
	Goal            IntentGoal        `json:"goal"`
	Constraints     IntentConstraints `json:"constraints"`
	Preferences     IntentPreferences `json:"preferences"`
	RawInput        string            `json:"rawInput,omitempty"`
	ParseConfidence float64           `json:"parseConfidence"`
	Confirmed       bool              `json:"confirmed"`
	CreatedAt       int64             `json:"createdAt"`
	ExpiresAt       int64             `json:"expiresAt,omitempty"`
	BlockHeight     uint64            `json:"blockHeight"`
	Metadata        map[string]string `json:"metadata,omitempty"`

	// Gap 6A: explicit forward link to the plan produced from this intent.
	// Populated by the intent pipeline after plan compilation completes.
	// Enables graph reconstruction from the struct alone without
	// requiring a RelationshipStore lookup.
	ResolvedPlanID string `json:"resolvedPlanId,omitempty"`
}

// IntentGoal describes the desired outcome.
type IntentGoal struct {
	Type         IntentGoalType         `json:"type"`
	SourceAssets []AssetAmount          `json:"sourceAssets"`
	TargetAssets []AssetAmount          `json:"targetAssets,omitempty"`
	TargetState  *TargetStateSpec       `json:"targetState,omitempty"`
	Via          string                 `json:"via,omitempty"`
	CustomType   string                 `json:"customType,omitempty"`
	CustomParams map[string]interface{} `json:"customParams,omitempty"`
}

// AssetAmount identifies a specific token and quantity.
type AssetAmount struct {
	Asset         string `json:"asset"`
	Amount        uint64 `json:"amount"`
	AmountDecimal string `json:"amountDecimal,omitempty"`
	IsMinimum     bool   `json:"isMinimum,omitempty"`
	IsMaximum     bool   `json:"isMaximum,omitempty"`
	TokenStandard string `json:"tokenStandard,omitempty"`
	ContractURL   string `json:"contractUrl,omitempty"`
}

// TargetStateSpec describes a desired on-chain state.
type TargetStateSpec struct {
	StateType  string            `json:"stateType"`
	Parameters map[string]string `json:"parameters"`
	Contract   string            `json:"contract,omitempty"`
}

// IntentConstraints are hard limits that disqualify paths.
type IntentConstraints struct {
	MinOutput            uint64   `json:"minOutput,omitempty"`
	MinOutputDecimal     string   `json:"minOutputDecimal,omitempty"`
	MaxGas               uint64   `json:"maxGas,omitempty"`
	MaxCredits           uint64   `json:"maxCredits,omitempty"`
	MinConfidence        float64  `json:"minConfidence,omitempty"`
	MinAverageConfidence float64  `json:"minAvgConfidence,omitempty"`
	MaxSteps             int      `json:"maxSteps,omitempty"`
	MaxSlippage          float64  `json:"maxSlippage,omitempty"`
	RequiredContracts    []string `json:"requiredContracts,omitempty"`
	ExcludedContracts    []string `json:"excludedContracts,omitempty"`
	Deadline             int64    `json:"deadline,omitempty"`
	AllowedImmuneStates  []string `json:"allowedImmuneStates,omitempty"`
}

// IntentPreferences are soft optimization targets for ranking.
type IntentPreferences struct {
	Optimize        OptimizationTarget `json:"optimize"`
	CustomWeights   map[string]float64 `json:"customWeights,omitempty"`
	PreferContracts []string           `json:"preferContracts,omitempty"`
	AvoidContracts  []string           `json:"avoidContracts,omitempty"`
	MaxAlternatives int                `json:"maxAlternatives,omitempty"`
}

// ParseResult is the output of the intent parser.
type ParseResult struct {
	Intent     *Intent           `json:"intent,omitempty"`
	Confidence float64           `json:"confidence"`
	Ambiguous  bool              `json:"ambiguous"`
	Candidates []IntentCandidate `json:"candidates,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
	// Description is a human-readable render of the parsed intent
	// (e.g., "TRANSFER 100 ACME -> at least 95 USD via CompoundV3").
	// Populated by ParseNaturalLanguage via DescribeIntent so RPC
	// + CLI consumers can echo what was parsed without re-rendering.
	// P1-J closure (2026-05-07).
	Description string `json:"description,omitempty"`
}

// IntentCandidate is one possible interpretation of an ambiguous input.
type IntentCandidate struct {
	Intent      *Intent `json:"intent"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}
