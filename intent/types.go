package intent

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
	GoalObjectCreate    IntentGoalType = "OBJECT_CREATE"
	GoalObjectMutate    IntentGoalType = "OBJECT_MUTATE"
	GoalTransfer        IntentGoalType = "TRANSFER"
	GoalPolicyBind      IntentGoalType = "POLICY_BIND"
	GoalCapabilityGrant IntentGoalType = "CAPABILITY_GRANT"
	GoalWorkflowStart   IntentGoalType = "WORKFLOW_START"
	GoalCredentialIssue IntentGoalType = "CREDENTIAL_ISSUE"
	GoalVaultCreate     IntentGoalType = "VAULT_CREATE"
	GoalSettlement      IntentGoalType = "SETTLEMENT"
	GoalSettlementNetting IntentGoalType = "SETTLEMENT_NETTING"
	GoalEscrowCreate      IntentGoalType = "ESCROW_CREATE"
	GoalObjectTransition  IntentGoalType = "OBJECT_TRANSITION"
	GoalPolicyChange      IntentGoalType = "POLICY_CHANGE"
	GoalContractUpgrade     IntentGoalType = "CONTRACT_UPGRADE"
	GoalPatchPropagation    IntentGoalType = "PATCH_PROPAGATION"
	GoalRevertTransaction   IntentGoalType = "REVERT_TRANSACTION"

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
)

// ValidGoalTypes is the set of all valid goal types.
var ValidGoalTypes = map[IntentGoalType]bool{
	GoalConvert: true, GoalEarnYield: true, GoalBorrow: true,
	GoalProvideLiquidity: true, GoalSwap: true, GoalStake: true,
	GoalBridge: true, GoalCompound: true, GoalCustom: true,
	GoalObjectCreate: true, GoalObjectMutate: true, GoalTransfer: true,
	GoalPolicyBind: true, GoalCapabilityGrant: true, GoalWorkflowStart: true,
	GoalCredentialIssue: true, GoalVaultCreate: true, GoalSettlement: true,
	GoalSettlementNetting: true,
	GoalEscrowCreate:      true,
	GoalObjectTransition: true,
	GoalPolicyChange:     true,
	GoalContractUpgrade:    true,
	GoalPatchPropagation:   true,
	GoalRevertTransaction:  true,
	GoalRoleAssign:         true,
	GoalRoleRevoke:         true,
	GoalRoleSuspend:        true,
	GoalRoleEmergency:      true,
	GoalRoleNormalize:      true,
	GoalDisclosureGrant:    true,
	GoalDisclosureRevoke:   true,
	GoalContractDeploy:     true,
	GoalContractCall:       true,
	GoalSwarmCreate:        true,
	GoalSwarmJoin:          true,
	GoalSwarmCoordinate:    true,
	GoalSwarmDissolve:       true,
	GoalShapeTransition:    true,
	GoalBridgeSend:         true,
	GoalBridgeReceive:      true,
	GoalCapabilityRevoke:   true,
	GoalPolicyUnbind:       true,
	GoalAnchorForce:        true,
	GoalTrustProfileCreate:   true,
	GoalTrustProfileUpdate:   true,
	GoalBootstrapRole:        true,
	GoalSystemAnchorPeriodic: true,
	GoalApprovalInvalidate:   true,
	GoalRoleExpire:           true,
	GoalCapabilityExpire:     true,
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
}

// IntentCandidate is one possible interpretation of an ambiguous input.
type IntentCandidate struct {
	Intent      *Intent `json:"intent"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
}
