// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

// ConditionNode is the AST node interface for policy expressions.
type ConditionNode interface {
	NodeType() ConditionNodeType
}

// ConditionNodeType enumerates AST node types.
type ConditionNodeType int

const (
	NodeBinaryOp ConditionNodeType = iota
	NodeUnaryOp
	NodeComparison
	NodeLiteral
	NodeOperand
	NodeAggregation
	NodeDuration
)

// BinaryOpNode represents AND / OR.
type BinaryOpNode struct {
	Op    BinaryOp
	Left  ConditionNode
	Right ConditionNode
}

func (n *BinaryOpNode) NodeType() ConditionNodeType { return NodeBinaryOp }

// UnaryOpNode represents NOT.
type UnaryOpNode struct {
	Op      UnaryOp
	Operand ConditionNode
}

func (n *UnaryOpNode) NodeType() ConditionNodeType { return NodeUnaryOp }

// ComparisonNode represents left CMP right.
type ComparisonNode struct {
	Op    ComparisonOp
	Left  ConditionNode
	Right ConditionNode
}

func (n *ComparisonNode) NodeType() ConditionNodeType { return NodeComparison }

// LiteralNode represents a constant value.
type LiteralNode struct {
	ValueType  LiteralType
	IntValue   int64
	FloatValue float64
	StrValue   string
	BoolValue  bool
}

func (n *LiteralNode) NodeType() ConditionNodeType { return NodeLiteral }

// OperandNode represents a data source reference (e.g., env::price, actor::role).
type OperandNode struct {
	Source OperandSource
	Args   []string
}

func (n *OperandNode) NodeType() ConditionNodeType { return NodeOperand }

// AggregationNode represents an aggregation over a window. WindowUnit selects the
// window dimension: block height / state version (default) or wall-clock seconds.
type AggregationNode struct {
	Function     AggregationFunc
	Operand      ConditionNode
	WindowBlocks uint64
	WindowUnit   AggregationWindowUnit
}

func (n *AggregationNode) NodeType() ConditionNodeType { return NodeAggregation }

// DurationNode wraps a condition with a FOR N BLOCKS qualifier.
type DurationNode struct {
	Condition ConditionNode
	Blocks    uint64
}

func (n *DurationNode) NodeType() ConditionNodeType { return NodeDuration }
