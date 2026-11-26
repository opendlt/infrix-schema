// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import "fmt"

// Compiler compiles a policy condition AST into bytecode for the VM.
type Compiler struct {
	code         []byte
	literals     []any
	operands     []OperandDescriptor
	aggregations []AggregationDescriptor
	gas          uint64
}

// NewCompiler creates a compiler.
func NewCompiler() *Compiler {
	return &Compiler{}
}

// Compile compiles an AST node into a CompiledCondition.
func (c *Compiler) Compile(node ConditionNode, source string) (*CompiledCondition, error) {
	if err := c.emit(node); err != nil {
		return nil, err
	}
	c.code = append(c.code, byte(OpHalt))

	return &CompiledCondition{
		Bytecode:         c.code,
		Literals:         c.literals,
		Operands:         c.operands,
		Aggregations:     c.aggregations,
		EstimatedGas:     c.gas,
		SourceExpression: source,
	}, nil
}

func (c *Compiler) emit(node ConditionNode) error {
	switch n := node.(type) {
	case *LiteralNode:
		return c.emitLiteral(n)
	case *OperandNode:
		return c.emitOperand(n)
	case *ComparisonNode:
		return c.emitComparison(n)
	case *BinaryOpNode:
		return c.emitBinaryOp(n)
	case *UnaryOpNode:
		return c.emitUnaryOp(n)
	case *AggregationNode:
		return c.emitAggregation(n)
	case *DurationNode:
		// Duration is handled at the rule level, not in bytecode.
		return c.emit(n.Condition)
	default:
		return fmt.Errorf("unknown node type: %T", node)
	}
}

// maxIndexedEntries is how many literals, operands or aggregations one condition can hold: the bytecode addresses each by one byte.
// Past it, byte(idx) would wrap and the VM would read another entry, so the compiler refuses instead.
const maxIndexedEntries = 256

func (c *Compiler) emitLiteral(n *LiteralNode) error {
	idx := len(c.literals)
	if idx >= maxIndexedEntries {
		return fmt.Errorf("condition has more than %d literals", maxIndexedEntries)
	}
	switch n.ValueType {
	case LitInt:
		c.literals = append(c.literals, n.IntValue)
		c.code = append(c.code, byte(OpPushLitInt), byte(idx))
	case LitFloat:
		c.literals = append(c.literals, n.FloatValue)
		c.code = append(c.code, byte(OpPushLitFloat), byte(idx))
	case LitString:
		c.literals = append(c.literals, n.StrValue)
		c.code = append(c.code, byte(OpPushLitStr), byte(idx))
	case LitBool:
		c.literals = append(c.literals, n.BoolValue)
		c.code = append(c.code, byte(OpPushLitBool), byte(idx))
	}
	c.gas++
	return nil
}

func (c *Compiler) emitOperand(n *OperandNode) error {
	idx := len(c.operands)
	if idx >= maxIndexedEntries {
		return fmt.Errorf("condition has more than %d operands", maxIndexedEntries)
	}
	c.operands = append(c.operands, OperandDescriptor{Source: n.Source, Args: n.Args})
	c.code = append(c.code, byte(OpLoadOperand), byte(idx))
	c.gas += 100 // Operand resolution is expensive
	return nil
}

func (c *Compiler) emitComparison(n *ComparisonNode) error {
	if err := c.emit(n.Left); err != nil {
		return err
	}
	if err := c.emit(n.Right); err != nil {
		return err
	}
	switch n.Op {
	case CmpEq:
		c.code = append(c.code, byte(OpCmpEqBC))
	case CmpNeq:
		c.code = append(c.code, byte(OpCmpNeqBC))
	case CmpGt:
		c.code = append(c.code, byte(OpCmpGtBC))
	case CmpLt:
		c.code = append(c.code, byte(OpCmpLtBC))
	case CmpGte:
		c.code = append(c.code, byte(OpCmpGteBC))
	case CmpLte:
		c.code = append(c.code, byte(OpCmpLteBC))
	}
	c.gas += 5
	return nil
}

func (c *Compiler) emitBinaryOp(n *BinaryOpNode) error {
	if err := c.emit(n.Left); err != nil {
		return err
	}
	if err := c.emit(n.Right); err != nil {
		return err
	}
	switch n.Op {
	case BinaryAnd:
		c.code = append(c.code, byte(OpAndBC))
	case BinaryOr:
		c.code = append(c.code, byte(OpOrBC))
	}
	c.gas += 3
	return nil
}

func (c *Compiler) emitUnaryOp(n *UnaryOpNode) error {
	if err := c.emit(n.Operand); err != nil {
		return err
	}
	c.code = append(c.code, byte(OpNotBC))
	c.gas += 2
	return nil
}

func (c *Compiler) emitAggregation(n *AggregationNode) error {
	// Compile the inner operand to get its descriptor.
	if err := c.emit(n.Operand); err != nil {
		return err
	}
	operandIdx := max(len(c.operands)-1, 0)

	opDesc := c.operands[operandIdx]
	aggIdx := len(c.aggregations)
	if aggIdx >= maxIndexedEntries {
		return fmt.Errorf("condition has more than %d aggregations", maxIndexedEntries)
	}
	c.aggregations = append(c.aggregations, AggregationDescriptor{
		Function:     n.Function,
		Source:       opDesc.Source,
		Args:         opDesc.Args,
		WindowBlocks: n.WindowBlocks,
		WindowUnit:   n.WindowUnit,
	})
	c.code = append(c.code, byte(OpLoadAgg), byte(aggIdx))
	c.gas += 500 // Aggregations are very expensive
	return nil
}

// CompileExpression parses and compiles a policy expression in one step.
func CompileExpression(expr string) (*CompiledCondition, error) {
	node, err := ParseExpression(expr)
	if err != nil {
		return nil, err
	}
	compiler := NewCompiler()
	return compiler.Compile(node, expr)
}
