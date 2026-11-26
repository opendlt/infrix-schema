// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser is a recursive descent parser for policy condition expressions.
// It supports all operand namespaces: env, actor, scope, time, approval.
type Parser struct {
	tokens []Token
	pos    int
}

// NewParser creates a parser from tokens.
func NewParser(tokens []Token) *Parser {
	return &Parser{tokens: tokens}
}

// Parse parses the full condition expression and returns the AST root.
func (p *Parser) Parse() (ConditionNode, error) {
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}

	// Check for FOR N BLOCKS duration qualifier
	if p.current().Type == TokFor {
		p.advance() // skip FOR
		if p.current().Type != TokNumber {
			return nil, fmt.Errorf("expected block count after FOR at position %d", p.current().Pos)
		}
		blocks := uint64(p.current().IntVal)
		p.advance() // skip number
		if p.current().Type == TokBlocks {
			p.advance() // skip BLOCKS (optional)
		}
		node = &DurationNode{Condition: node, Blocks: blocks}
	}

	// The whole input is the expression. Trailing tokens used to be dropped without a word, so a condition meant something other than
	// its text.
	if p.current().Type != TokEOF {
		return nil, fmt.Errorf("unexpected token '%s' at position %d after the expression", p.current().Value, p.current().Pos)
	}
	return node, nil
}

func (p *Parser) parseOr() (ConditionNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.current().Type == TokOr {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &BinaryOpNode{Op: BinaryOr, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseAnd() (ConditionNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.current().Type == TokAnd {
		p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &BinaryOpNode{Op: BinaryAnd, Left: left, Right: right}
	}
	return left, nil
}

func (p *Parser) parseNot() (ConditionNode, error) {
	if p.current().Type == TokNot {
		p.advance()
		operand, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		return &UnaryOpNode{Op: UnaryNot, Operand: operand}, nil
	}
	return p.parseComparison()
}

func (p *Parser) parseComparison() (ConditionNode, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	var op ComparisonOp
	switch p.current().Type {
	case TokEqEq:
		op = CmpEq
	case TokNotEq:
		op = CmpNeq
	case TokGt:
		op = CmpGt
	case TokLt:
		op = CmpLt
	case TokGte:
		op = CmpGte
	case TokLte:
		op = CmpLte
	default:
		return left, nil
	}
	p.advance()

	right, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return &ComparisonNode{Op: op, Left: left, Right: right}, nil
}

func (p *Parser) parsePrimary() (ConditionNode, error) {
	tok := p.current()

	switch tok.Type {
	case TokNumber:
		p.advance()
		return &LiteralNode{ValueType: LitInt, IntValue: tok.IntVal}, nil

	case TokFloat:
		p.advance()
		return &LiteralNode{ValueType: LitFloat, FloatValue: tok.FltVal}, nil

	case TokString:
		p.advance()
		return &LiteralNode{ValueType: LitString, StrValue: tok.Value}, nil

	case TokBool:
		p.advance()
		return &LiteralNode{ValueType: LitBool, BoolValue: tok.BoolVal}, nil

	case TokLParen:
		p.advance()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.current().Type != TokRParen {
			return nil, fmt.Errorf("expected ')' at position %d", p.current().Pos)
		}
		p.advance()
		return node, nil

	case TokIdent:
		return p.parseIdentOrCall()

	default:
		return nil, fmt.Errorf("unexpected token '%s' at position %d", tok.Value, tok.Pos)
	}
}

func (p *Parser) parseIdentOrCall() (ConditionNode, error) {
	name := p.current().Value
	p.advance()

	// Check for namespace::operand pattern
	if p.current().Type == TokColonColon {
		p.advance()
		if p.current().Type != TokIdent {
			return nil, fmt.Errorf("expected an operand name after %s:: at position %d", name, p.current().Pos)
		}
		funcName := p.current().Value
		p.advance()

		// Parse arguments: value tokens separated by commas, closed by ')'. Any other token used to become an argument, and an unclosed
		// list ran to the end of the input.
		var args []string
		if p.current().Type == TokLParen {
			p.advance()
			for p.current().Type != TokRParen {
				switch p.current().Type {
				case TokString, TokNumber, TokFloat, TokIdent, TokBool:
				default:
					return nil, fmt.Errorf("expected an argument or ')' in %s::%s at position %d", name, funcName, p.current().Pos)
				}
				args = append(args, p.current().Value)
				p.advance()
				if p.current().Type == TokComma {
					p.advance()
					if p.current().Type == TokRParen {
						return nil, fmt.Errorf("expected an argument after ',' in %s::%s at position %d", name, funcName, p.current().Pos)
					}
				} else if p.current().Type != TokRParen {
					return nil, fmt.Errorf("expected ',' or ')' in %s::%s at position %d", name, funcName, p.current().Pos)
				}
			}
			p.advance()
		}

		source, ok := ResolveOperandSource(name, funcName)
		if !ok {
			return nil, fmt.Errorf("unknown operand %s::%s at position %d", name, funcName, p.current().Pos)
		}
		return &OperandNode{Source: source, Args: args}, nil
	}

	// Check for aggregation function: AVG(...), MAX(...), etc.
	upper := strings.ToUpper(name)
	if aggFunc, ok := resolveAggregation(upper); ok {
		if p.current().Type != TokLParen {
			return nil, fmt.Errorf("expected '(' after %s at position %d", name, p.current().Pos)
		}
		p.advance() // skip (

		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}

		if p.current().Type != TokComma {
			return nil, fmt.Errorf("expected ',' in %s at position %d", name, p.current().Pos)
		}
		p.advance()

		if p.current().Type != TokNumber {
			return nil, fmt.Errorf("expected window size in %s at position %d", name, p.current().Pos)
		}
		windowBlocks, _ := strconv.ParseUint(p.current().Value, 10, 64)
		p.advance()

		// Optional third argument: the window unit ("blocks" | "seconds").
		// Absent → blocks (state-version window; backward-compatible). "seconds"
		// selects a wall-clock window so a rate limit measures real elapsed time
		// even while the canonical version is idle (idle-unless-mutated model).
		windowUnit := AggWindowBlocks
		if p.current().Type == TokComma {
			p.advance()
			// The unit word may lex as a bare identifier ("seconds") or as
			// the reserved duration keyword TokBlocks ("blocks", shared with
			// the `for N blocks` duration grammar). Accept either.
			if p.current().Type != TokIdent && p.current().Type != TokBlocks {
				return nil, fmt.Errorf("expected window unit (blocks|seconds) in %s at position %d", name, p.current().Pos)
			}
			switch strings.ToLower(p.current().Value) {
			case "blocks", "block":
				windowUnit = AggWindowBlocks
			case "seconds", "second", "secs", "sec":
				windowUnit = AggWindowSeconds
			default:
				return nil, fmt.Errorf("unknown aggregation window unit %q at position %d (want blocks|seconds)", p.current().Value, p.current().Pos)
			}
			p.advance()
		}

		if p.current().Type != TokRParen {
			return nil, fmt.Errorf("expected ')' closing %s at position %d", name, p.current().Pos)
		}
		p.advance()

		return &AggregationNode{Function: aggFunc, Operand: operand, WindowBlocks: windowBlocks, WindowUnit: windowUnit}, nil
	}

	// Plain identifier (variable reference)
	return &LiteralNode{ValueType: LitString, StrValue: name}, nil
}

func (p *Parser) current() Token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return Token{Type: TokEOF}
}

func (p *Parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}

func resolveAggregation(name string) (AggregationFunc, bool) {
	switch name {
	case "AVG":
		return AggAvg, true
	case "MAX":
		return AggMax, true
	case "MIN":
		return AggMin, true
	case "STDDEV":
		return AggStdDev, true
	case "SUM":
		return AggSum, true
	case "COUNT":
		return AggCount, true
	}
	return 0, false
}

// ParseExpression lexes and parses a policy condition expression string.
func ParseExpression(expr string) (ConditionNode, error) {
	lexer := NewLexer(expr)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return nil, fmt.Errorf("lex error: %w", err)
	}
	parser := NewParser(tokens)
	return parser.Parse()
}
