// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// VM is a stack-based bytecode evaluator for compiled policy conditions.
// It handles all operand categories: environmental, authorization, and approval.
// Operand resolution returns interface{} to support both numeric and string values.
type VM struct {
	stack  []any
	gas    uint64
	maxGas uint64
}

// NewVM creates a VM with the given gas budget.
func NewVM(maxGas uint64) *VM {
	return &VM{maxGas: maxGas}
}

// Evaluate runs a compiled condition and returns the boolean result,
// gas consumed, and any error.
func (vm *VM) Evaluate(cc *CompiledCondition, ctx EvalContext) (bool, uint64, error) {
	vm.stack = vm.stack[:0]
	vm.gas = 0

	ip := 0
	for ip < len(cc.Bytecode) {
		op := ConditionOp(cc.Bytecode[ip])
		ip++

		if vm.gas > vm.maxGas {
			return false, vm.gas, fmt.Errorf("gas budget exceeded: %d > %d", vm.gas, vm.maxGas)
		}

		switch op {
		case OpPushLitInt:
			idx := int(cc.Bytecode[ip])
			ip++
			vm.push(cc.Literals[idx])
			vm.gas++

		case OpPushLitFloat:
			idx := int(cc.Bytecode[ip])
			ip++
			vm.push(cc.Literals[idx])
			vm.gas++

		case OpPushLitStr:
			idx := int(cc.Bytecode[ip])
			ip++
			vm.push(cc.Literals[idx])
			vm.gas++

		case OpPushLitBool:
			idx := int(cc.Bytecode[ip])
			ip++
			vm.push(cc.Literals[idx])
			vm.gas++

		case OpLoadOperand:
			idx := int(cc.Bytecode[ip])
			ip++
			desc := cc.Operands[idx]
			val, err := ctx.ResolveOperand(desc.Source, desc.Args)
			if err != nil {
				return false, vm.gas, err
			}
			vm.push(val)
			vm.gas += 100

		case OpLoadAgg:
			idx := int(cc.Bytecode[ip])
			ip++
			desc := cc.Aggregations[idx]
			// Pop the operand value that was pushed by the inner operand emit.
			if len(vm.stack) > 0 {
				vm.stack = vm.stack[:len(vm.stack)-1]
			}
			val, err := ctx.ResolveAggregation(desc.Function, desc.Source, desc.Args, desc.WindowBlocks, desc.WindowUnit)
			if err != nil {
				return false, vm.gas, err
			}
			vm.push(val)
			vm.gas += 500

		case OpCmpEqBC:
			r, l := vm.pop(), vm.pop()
			vm.push(compareEq(l, r))
			vm.gas += 5
		case OpCmpNeqBC:
			r, l := vm.pop(), vm.pop()
			vm.push(!compareEq(l, r))
			vm.gas += 5
		case OpCmpGtBC:
			r, l := vm.popFloat(), vm.popFloat()
			vm.push(l > r)
			vm.gas += 5
		case OpCmpLtBC:
			r, l := vm.popFloat(), vm.popFloat()
			vm.push(l < r)
			vm.gas += 5
		case OpCmpGteBC:
			r, l := vm.popFloat(), vm.popFloat()
			vm.push(l >= r)
			vm.gas += 5
		case OpCmpLteBC:
			r, l := vm.popFloat(), vm.popFloat()
			vm.push(l <= r)
			vm.gas += 5

		case OpAndBC:
			r, l := vm.popBool(), vm.popBool()
			vm.push(l && r)
			vm.gas += 3
		case OpOrBC:
			r, l := vm.popBool(), vm.popBool()
			vm.push(l || r)
			vm.gas += 3
		case OpNotBC:
			v := vm.popBool()
			vm.push(!v)
			vm.gas += 2

		// String-aware opcodes (Phase 4)
		case OpStrContains:
			substr := vm.popString()
			str := vm.popString()
			vm.push(strings.Contains(str, substr))
			vm.gas += 8
		case OpStrPrefix:
			prefix := vm.popString()
			str := vm.popString()
			vm.push(strings.HasPrefix(str, prefix))
			vm.gas += 8
		case OpStrSuffix:
			suffix := vm.popString()
			str := vm.popString()
			vm.push(strings.HasSuffix(str, suffix))
			vm.gas += 8
		case OpStrMatch:
			pattern := vm.popString()
			str := vm.popString()
			vm.push(globMatch(pattern, str))
			vm.gas += 10

		case OpHalt:
			result := vm.popBool()
			return result, vm.gas, nil

		default:
			return false, vm.gas, fmt.Errorf("unknown opcode: 0x%02x", op)
		}
	}

	if len(vm.stack) == 0 {
		return false, vm.gas, fmt.Errorf("empty stack at end of evaluation")
	}
	return vm.popBool(), vm.gas, nil
}

// GasUsed returns the total gas consumed by the last evaluation.
func (vm *VM) GasUsed() uint64 {
	return vm.gas
}

func (vm *VM) push(v any) {
	vm.stack = append(vm.stack, v)
}

func (vm *VM) pop() any {
	if len(vm.stack) == 0 {
		return nil
	}
	v := vm.stack[len(vm.stack)-1]
	vm.stack = vm.stack[:len(vm.stack)-1]
	return v
}

func (vm *VM) popFloat() float64 {
	return toFloat(vm.pop())
}

func (vm *VM) popBool() bool {
	v := vm.pop()
	switch val := v.(type) {
	case bool:
		return val
	case float64:
		return val != 0
	case int64:
		return val != 0
	case int:
		return val != 0
	case string:
		return val != ""
	default:
		return false
	}
}

// CompareEq is the VM's equality (OpCmpEqBC), exported so the node's other comparisons share it.
func CompareEq(l, r any) bool { return compareEq(l, r) }

// GlobMatch is the VM's glob match (OpStrMatch), exported so the node shares it.
func GlobMatch(pattern, str string) bool { return globMatch(pattern, str) }

// ToFloatPublic converts any value to float64. Exported for use by policy templates.
func ToFloatPublic(v any) float64 { return toFloat(v) }

// toFloat converts an interface value to float64 for numeric comparisons.
func toFloat(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int64:
		return float64(val)
	case int:
		return float64(val)
	case uint64:
		return float64(val)
	case bool:
		if val {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// --- VMValue typed value system (Phase 4) ---

// VMValueType classifies the type of a value on the VM stack.
type VMValueType uint8

const (
	VMTypeNum   VMValueType = iota // float64
	VMTypeStr                      // string
	VMTypeBool                     // bool
	VMTypeBytes                    // []byte
)

// VMValue is a typed wrapper for VM stack values.
type VMValue struct {
	Type  VMValueType
	Num   float64
	Str   string
	Bool  bool
	Bytes []byte
}

// popString pops a value and coerces to string.
func (vm *VM) popString() string {
	v := vm.pop()
	switch val := v.(type) {
	case string:
		return val
	case VMValue:
		return val.Str
	case float64:
		return fmt.Sprintf("%g", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// globMatch performs simple glob matching (* matches any sequence).
func globMatch(pattern, str string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == str
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		return strings.HasPrefix(str, parts[0]) && strings.HasSuffix(str, parts[1])
	}
	// General case: check each part appears in order.
	remaining := str
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}
	return true
}

// compareEq handles equality comparison for both numeric and string values.
// Numeric values use epsilon comparison; strings use exact match.
func compareEq(l, r any) bool {
	// String == String
	ls, lIsStr := l.(string)
	rs, rIsStr := r.(string)
	if lIsStr && rIsStr {
		return ls == rs
	}

	// Bool == Bool
	lb, lIsBool := l.(bool)
	rb, rIsBool := r.(bool)
	if lIsBool && rIsBool {
		return lb == rb
	}

	// A STRING IS NEVER EQUAL TO A NON-STRING BY COERCION.
	//
	// toFloat returns 0 for any string it cannot parse, so falling straight to
	// the numeric path made compareEq(float64(0), "true") report EQUAL — and
	// with it compareEq(0, "false"), compareEq(0, "anything"). Any rule of the
	// form `env::custom_metric(x) == "literal"` therefore FIRED whenever the
	// metric was unresolved, because an unresolved operand resolves to 0.
	//
	// Live effect: the compliance rule pack denied with "actor matched
	// sanctions list — denied" for an actor it had no sanctions data about.
	// The refusal may be defensible; the STATED REASON was a factual claim the
	// node could not support, and it lands in an audit record.
	//
	// A string operand only compares numerically when it actually parses as a
	// number, so "100" == 100 still holds and "true" == 0 does not.
	if lIsStr != rIsStr {
		strSide := ls
		if rIsStr {
			strSide = rs
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(strSide), 64)
		if err != nil {
			return false
		}
		other := l
		if lIsStr {
			other = r
		}
		return math.Abs(toFloat(other)-parsed) < 1e-9
	}

	// Numeric comparison with epsilon
	lf := toFloat(l)
	rf := toFloat(r)
	return math.Abs(lf-rf) < 1e-9
}
