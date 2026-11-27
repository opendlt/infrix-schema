package policyeval

import "testing"

// Moved verbatim from infrix-core pkg/policy vm_string_test.go with the VM body (brief 28bi).

// ---------------------------------------------------------------------------
// popString coercion
// ---------------------------------------------------------------------------

func TestVMUpgrade_PopStringCoercion(t *testing.T) {
	vm := NewVM(10000)

	// String value
	vm.push("hello")
	if vm.popString() != "hello" {
		t.Error("string -> string")
	}

	// Float value
	vm.push(float64(42))
	if vm.popString() != "42" {
		t.Errorf("float -> string: %s", vm.popString())
	}

	// Bool value
	vm.push(true)
	if vm.popString() != "true" {
		t.Error("bool -> string")
	}
}

