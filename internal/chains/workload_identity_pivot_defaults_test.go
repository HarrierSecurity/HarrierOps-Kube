package chains

import "testing"

func TestWorkloadIdentityEarliestDefaultRowKindsMatchesTask12Set(t *testing.T) {
	got := WorkloadIdentityEarliestDefaultRowKinds()
	want := []WorkloadIdentityRowKind{
		WorkloadIdentityRowExecIntoPodsInNamespace,
		WorkloadIdentityRowReadSecretsInNamespace,
		WorkloadIdentityRowTokenPathVisible,
	}

	if len(got) != len(want) {
		t.Fatalf("len(WorkloadIdentityEarliestDefaultRowKinds()) = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("WorkloadIdentityEarliestDefaultRowKinds()[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestEvaluateWorkloadIdentityDefaultRowAllowsTask12SafeDefaults(t *testing.T) {
	for _, kind := range []WorkloadIdentityRowKind{
		WorkloadIdentityRowExecIntoPodsInNamespace,
		WorkloadIdentityRowReadSecretsInNamespace,
		WorkloadIdentityRowTokenPathVisible,
	} {
		t.Run(string(kind), func(t *testing.T) {
			got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{Kind: kind})
			if !got.AllowedDefault {
				t.Fatalf("AllowedDefault = false for %q", kind)
			}
			if got.SuppressDefault {
				t.Fatalf("SuppressDefault = true for %q", kind)
			}
			if got.Reason == "" {
				t.Fatalf("Reason = empty for %q", kind)
			}
		})
	}
}

func TestEvaluateWorkloadIdentityDefaultRowKeepsPatchSpecificRowsOutByDefault(t *testing.T) {
	for _, kind := range []WorkloadIdentityRowKind{
		WorkloadIdentityRowPatchSpecificSurface,
		WorkloadIdentityRowSwitchServiceAccount,
		WorkloadIdentityRowAddSidecar,
	} {
		t.Run(string(kind), func(t *testing.T) {
			got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{Kind: kind})
			if got.AllowedDefault {
				t.Fatalf("AllowedDefault = true for %q, want false", kind)
			}
			if !got.SuppressDefault {
				t.Fatalf("SuppressDefault = false for %q, want true", kind)
			}
		})
	}
}

func TestEvaluateWorkloadIdentityDefaultRowSeparatesTokenVisibilityFromRuntimeInspection(t *testing.T) {
	got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
		Kind:                    WorkloadIdentityRowTokenPathVisible,
		RuntimeInspectionProven: true,
	})
	if got.AllowedDefault {
		t.Fatal("AllowedDefault = true, want false when runtime inspection is already proven")
	}
	if got.SuppressDefault {
		t.Fatal("SuppressDefault = true, want false because this should become a different row type instead")
	}
}

func TestEvaluateWorkloadIdentityDefaultRowSuppressesUnknownRowsUntilProven(t *testing.T) {
	got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
		Kind: WorkloadIdentityRowKind("future-row-type"),
	})
	if got.AllowedDefault {
		t.Fatal("AllowedDefault = true, want false")
	}
	if !got.SuppressDefault {
		t.Fatal("SuppressDefault = false, want true")
	}
}
