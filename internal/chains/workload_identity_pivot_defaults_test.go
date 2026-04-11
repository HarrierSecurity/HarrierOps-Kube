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

func TestEvaluateWorkloadIdentityDefaultRowAllowsExactEnvPatchRowsOnceAllGatesAreMet(t *testing.T) {
	for _, surface := range []string{
		"image",
		"command",
		"args",
		"env",
		"mounted secret refs",
		"mounted config refs",
		"init containers",
	} {
		t.Run(surface, func(t *testing.T) {
			got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowPatchSpecificSurface,
				ExactActionProven:           true,
				VisibleSurface:              surface,
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
			})
			if !got.AllowedDefault {
				t.Fatalf("AllowedDefault = false, want true: %s", got.Reason)
			}
			if got.SuppressDefault {
				t.Fatalf("SuppressDefault = true, want false: %s", got.Reason)
			}
		})
	}
}

func TestEvaluateWorkloadIdentityDefaultRowKeepsPatchSpecificRowsOutUntilEligibilityIsHonest(t *testing.T) {
	testCases := []struct {
		name   string
		inputs WorkloadIdentityDefaultRowInputs
	}{
		{
			name: "missing exact action",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowPatchSpecificSurface,
				VisibleSurface:              "env",
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
			},
		},
		{
			name: "unsafe surface",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowPatchSpecificSurface,
				ExactActionProven:           true,
				VisibleSurface:              "service account",
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
			},
		},
		{
			name: "thin visibility",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowPatchSpecificSurface,
				ExactActionProven:           true,
				VisibleSurface:              "env",
				VisibilityTier:              "low",
				ConfidenceBoundaryAvailable: true,
			},
		},
		{
			name: "missing confidence boundary",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:              WorkloadIdentityRowPatchSpecificSurface,
				ExactActionProven: true,
				VisibleSurface:    "env",
				VisibilityTier:    "high",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateWorkloadIdentityDefaultRow(tc.inputs)
			if got.AllowedDefault {
				t.Fatalf("AllowedDefault = true, want false for %s", tc.name)
			}
			if !got.SuppressDefault {
				t.Fatalf("SuppressDefault = false, want true for %s", tc.name)
			}
		})
	}
}

func TestEvaluateWorkloadIdentityDefaultRowKeepsRiskierRowsOutByDefault(t *testing.T) {
	for _, kind := range []WorkloadIdentityRowKind{
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

func TestEvaluateWorkloadIdentityDefaultRowKeepsSidecarRowsOutUntilInsertionSemanticsAreHonest(t *testing.T) {
	got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
		Kind:                        WorkloadIdentityRowAddSidecar,
		ExactActionProven:           true,
		VisibleSurface:              "sidecars",
		VisibilityTier:              "high",
		ConfidenceBoundaryAvailable: true,
	})
	if got.AllowedDefault {
		t.Fatalf("AllowedDefault = true, want false: %s", got.Reason)
	}
	if !got.SuppressDefault {
		t.Fatalf("SuppressDefault = false, want true: %s", got.Reason)
	}
	want := "Keep out of default output until the family can prove honest insertion of a new sidecar, not just changeable sidecar-related workload surfaces."
	if got.Reason != want {
		t.Fatalf("Reason = %q, want %q", got.Reason, want)
	}
}

func TestEvaluateWorkloadIdentityDefaultRowAllowsExactServiceAccountSwitchRowsOnceAllGatesAreMet(t *testing.T) {
	got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
		Kind:                        WorkloadIdentityRowSwitchServiceAccount,
		ExactActionProven:           true,
		VisibleSurface:              "service account",
		VisibilityTier:              "high",
		ConfidenceBoundaryAvailable: true,
		ExactTargetNamed:            true,
	})
	if !got.AllowedDefault {
		t.Fatalf("AllowedDefault = false, want true: %s", got.Reason)
	}
	if got.SuppressDefault {
		t.Fatalf("SuppressDefault = true, want false: %s", got.Reason)
	}
}

func TestEvaluateWorkloadIdentityDefaultRowAllowsBoundedServiceAccountFallbackRows(t *testing.T) {
	got := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
		Kind:                        WorkloadIdentityRowSwitchServiceAccount,
		ExactActionProven:           true,
		VisibleSurface:              "service account",
		VisibilityTier:              "high",
		ConfidenceBoundaryAvailable: true,
		WeakerFallbackAvailable:     true,
	})
	if !got.AllowedDefault {
		t.Fatalf("AllowedDefault = false, want true: %s", got.Reason)
	}
	if got.SuppressDefault {
		t.Fatalf("SuppressDefault = true, want false: %s", got.Reason)
	}
}

func TestEvaluateWorkloadIdentityDefaultRowKeepsServiceAccountSwitchRowsOutUntilEligibilityIsHonest(t *testing.T) {
	testCases := []struct {
		name   string
		inputs WorkloadIdentityDefaultRowInputs
	}{
		{
			name: "missing exact action",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowSwitchServiceAccount,
				VisibleSurface:              "service account",
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
				ExactTargetNamed:            true,
			},
		},
		{
			name: "wrong visible surface",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowSwitchServiceAccount,
				ExactActionProven:           true,
				VisibleSurface:              "env",
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
				ExactTargetNamed:            true,
			},
		},
		{
			name: "thin visibility",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowSwitchServiceAccount,
				ExactActionProven:           true,
				VisibleSurface:              "service account",
				VisibilityTier:              "low",
				ConfidenceBoundaryAvailable: true,
				ExactTargetNamed:            true,
			},
		},
		{
			name: "missing confidence boundary",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:              WorkloadIdentityRowSwitchServiceAccount,
				ExactActionProven: true,
				VisibleSurface:    "service account",
				VisibilityTier:    "high",
				ExactTargetNamed:  true,
			},
		},
		{
			name: "no exact target and no bounded fallback",
			inputs: WorkloadIdentityDefaultRowInputs{
				Kind:                        WorkloadIdentityRowSwitchServiceAccount,
				ExactActionProven:           true,
				VisibleSurface:              "service account",
				VisibilityTier:              "high",
				ConfidenceBoundaryAvailable: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateWorkloadIdentityDefaultRow(tc.inputs)
			if got.AllowedDefault {
				t.Fatalf("AllowedDefault = true, want false for %s", tc.name)
			}
			if !got.SuppressDefault {
				t.Fatalf("SuppressDefault = false, want true for %s", tc.name)
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
