package chains

import "testing"

func TestClassifyWorkloadIdentityVisibilityReturnsHighWhenWholePathIsVisible(t *testing.T) {
	got, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
		WorkloadVisible:         true,
		SubversionPointVisible:  true,
		AttachedIdentityVisible: true,
		StrongerControlVisible:  true,
		VisibleChangeSurfaces:   true,
	})
	if !ok {
		t.Fatal("ClassifyWorkloadIdentityVisibility() ok = false, want true")
	}
	if got.Tier != "high" {
		t.Fatalf("Tier = %q, want high", got.Tier)
	}
	if got.SuppressDefault {
		t.Fatal("SuppressDefault = true, want false")
	}
	want := "Current scope can see the workload-side lever, the stronger identity, the downstream control behind this path, and the visible change surfaces on the workload."
	if got.OperatorWording != want {
		t.Fatalf("OperatorWording = %q, want %q", got.OperatorWording, want)
	}
}

func TestClassifyWorkloadIdentityVisibilityReturnsMediumWhenLeverIsStillMissing(t *testing.T) {
	got, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
		WorkloadVisible:         true,
		AttachedIdentityVisible: true,
		StrongerControlVisible:  true,
	})
	if !ok {
		t.Fatal("ClassifyWorkloadIdentityVisibility() ok = false, want true")
	}
	if got.Tier != "medium" {
		t.Fatalf("Tier = %q, want medium", got.Tier)
	}
	if got.SuppressDefault {
		t.Fatal("SuppressDefault = true, want false")
	}
	want := "Current scope can see the workload and stronger identity story, but it does not yet show the exact workload-side lever."
	if got.OperatorWording != want {
		t.Fatalf("OperatorWording = %q, want %q", got.OperatorWording, want)
	}
}

func TestClassifyWorkloadIdentityVisibilityReturnsLowAndSuppressesThinRows(t *testing.T) {
	got, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
		WorkloadVisible:         true,
		AttachedIdentityVisible: true,
	})
	if !ok {
		t.Fatal("ClassifyWorkloadIdentityVisibility() ok = false, want true")
	}
	if got.Tier != "low" {
		t.Fatalf("Tier = %q, want low", got.Tier)
	}
	if !got.SuppressDefault {
		t.Fatal("SuppressDefault = false, want true")
	}
	want := "Current scope can see a workload-linked clue, but not enough surrounding path detail to treat it like a default pivot."
	if got.OperatorWording != want {
		t.Fatalf("OperatorWording = %q, want %q", got.OperatorWording, want)
	}
}

func TestClassifyWorkloadIdentityVisibilityKeepsExactLowVisibilityRowsAvailable(t *testing.T) {
	got, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
		WorkloadVisible:   true,
		ExactBlockerKnown: true,
		NextReviewSet:     true,
	})
	if !ok {
		t.Fatal("ClassifyWorkloadIdentityVisibility() ok = false, want true")
	}
	if got.Tier != "low" {
		t.Fatalf("Tier = %q, want low", got.Tier)
	}
	if got.SuppressDefault {
		t.Fatal("SuppressDefault = true, want false")
	}
	want := "Current scope can see a workload-linked clue, but visibility is still too thin to treat it like a default pivot until that blocker is cleared."
	if got.OperatorWording != want {
		t.Fatalf("OperatorWording = %q, want %q", got.OperatorWording, want)
	}
}

func TestClassifyWorkloadIdentityVisibilityRequiresVisibleWorkload(t *testing.T) {
	if got, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{}); ok || got.Tier != "" {
		t.Fatalf("ClassifyWorkloadIdentityVisibility(empty) = %#v, %v; want zero false", got, ok)
	}
}
