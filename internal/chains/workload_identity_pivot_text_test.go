package chains

import "testing"

func TestWorkloadPatchWhyStopHereUsesLockedOperatorWording(t *testing.T) {
	if got := WorkloadPatchWhyStopHere(); got != "current foothold can change an already running workload with stronger identity" {
		t.Fatalf("WorkloadPatchWhyStopHere() = %q", got)
	}
}

func TestFormatWorkloadPatchConfidenceBoundaryUsesPositiveEvidenceBoundary(t *testing.T) {
	got, ok := FormatWorkloadPatchConfidenceBoundary([]string{
		"sidecars",
		"env",
		"image",
		"service account",
		"env",
		"unknown field",
		"mounted secret refs",
	})
	if !ok {
		t.Fatal("FormatWorkloadPatchConfidenceBoundary() ok = false, want true")
	}

	want := "Current scope confirms these workload fields are changeable: image, env, service account, mounted secret refs, sidecars."
	if got != want {
		t.Fatalf("FormatWorkloadPatchConfidenceBoundary() = %q, want %q", got, want)
	}
}

func TestFormatWorkloadPatchConfidenceBoundarySuppressesEmptySurfaceLists(t *testing.T) {
	if got, ok := FormatWorkloadPatchConfidenceBoundary(nil); ok || got != "" {
		t.Fatalf("FormatWorkloadPatchConfidenceBoundary(nil) = (%q, %v), want empty false", got, ok)
	}

	if got, ok := FormatWorkloadPatchConfidenceBoundary([]string{"unknown field"}); ok || got != "" {
		t.Fatalf("FormatWorkloadPatchConfidenceBoundary(unknown) = (%q, %v), want empty false", got, ok)
	}
}
