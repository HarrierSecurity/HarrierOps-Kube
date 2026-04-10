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

func TestWorkloadServiceAccountSwitchWhyStopHereUsesLockedOperatorWording(t *testing.T) {
	if got := workloadServiceAccountSwitchWhyStopHere; got != "current foothold can repoint an already running workload toward a stronger visible identity" {
		t.Fatalf("WorkloadServiceAccountSwitchWhyStopHere() = %q", got)
	}
	if got := workloadServiceAccountFallbackWhyStopHere; got != "current foothold can change the workload identity path, but exact replacement target still needs bounded follow-up" {
		t.Fatalf("WorkloadServiceAccountFallbackWhyStopHere() = %q", got)
	}
}

func TestFormatExactServiceAccountSwitchConfidenceBoundaryUsesPositiveEvidenceBoundary(t *testing.T) {
	got, ok := FormatExactServiceAccountSwitchConfidenceBoundary("default", "default/fox-admin")
	if !ok {
		t.Fatal("FormatExactServiceAccountSwitchConfidenceBoundary() ok = false, want true")
	}

	want := "Current scope confirms the workload service account field is changeable, and namespace default shows one visible replacement service account with stronger downstream control: default/fox-admin."
	if got != want {
		t.Fatalf("FormatExactServiceAccountSwitchConfidenceBoundary() = %q, want %q", got, want)
	}
}

func TestFormatBoundedServiceAccountSwitchConfidenceBoundaryUsesPositiveEvidenceBoundary(t *testing.T) {
	got, ok := FormatBoundedServiceAccountSwitchConfidenceBoundary("default", "default/web")
	if !ok {
		t.Fatal("FormatBoundedServiceAccountSwitchConfidenceBoundary() ok = false, want true")
	}

	want := "Current scope confirms the workload service account field is changeable, and stronger visible service-account paths exist in namespace default beyond default/web."
	if got != want {
		t.Fatalf("FormatBoundedServiceAccountSwitchConfidenceBoundary() = %q, want %q", got, want)
	}
}
