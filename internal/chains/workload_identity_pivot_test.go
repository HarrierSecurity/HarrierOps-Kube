package chains

import (
	"testing"

	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
)

func TestBuildWorkloadIdentityPivotOutputBuildsTokenPathVisibleRow(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                 "pod:default:fox-admin",
				Name:               "fox-admin",
				Namespace:          "default",
				ServiceAccountName: "fox-admin",
				Priority:           "high",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:               "serviceaccount:default:fox-admin",
				Name:             "fox-admin",
				Namespace:        "default",
				RelatedWorkloads: []string{"default/fox-admin"},
				PowerSummary:     "has cluster-wide admin-like access",
				TokenPosture:     "token auto-mount is visible on 1 attached workload; legacy token secret is visible",
				Priority:         "high",
			},
		},
		Secrets: []model.SecretPath{
			{
				ID:               "secret-path:default:fox-admin:secret:fox-admin-token",
				LikelySecretType: "service-account token",
				RelatedWorkloads: []string{"default/fox-admin"},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}
	if output.Family != "workload-identity-pivot" {
		t.Fatalf("Family = %q, want workload-identity-pivot", output.Family)
	}
	if len(output.Paths) != 1 {
		t.Fatalf("len(Paths) = %d, want 1", len(output.Paths))
	}
	if output.Paths[0].PathType != "direct control not confirmed" {
		t.Fatalf("PathType = %q, want direct control not confirmed", output.Paths[0].PathType)
	}
	if output.Paths[0].ConfidenceBoundary != "Current scope confirms a workload-linked token path is visible, but runtime inspection is not yet proven." {
		t.Fatalf("ConfidenceBoundary = %q", output.Paths[0].ConfidenceBoundary)
	}
	if output.Paths[0].VisibilityTier != "medium" {
		t.Fatalf("VisibilityTier = %q, want medium", output.Paths[0].VisibilityTier)
	}
}

func TestBuildWorkloadIdentityPivotOutputBuildsExecRowWhenCurrentFootholdCanReachNamespacePods(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                 "pod:storefront:web-5d4f6",
				Name:               "web-5d4f6",
				Namespace:          "storefront",
				ServiceAccountName: "web",
				Priority:           "high",
				PublicExposure:     true,
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:           "serviceaccount:storefront:web",
				Name:         "web",
				Namespace:    "storefront",
				PowerSummary: "can change workloads",
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:namespace/storefront:can-exec-into-pods",
				Scope:         "namespace/storefront",
				ActionSummary: "can exec into pods",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}
	if len(output.Paths) != 1 {
		t.Fatalf("len(Paths) = %d, want 1", len(output.Paths))
	}
	row := output.Paths[0]
	if row.PathType != "direct control visible" {
		t.Fatalf("PathType = %q, want direct control visible", row.PathType)
	}
	if row.VisibilityTier != "high" {
		t.Fatalf("VisibilityTier = %q, want high", row.VisibilityTier)
	}
	if row.SubversionPoint != "exec into pods in namespace storefront" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
}

func TestBuildWorkloadIdentityPivotOutputSuppressesNonNamespacePermissionScopes(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                 "pod:storefront:web-5d4f6",
				Name:               "web-5d4f6",
				Namespace:          "storefront",
				ServiceAccountName: "web",
				Priority:           "high",
				PublicExposure:     true,
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:           "serviceaccount:storefront:web",
				Name:         "web",
				Namespace:    "storefront",
				PowerSummary: "can change workloads",
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:cluster-wide:can-exec-into-pods",
				Scope:         "cluster-wide",
				ActionSummary: "can exec into pods",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}
	if len(output.Paths) != 0 {
		t.Fatalf("len(Paths) = %d, want 0 for non-namespace scope", len(output.Paths))
	}
}
