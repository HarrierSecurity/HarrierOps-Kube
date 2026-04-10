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

func TestBuildWorkloadIdentityPivotOutputBuildsExactEnvPatchRowWhenActionAndSurfaceMatchSameWorkload(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "env", "service account"},
				Priority:             "high",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:           "serviceaccount:default:fox-admin",
				Name:         "fox-admin",
				Namespace:    "default",
				PowerSummary: "has cluster-wide admin-like access",
				Priority:     "high",
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-pods",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "pods",
				ActionSummary: "can patch pods",
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
	if row.SubversionPoint != "patch env on workload default/fox-admin" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
	if row.WhyStopHere != WorkloadPatchWhyStopHere() {
		t.Fatalf("WhyStopHere = %q", row.WhyStopHere)
	}
	wantBoundary := "Current scope confirms these workload fields are changeable: image, env, service account."
	if row.ConfidenceBoundary != wantBoundary {
		t.Fatalf("ConfidenceBoundary = %q, want %q", row.ConfidenceBoundary, wantBoundary)
	}
}

func TestBuildWorkloadIdentityPivotOutputDoesNotPromoteControllerPatchIntoExactEnvRow(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "env", "service account"},
				Priority:             "high",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:           "serviceaccount:default:fox-admin",
				Name:         "fox-admin",
				Namespace:    "default",
				PowerSummary: "has cluster-wide admin-like access",
				Priority:     "high",
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-workload-controllers",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "workload-controllers",
				ActionSummary: "can patch workload controllers",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}
	if len(output.Paths) != 0 {
		t.Fatalf("len(Paths) = %d, want 0 when only controller patch is visible", len(output.Paths))
	}
}

func TestBuildWorkloadIdentityPivotOutputBuildsExactServiceAccountSwitchRowWhenOneStrongerCandidateIsVisible(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:web",
				Name:                 "web",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			},
			{
				ID:                   "pod:default:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:             "serviceaccount:default:web",
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			},
			{
				ID:             "serviceaccount:default:fox-admin",
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-pods",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "pods",
				ActionSummary: "can patch pods",
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
	if row.SubversionPoint != "switch workload default/web to service account default/fox-admin" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
	if row.LikelyKubernetesControl != "service account default/fox-admin has cluster-wide admin-like access" {
		t.Fatalf("LikelyKubernetesControl = %q", row.LikelyKubernetesControl)
	}
	wantBoundary := "Current scope confirms the workload service account field is changeable, and namespace default shows one visible replacement service account with stronger downstream control: default/fox-admin."
	if row.ConfidenceBoundary != wantBoundary {
		t.Fatalf("ConfidenceBoundary = %q, want %q", row.ConfidenceBoundary, wantBoundary)
	}
}

func TestBuildWorkloadIdentityPivotOutputBuildsExactServiceAccountSwitchRowWhenOneCandidateHasUniqueHighestRank(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:web",
				Name:                 "web",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			},
			{
				ID:                   "pod:default:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
			{
				ID:                   "pod:default:builder",
				Name:                 "builder",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "builder",
				ServiceAccountPower:  "can change workloads",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "medium",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:             "serviceaccount:default:web",
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			},
			{
				ID:             "serviceaccount:default:fox-admin",
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			},
			{
				ID:             "serviceaccount:default:builder",
				Name:           "builder",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can change workloads",
				Priority:       "high",
				PowerRank:      80,
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-pods",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "pods",
				ActionSummary: "can patch pods",
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
	if row.SubversionPoint != "switch workload default/web to service account default/fox-admin" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
	if row.LikelyKubernetesControl != "service account default/fox-admin has cluster-wide admin-like access" {
		t.Fatalf("LikelyKubernetesControl = %q", row.LikelyKubernetesControl)
	}
	wantBoundary := "Current scope confirms the workload service account field is changeable, and namespace default shows one visible replacement service account with stronger downstream control: default/fox-admin."
	if row.ConfidenceBoundary != wantBoundary {
		t.Fatalf("ConfidenceBoundary = %q, want %q", row.ConfidenceBoundary, wantBoundary)
	}
}

func TestBuildWorkloadIdentityPivotOutputFallsBackToBoundedServiceAccountRepointingWhenTopRankIsAmbiguous(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:web",
				Name:                 "web",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			},
			{
				ID:                   "pod:default:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "can change workloads",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
			{
				ID:                   "pod:default:builder",
				Name:                 "builder",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "builder",
				ServiceAccountPower:  "can create pods",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "medium",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:             "serviceaccount:default:web",
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			},
			{
				ID:             "serviceaccount:default:fox-admin",
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can change workloads",
				Priority:       "high",
				PowerRank:      80,
			},
			{
				ID:             "serviceaccount:default:builder",
				Name:           "builder",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can create pods",
				Priority:       "high",
				PowerRank:      80,
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-pods",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "pods",
				ActionSummary: "can patch pods",
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
	if row.PathType != "workload pivot" {
		t.Fatalf("PathType = %q, want workload pivot", row.PathType)
	}
	if row.SubversionPoint != "review stronger service-account repointing on workload default/web" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
	if row.LikelyKubernetesControl != "visible replacement identities include can create pods, can change workloads" {
		t.Fatalf("LikelyKubernetesControl = %q", row.LikelyKubernetesControl)
	}
	if row.MissingConfirmation != "Current scope does not justify naming one exact replacement service account yet." {
		t.Fatalf("MissingConfirmation = %q", row.MissingConfirmation)
	}
}

func TestBuildWorkloadIdentityPivotOutputSupportsControllerBasedServiceAccountRepointing(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "deployment:apps:storefront:web",
				Name:                 "web",
				Namespace:            "apps",
				Kind:                 "Deployment",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			},
			{
				ID:                   "deployment:apps:fox-admin",
				Name:                 "fox-admin",
				Namespace:            "apps",
				Kind:                 "Deployment",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
			{
				ID:                   "pod:apps:debug",
				Name:                 "debug",
				Namespace:            "apps",
				Kind:                 "Pod",
				ServiceAccountName:   "debug",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "low",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:             "serviceaccount:apps:web",
				Name:           "web",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			},
			{
				ID:             "serviceaccount:apps:fox-admin",
				Name:           "fox-admin",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			},
			{
				ID:             "serviceaccount:apps:debug",
				Name:           "debug",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "low",
				PowerRank:      100,
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-workload-controllers",
				Scope:         "namespace/apps",
				ActionVerb:    "patch",
				TargetGroup:   "workload-controllers",
				ActionSummary: "can patch workload controllers",
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
	if row.SubversionPoint != "review stronger service-account repointing on workload apps/web" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
	if row.PathType != "workload pivot" {
		t.Fatalf("PathType = %q, want workload pivot", row.PathType)
	}
}

func TestBuildWorkloadIdentityPivotOutputUsesPowerRankInsteadOfSummaryTextForExactServiceAccountSwitch(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			{
				ID:                   "pod:default:web",
				Name:                 "web",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
			{
				ID:                   "pod:default:custom-strong",
				Name:                 "custom-strong",
				Namespace:            "default",
				Kind:                 "Pod",
				ServiceAccountName:   "custom-strong",
				ServiceAccountPower:  "custom stronger wording",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			},
		},
		ServiceAccounts: []model.ServiceAccountPath{
			{
				ID:             "serviceaccount:default:web",
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerRank:      0,
			},
			{
				ID:             "serviceaccount:default:custom-strong",
				Name:           "custom-strong",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "custom stronger wording",
				PowerRank:      95,
			},
		},
		Permissions: []model.PermissionPath{
			{
				ID:            "current-session:user:patch-pods",
				Scope:         "namespace/default",
				ActionVerb:    "patch",
				TargetGroup:   "pods",
				ActionSummary: "can patch pods",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	if len(output.Paths) != 1 {
		t.Fatalf("len(Paths) = %d, want 1", len(output.Paths))
	}
	if output.Paths[0].SubversionPoint != "switch workload default/web to service account default/custom-strong" {
		t.Fatalf("SubversionPoint = %q", output.Paths[0].SubversionPoint)
	}
}
