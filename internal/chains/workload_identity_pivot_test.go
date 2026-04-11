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
			testPodWorkloadPath(workloadPathSpec{
				Name:                "fox-admin",
				Namespace:           "default",
				ServiceAccountName:  "fox-admin",
				ServiceAccountPower: "has cluster-wide admin-like access",
				PatchRelevantFields: []string{"image", "env", "service account"},
				Priority:            "high",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:         "fox-admin",
				Namespace:    "default",
				PowerSummary: "has cluster-wide admin-like access",
				Priority:     "high",
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	row, ok := chainRowBySubversionPoint(output.Paths, "patch env on workload default/fox-admin")
	if !ok {
		t.Fatalf("missing env patch row in %#v", output.Paths)
	}
	if row.PathType != "direct control visible" {
		t.Fatalf("PathType = %q, want direct control visible", row.PathType)
	}
	if row.VisibilityTier != "high" {
		t.Fatalf("VisibilityTier = %q, want high", row.VisibilityTier)
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
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "fox-admin",
				Namespace:            "default",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "env", "service account"},
				Priority:             "high",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:         "fox-admin",
				Namespace:    "default",
				PowerSummary: "has cluster-wide admin-like access",
				Priority:     "high",
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "workload-controllers", "can patch workload controllers"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}
	if len(output.Paths) != 0 {
		t.Fatalf("len(Paths) = %d, want 0 when only controller patch is visible", len(output.Paths))
	}
}

func TestBuildWorkloadIdentityPivotOutputBuildsExactRowsForSafeVisiblePatchSurfaces(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			testPodWorkloadPath(workloadPathSpec{
				Name:                "fox-admin",
				Namespace:           "default",
				ServiceAccountName:  "fox-admin",
				ServiceAccountPower: "has cluster-wide admin-like access",
				PatchRelevantFields: []string{"image", "command", "args", "env", "service account", "mounted secret refs", "mounted config refs", "init containers", "sidecars"},
				Priority:            "high",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:         "fox-admin",
				Namespace:    "default",
				PowerSummary: "has cluster-wide admin-like access",
				Priority:     "high",
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	got := map[string]bool{}
	for _, row := range output.Paths {
		got[row.SubversionPoint] = true
	}

	for _, want := range []string{
		"patch image on workload default/fox-admin",
		"patch command on workload default/fox-admin",
		"patch args on workload default/fox-admin",
		"patch env on workload default/fox-admin",
		"patch mounted secret refs on workload default/fox-admin",
		"patch mounted config refs on workload default/fox-admin",
		"patch init containers on workload default/fox-admin",
	} {
		if !got[want] {
			t.Fatalf("missing exact patch row %q in %#v", want, got)
		}
	}

	for _, suppressed := range []string{
		"patch service account on workload default/fox-admin",
		"patch sidecars on workload default/fox-admin",
		"patch replicas on workload default/fox-admin",
	} {
		if got[suppressed] {
			t.Fatalf("unexpected suppressed patch row %q in %#v", suppressed, got)
		}
	}
}

func TestBuildWorkloadIdentityPivotOutputBuildsExactServiceAccountSwitchRowWhenOneStrongerCandidateIsVisible(t *testing.T) {
	output, err := BuildWorkloadIdentityPivotOutput(contracts.Metadata{Command: "chains"}, WorkloadIdentityPivotInputs{
		StartingFoothold: "fox-operator (current foothold)",
		Workloads: []model.WorkloadPath{
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "web",
				Namespace:            "default",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "fox-admin",
				Namespace:            "default",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	row, ok := chainRowBySubversionPoint(output.Paths, "switch workload default/web to service account default/fox-admin")
	if !ok {
		t.Fatalf("missing exact service-account switch row in %#v", output.Paths)
	}
	if row.PathType != "direct control visible" {
		t.Fatalf("PathType = %q, want direct control visible", row.PathType)
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
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "web",
				Namespace:            "default",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "fox-admin",
				Namespace:            "default",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "builder",
				Namespace:            "default",
				ServiceAccountName:   "builder",
				ServiceAccountPower:  "can change workloads",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "medium",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "builder",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can change workloads",
				Priority:       "high",
				PowerRank:      80,
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	row, ok := chainRowBySubversionPoint(output.Paths, "switch workload default/web to service account default/fox-admin")
	if !ok {
		t.Fatalf("missing exact service-account switch row in %#v", output.Paths)
	}
	if row.PathType != "direct control visible" {
		t.Fatalf("PathType = %q, want direct control visible", row.PathType)
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
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "web",
				Namespace:            "default",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "fox-admin",
				Namespace:            "default",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "can change workloads",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "builder",
				Namespace:            "default",
				ServiceAccountName:   "builder",
				ServiceAccountPower:  "can create pods",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "medium",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "fox-admin",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can change workloads",
				Priority:       "high",
				PowerRank:      80,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "builder",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "can create pods",
				Priority:       "high",
				PowerRank:      80,
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	row, ok := chainRowBySubversionPoint(output.Paths, "review stronger service-account repointing on workload default/web")
	if !ok {
		t.Fatalf("missing bounded service-account repointing row in %#v", output.Paths)
	}
	if row.PathType != "workload pivot" {
		t.Fatalf("PathType = %q, want workload pivot", row.PathType)
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
			testDeploymentWorkloadPath(workloadPathSpec{
				Name:                 "web",
				Namespace:            "apps",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
				PublicExposure:       true,
			}),
			testDeploymentWorkloadPath(workloadPathSpec{
				Name:                 "fox-admin",
				Namespace:            "apps",
				ServiceAccountName:   "fox-admin",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "debug",
				Namespace:            "apps",
				ServiceAccountName:   "debug",
				ServiceAccountPower:  "has cluster-wide admin-like access",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "low",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "web",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				Priority:       "medium",
				PowerRank:      0,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "fox-admin",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "high",
				PowerRank:      100,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "debug",
				Namespace:      "apps",
				EvidenceStatus: "direct",
				PowerSummary:   "has cluster-wide admin-like access",
				Priority:       "low",
				PowerRank:      100,
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("apps", "patch", "workload-controllers", "can patch workload controllers"),
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
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "web",
				Namespace:            "default",
				ServiceAccountName:   "web",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
			testPodWorkloadPath(workloadPathSpec{
				Name:                 "custom-strong",
				Namespace:            "default",
				ServiceAccountName:   "custom-strong",
				ServiceAccountPower:  "custom stronger wording",
				VisiblePatchSurfaces: []string{"image", "service account"},
				Priority:             "high",
			}),
		},
		ServiceAccounts: []model.ServiceAccountPath{
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "web",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerRank:      0,
			}),
			testServiceAccountPath(serviceAccountPathSpec{
				Name:           "custom-strong",
				Namespace:      "default",
				EvidenceStatus: "direct",
				PowerSummary:   "custom stronger wording",
				PowerRank:      95,
			}),
		},
		Permissions: []model.PermissionPath{
			testCurrentSessionWorkloadChangePermission("default", "patch", "pods", "can patch pods"),
		},
	})
	if err != nil {
		t.Fatalf("BuildWorkloadIdentityPivotOutput() error = %v", err)
	}

	row, ok := chainRowBySubversionPoint(output.Paths, "switch workload default/web to service account default/custom-strong")
	if !ok {
		t.Fatalf("missing exact service-account switch row in %#v", output.Paths)
	}
	if row.SubversionPoint != "switch workload default/web to service account default/custom-strong" {
		t.Fatalf("SubversionPoint = %q", row.SubversionPoint)
	}
}

type workloadPathSpec struct {
	Name                 string
	Namespace            string
	ServiceAccountName   string
	ServiceAccountPower  string
	PatchRelevantFields  []string
	VisiblePatchSurfaces []string
	Priority             string
	PublicExposure       bool
}

func testPodWorkloadPath(spec workloadPathSpec) model.WorkloadPath {
	patchRelevantFields := spec.PatchRelevantFields
	if len(patchRelevantFields) == 0 {
		patchRelevantFields = spec.VisiblePatchSurfaces
	}
	return model.WorkloadPath{
		ID:                   "pod:" + spec.Namespace + ":" + spec.Name,
		Kind:                 "Pod",
		Name:                 spec.Name,
		Namespace:            spec.Namespace,
		ServiceAccountName:   spec.ServiceAccountName,
		ServiceAccountPower:  spec.ServiceAccountPower,
		PatchRelevantFields:  patchRelevantFields,
		VisiblePatchSurfaces: spec.VisiblePatchSurfaces,
		Priority:             spec.Priority,
		PublicExposure:       spec.PublicExposure,
	}
}

func testDeploymentWorkloadPath(spec workloadPathSpec) model.WorkloadPath {
	patchRelevantFields := spec.PatchRelevantFields
	if len(patchRelevantFields) == 0 {
		patchRelevantFields = spec.VisiblePatchSurfaces
	}
	return model.WorkloadPath{
		ID:                   "deployment:" + spec.Namespace + ":" + spec.Name,
		Kind:                 "Deployment",
		Name:                 spec.Name,
		Namespace:            spec.Namespace,
		ServiceAccountName:   spec.ServiceAccountName,
		ServiceAccountPower:  spec.ServiceAccountPower,
		PatchRelevantFields:  patchRelevantFields,
		VisiblePatchSurfaces: spec.VisiblePatchSurfaces,
		Priority:             spec.Priority,
		PublicExposure:       spec.PublicExposure,
	}
}

type serviceAccountPathSpec struct {
	Name             string
	Namespace        string
	EvidenceStatus   string
	Priority         string
	PowerSummary     string
	PowerRank        int
	RelatedWorkloads []string
	TokenPosture     string
}

func testServiceAccountPath(spec serviceAccountPathSpec) model.ServiceAccountPath {
	return model.ServiceAccountPath{
		ID:               "serviceaccount:" + spec.Namespace + ":" + spec.Name,
		Name:             spec.Name,
		Namespace:        spec.Namespace,
		EvidenceStatus:   spec.EvidenceStatus,
		Priority:         spec.Priority,
		PowerSummary:     spec.PowerSummary,
		PowerRank:        spec.PowerRank,
		RelatedWorkloads: spec.RelatedWorkloads,
		TokenPosture:     spec.TokenPosture,
	}
}

func testCurrentSessionWorkloadChangePermission(namespace, verb, targetGroup, summary string) model.PermissionPath {
	return model.PermissionPath{
		ID:            "current-session:user:" + verb + "-" + targetGroup,
		Scope:         "namespace/" + namespace,
		ActionVerb:    verb,
		TargetGroup:   targetGroup,
		ActionSummary: summary,
	}
}

func chainRowBySubversionPoint(rows []model.ChainPathRecord, subversionPoint string) (model.ChainPathRecord, bool) {
	for _, row := range rows {
		if row.SubversionPoint == subversionPoint {
			return row, true
		}
	}
	return model.ChainPathRecord{}, false
}
