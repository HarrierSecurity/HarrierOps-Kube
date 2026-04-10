package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func TestWorkloadsPayloadRanksJoinedWorkloadPaths(t *testing.T) {
	payload, err := buildCommandPayload("workloads", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	rows, ok := payload["workload_assets"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("workload_assets = %T, want non-empty []any", payload["workload_assets"])
	}

	first := requireMap(t, rows[0])
	if first["name"] != "web-5d4f6" {
		t.Fatalf("first name = %v, want web-5d4f6", first["name"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["public_exposure"] != true {
		t.Fatalf("first public_exposure = %v, want true", first["public_exposure"])
	}
	if !strings.Contains(first["identity_summary"].(string), "can change workloads") {
		t.Fatalf("first identity_summary = %v, want exposed identity-bearing workload", first["identity_summary"])
	}

	nodeDebug := findWorkloadRow(t, rows, "build", "node-debug")
	if nodeDebug["priority"] != "medium" {
		t.Fatalf("node-debug priority = %v, want medium", nodeDebug["priority"])
	}
	riskSignals, ok := nodeDebug["risk_signals"].([]any)
	if !ok || len(riskSignals) == 0 {
		t.Fatalf("node-debug risk_signals = %#v, want non-empty", nodeDebug["risk_signals"])
	}

	web := findWorkloadRow(t, rows, "storefront", "web-5d4f6")
	if web["public_exposure"] != true {
		t.Fatalf("web-5d4f6 public_exposure = %v, want true", web["public_exposure"])
	}
	if web["priority"] != "high" {
		t.Fatalf("web-5d4f6 priority = %v, want high", web["priority"])
	}
	if !strings.Contains(web["why_care"].(string), "public-looking exposure path") {
		t.Fatalf("web-5d4f6 why_care = %q, want exposure wording", web["why_care"])
	}
	if got := requireStringSlice(t, web["visible_patch_surfaces"]); !equalStrings(got, []string{"image", "service account"}) {
		t.Fatalf("web-5d4f6 visible_patch_surfaces = %#v, want image + service account", got)
	}

	foxAdmin := findWorkloadRow(t, rows, "default", "fox-admin")
	if foxAdmin["priority"] != "high" {
		t.Fatalf("fox-admin priority = %v, want high", foxAdmin["priority"])
	}
	if !strings.Contains(foxAdmin["identity_summary"].(string), "cluster-wide admin-like access") {
		t.Fatalf("fox-admin identity_summary = %v, want strong identity path", foxAdmin["identity_summary"])
	}
	if got := requireStringSlice(t, foxAdmin["visible_patch_surfaces"]); !equalStrings(got, []string{
		"image",
		"command",
		"args",
		"env",
		"service account",
		"mounted secret refs",
		"mounted config refs",
		"init containers",
		"sidecars",
	}) {
		t.Fatalf("fox-admin visible_patch_surfaces = %#v, want workload patch surfaces", got)
	}
}

func TestWorkloadEnrichmentPrioritizesExposureIdentityAndExecution(t *testing.T) {
	rows := enrichWorkloadPaths(
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{
					ID:                 "deployment:edge:frontdoor",
					Namespace:          "edge",
					Name:               "frontdoor",
					Kind:               "Deployment",
					ServiceAccountName: "frontdoor",
					Images:             []string{"ghcr.io/example/frontdoor:1.2.3"},
					Command:            []string{"nginx"},
					Args:               []string{"-g", "daemon off;"},
					EnvNames:           []string{"LOG_LEVEL"},
					MountedConfigRefs:  []string{"frontdoor-config"},
					Sidecars:           []string{"log-shipper"},
					Replicas:           intPtr(3),
				},
				{ID: "pod:ops:builder", Namespace: "ops", Name: "builder", Kind: "Pod", ServiceAccountName: "default", HostPathMounts: []string{"/var/lib/kubelet"}, HostNetwork: true, HostPID: true, AutomountServiceAccountToken: boolPtr(true)},
				{ID: "pod:default:quiet", Namespace: "default", Name: "quiet", Kind: "Pod", ServiceAccountName: "default"},
			},
		},
		model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:edge:frontdoor", Namespace: "edge", Name: "frontdoor"},
				{ID: "serviceaccount:default:default", Namespace: "default", Name: "default"},
			},
		},
		model.ExposureData{
			ExposureAssets: []model.Exposure{
				{ID: "ingress:edge:frontdoor", Namespace: "edge", ExposureType: "Ingress", Public: true, ExternalTargets: []string{"frontdoor.example.com"}, RelatedWorkloads: []string{"frontdoor"}},
			},
		},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-frontdoor", SubjectKind: "ServiceAccount", SubjectNamespace: stringPtr("edge"), SubjectName: "frontdoor", DangerousRights: []string{"read secrets"}, EvidenceStatus: "direct", Scope: "namespace/edge"},
			},
		},
	)

	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	if rows[0].Namespace != "edge" || rows[0].Name != "frontdoor" {
		t.Fatalf("first row = %s/%s, want edge/frontdoor", rows[0].Namespace, rows[0].Name)
	}
	if !rows[0].PublicExposure {
		t.Fatalf("edge/frontdoor PublicExposure = false, want true")
	}
	if rows[0].ServiceAccountPower != "can read secrets" {
		t.Fatalf("edge/frontdoor ServiceAccountPower = %q, want can read secrets", rows[0].ServiceAccountPower)
	}
	if got := rows[0].VisiblePatchSurfaces; !equalStrings(got, []string{
		"image",
		"command",
		"args",
		"env",
		"service account",
		"mounted config refs",
		"sidecars",
	}) {
		t.Fatalf("edge/frontdoor VisiblePatchSurfaces = %#v, want ordered patch surfaces", got)
	}
	if rows[1].Namespace != "ops" || rows[1].Name != "builder" {
		t.Fatalf("second row = %s/%s, want ops/builder", rows[1].Namespace, rows[1].Name)
	}
	if rows[1].Priority != "medium" {
		t.Fatalf("ops/builder priority = %s, want medium", rows[1].Priority)
	}
	if rows[2].Namespace != "default" || rows[2].Name != "quiet" {
		t.Fatalf("third row = %s/%s, want default/quiet", rows[2].Namespace, rows[2].Name)
	}
	if rows[2].Priority != "low" {
		t.Fatalf("default/quiet priority = %s, want low", rows[2].Priority)
	}
}

func TestWorkloadEnrichmentKeepsOperationallyCentralRowsAheadOfQuietOnes(t *testing.T) {
	rows := enrichWorkloadPaths(
		model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "deployment:ops:ingress-controller", Namespace: "ops", Name: "ingress-controller", Kind: "Deployment", ServiceAccountName: "default"},
				{ID: "pod:default:quiet", Namespace: "default", Name: "quiet", Kind: "Pod", ServiceAccountName: "default"},
			},
		},
		model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:default:default", Namespace: "default", Name: "default"},
				{ID: "serviceaccount:ops:default", Namespace: "ops", Name: "default"},
			},
		},
		model.ExposureData{},
		model.RBACData{},
	)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Namespace != "ops" || rows[0].Name != "ingress-controller" {
		t.Fatalf("first row = %s/%s, want ops/ingress-controller", rows[0].Namespace, rows[0].Name)
	}
	if !strings.Contains(rows[0].WhyCare, "looks operationally central") {
		t.Fatalf("ingress-controller why_care = %q, want centrality wording", rows[0].WhyCare)
	}
	if rows[1].Namespace != "default" || rows[1].Name != "quiet" {
		t.Fatalf("second row = %s/%s, want default/quiet", rows[1].Namespace, rows[1].Name)
	}
}

func TestWorkloadsPayloadKeepsRowsWhenSupportReadsFail(t *testing.T) {
	payload, err := buildWorkloadsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			Namespace:   "default",
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "pod:default:quiet", Namespace: "default", Name: "quiet", Kind: "Pod", ServiceAccountName: "default"},
			},
		},
		serviceAccountsErr: errors.New("forbidden"),
		exposuresErr:       errors.New("forbidden"),
		rbacErr:            errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildWorkloadsPayload() error = %v", err)
	}

	rows, ok := payload["workload_assets"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("workload_assets = %#v, want one row", payload["workload_assets"])
	}

	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) < 3 {
		t.Fatalf("issues = %#v, want propagated support issues", payload["issues"])
	}

	scopes := map[string]bool{}
	for _, issue := range issues {
		mapping := requireMap(t, issue)
		scope, _ := mapping["scope"].(string)
		scopes[scope] = true
	}
	for _, want := range []string{"workloads.service-accounts", "workloads.exposure", "workloads.rbac"} {
		if !scopes[want] {
			t.Fatalf("missing issue scope %q in %#v", want, scopes)
		}
	}
}

func TestWorkloadsTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"workloads"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"priority",
		"workload",
		"identity",
		"execution",
		"default/fox-admin",
		"cluster-wide admin-like access",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}

func requireStringSlice(t *testing.T, value any) []string {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("value = %T, want []any", value)
	}

	got := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("item = %T, want string", item)
		}
		got = append(got, text)
	}
	return got
}

func equalStrings(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func intPtr(value int) *int {
	return &value
}
