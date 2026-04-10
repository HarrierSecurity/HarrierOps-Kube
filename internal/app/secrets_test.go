package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func TestSecretsPayloadRanksSecretPathsWithoutDumpingValues(t *testing.T) {
	payload, err := buildCommandPayload("secrets", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	rows, ok := payload["secret_paths"].([]any)
	if !ok || len(rows) < 3 {
		t.Fatalf("secret_paths = %#v, want visible secret rows", payload["secret_paths"])
	}

	first := requireMap(t, rows[0])
	if first["safe_label"] != "fox-admin-token" {
		t.Fatalf("first safe_label = %v, want fox-admin-token", first["safe_label"])
	}
	if first["secret_story"] != "stores-secret" {
		t.Fatalf("first secret_story = %v, want stores-secret", first["secret_story"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["likely_secret_type"] != "service-account token" {
		t.Fatalf("first likely_secret_type = %v, want service-account token", first["likely_secret_type"])
	}
	if first["direct_use_confidence"] != "direct" {
		t.Fatalf("first direct_use_confidence = %v, want direct", first["direct_use_confidence"])
	}
	if _, exists := first["value"]; exists {
		t.Fatalf("first row unexpectedly contains secret value field: %#v", first)
	}

	web := requireMap(t, rows[1])
	if web["safe_label"] != "regcred" {
		t.Fatalf("second safe_label = %v, want regcred", web["safe_label"])
	}
	if web["likely_target_family"] != "container registry" {
		t.Fatalf("second likely_target_family = %v, want container registry", web["likely_target_family"])
	}
	if web["next_review"] != "workloads" {
		t.Fatalf("second next_review = %v, want workloads", web["next_review"])
	}
	if !strings.Contains(web["why_care"].(string), "exposed workload path") {
		t.Fatalf("second why_care = %q, want exposed linkage wording", web["why_care"])
	}
}

func TestSecretsPayloadRecognizesExternalSecretDependencyHeuristic(t *testing.T) {
	payload, err := buildSecretsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{ContextName: "ops", Namespace: "default"},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{ID: "deployment:ops:external-secrets", Namespace: "ops", Name: "external-secrets", Kind: "Deployment", Images: []string{"ghcr.io/external-secrets/external-secrets:v0.10.0"}},
			},
		},
		exposuresData: model.ExposureData{},
		rbacData:      model.RBACData{},
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildSecretsPayload() error = %v", err)
	}

	rows, ok := payload["secret_paths"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("secret_paths = %#v, want one heuristic dependency row", payload["secret_paths"])
	}

	row := requireMap(t, rows[0])
	if row["secret_story"] != "uses-external-secret" {
		t.Fatalf("secret_story = %v, want uses-external-secret", row["secret_story"])
	}
	if row["confidence"] != "likely" {
		t.Fatalf("confidence = %v, want likely", row["confidence"])
	}
	if row["next_review"] != "workloads" {
		t.Fatalf("next_review = %v, want workloads", row["next_review"])
	}
}

func TestSecretsPayloadKeepsRowsWhenSupportReadsFail(t *testing.T) {
	payload, err := buildSecretsPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			Namespace:   "default",
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{ID: "serviceaccount:default:fox-admin", Namespace: "default", Name: "fox-admin", SecretNames: []string{"fox-admin-token"}},
			},
		},
		workloadsErr: errors.New("forbidden"),
		exposuresErr: errors.New("forbidden"),
		rbacErr:      errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildSecretsPayload() error = %v", err)
	}

	rows, ok := payload["secret_paths"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("secret_paths = %#v, want one row despite support failures", payload["secret_paths"])
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
	for _, want := range []string{"secrets.workloads", "secrets.exposure", "secrets.rbac"} {
		if !scopes[want] {
			t.Fatalf("missing issue scope %q in %#v", want, scopes)
		}
	}
}

func TestSecretsTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"secrets"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := normalizedTableText(stdout.String())
	for _, want := range []string{
		"priority",
		"story",
		"service-account secret:",
		"fox-admin-token",
		"image pull secret: regcred",
		"container registry",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}
