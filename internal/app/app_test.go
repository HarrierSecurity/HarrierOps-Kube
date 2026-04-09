package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/output"
	"harrierops-kube/internal/provider"
)

func TestCLICommandsSmoke(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	commands := []string{
		"whoami",
		"inventory",
		"rbac",
		"service-accounts",
		"workloads",
		"exposure",
		"permissions",
		"secrets",
		"privesc",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			outDir := t.TempDir()
			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}

			exitCode := Run(
				[]string{"--outdir", outDir, "--output", "json", command},
				stdout,
				stderr,
				[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
			)

			if exitCode != 0 {
				t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
			}

			payload := decodeJSONMap(t, stdout.Bytes())
			metadata := requireMap(t, payload["metadata"])
			if metadata["command"] != command {
				t.Fatalf("metadata.command = %v, want %s", metadata["command"], command)
			}

			lootPath := filepath.Join(outDir, "loot", command+".json")
			if _, err := os.Stat(lootPath); err != nil {
				t.Fatalf("expected artifact %s: %v", lootPath, err)
			}
		})
	}
}

func TestCLIAllowsSharedFlagsAfterCommand(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	outDir := t.TempDir()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"whoami", "--debug", "--output", "json", "--outdir", outDir},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	payload := decodeJSONMap(t, stdout.Bytes())
	metadata := requireMap(t, payload["metadata"])
	if metadata["command"] != "whoami" {
		t.Fatalf("metadata.command = %v, want whoami", metadata["command"])
	}

	lootPath := filepath.Join(outDir, "loot", "whoami.json")
	if _, err := os.Stat(lootPath); err != nil {
		t.Fatalf("expected artifact %s: %v", lootPath, err)
	}
}

func TestCLIAllowsSharedFlagsOnEitherSideOfCommand(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	outDir := t.TempDir()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"--context", "lab-cluster", "inventory", "--output", "json", "--outdir", outDir},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	payload := decodeJSONMap(t, stdout.Bytes())
	metadata := requireMap(t, payload["metadata"])
	if metadata["command"] != "inventory" {
		t.Fatalf("metadata.command = %v, want inventory", metadata["command"])
	}
	if metadata["context_name"] != "lab-cluster" {
		t.Fatalf("metadata.context_name = %v, want lab-cluster", metadata["context_name"])
	}
}

func TestCLIDoesNotWriteArtifactsWithoutOutdir(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	workingDir := t.TempDir()
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if err := os.Chdir(workingDir); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}
	defer func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"whoami", "--output", "json"},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	for _, directory := range []string{"loot", "json", "table", "csv"} {
		if _, err := os.Stat(filepath.Join(workingDir, directory)); err == nil {
			t.Fatalf("unexpected artifact directory %q was created", directory)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %q: %v", directory, err)
		}
	}
}

func TestCLIStillRejectsTrailingArgsWhenSharedFlagsMoveAround(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"whoami", "--output", "json", "extra"},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), `unexpected arguments after command "whoami": extra`) {
		t.Fatalf("stderr = %q, want trailing-args guidance", stderr.String())
	}
}

func TestPlannedPhaseOneCommandsReturnHelpfulError(t *testing.T) {
	if len(commandNamesWithStatus("planned-phase1")) != 0 {
		t.Fatalf("planned phase 1 commands = %#v, want none", commandNamesWithStatus("planned-phase1"))
	}
}

func TestLaterDepthSurfaceReturnsHelpfulError(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"images"}, stdout, stderr, nil)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "later depth surface") {
		t.Fatalf("stderr = %q, want later-depth guidance", stderr.String())
	}
}

func TestUsageTextReflectsCurrentSurface(t *testing.T) {
	usage := usageText()

	if strings.Contains(usage, "all-checks") {
		t.Fatalf("usage text still references all-checks: %q", usage)
	}
	for _, want := range []string{
		"implemented commands: whoami, inventory, rbac, service-accounts, workloads, exposure, permissions, secrets, privesc",
		"planned phase 1 commands: none",
		"later depth surfaces: images",
		"implemented sections: identity, core, workload, exposure, secrets",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage text missing %q in %q", want, usage)
		}
	}
}

func TestGoldenOutputsForImplementedCommands(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	goldenDir := testGoldenDir(t)

	for _, command := range []string{
		"whoami",
		"inventory",
		"rbac",
		"service-accounts",
		"exposure",
		"workloads",
		"permissions",
		"secrets",
		"privesc",
	} {
		t.Run(command, func(t *testing.T) {
			payload, err := buildCommandPayload(command, Options{FixtureDir: fixtureDir})
			if err != nil {
				t.Fatalf("buildCommandPayload() error = %v", err)
			}

			got := normalizeGeneratedAt(t, payload)
			wantBytes, err := os.ReadFile(filepath.Join(goldenDir, command+".json"))
			if err != nil {
				t.Fatalf("read golden file: %v", err)
			}
			want := decodeJSONMap(t, wantBytes)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("payload mismatch\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestWhoAmIPayloadIdentityCases(t *testing.T) {
	testCases := []struct {
		name                string
		fixtureDir          string
		wantLabel           string
		wantConfidence      string
		wantAuthMaterial    string
		wantExecutionOrigin string
		wantEnvironmentType string
		wantBlockers        int
	}{
		{
			name:                "direct",
			fixtureDir:          testFixtureDir(t),
			wantLabel:           "fox-operator",
			wantConfidence:      "direct",
			wantAuthMaterial:    "exec-plugin",
			wantExecutionOrigin: "outside-cluster",
			wantEnvironmentType: "self-managed-like",
			wantBlockers:        0,
		},
		{
			name:                "inferred",
			fixtureDir:          whoamiFixtureCaseDir(t, "inferred"),
			wantLabel:           "system:serviceaccount:payments:api",
			wantConfidence:      "inferred",
			wantAuthMaterial:    "service-account-token",
			wantExecutionOrigin: "inside-pod",
			wantEnvironmentType: "self-managed-like",
			wantBlockers:        1,
		},
		{
			name:                "blocked",
			fixtureDir:          whoamiFixtureCaseDir(t, "blocked"),
			wantLabel:           "unknown current identity",
			wantConfidence:      "blocked",
			wantAuthMaterial:    "unknown",
			wantExecutionOrigin: "outside-cluster",
			wantEnvironmentType: "self-managed-like",
			wantBlockers:        2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := buildCommandPayload("whoami", Options{FixtureDir: tc.fixtureDir})
			if err != nil {
				t.Fatalf("buildCommandPayload() error = %v", err)
			}

			currentIdentity := requireMap(t, payload["current_identity"])
			if currentIdentity["label"] != tc.wantLabel {
				t.Fatalf("current_identity.label = %v, want %s", currentIdentity["label"], tc.wantLabel)
			}
			if currentIdentity["confidence"] != tc.wantConfidence {
				t.Fatalf("current_identity.confidence = %v, want %s", currentIdentity["confidence"], tc.wantConfidence)
			}

			session := requireMap(t, payload["session"])
			if session["auth_material_type"] != tc.wantAuthMaterial {
				t.Fatalf("session.auth_material_type = %v, want %s", session["auth_material_type"], tc.wantAuthMaterial)
			}
			if session["execution_origin"] != tc.wantExecutionOrigin {
				t.Fatalf("session.execution_origin = %v, want %s", session["execution_origin"], tc.wantExecutionOrigin)
			}

			environmentHint := requireMap(t, payload["environment_hint"])
			if environmentHint["type"] != tc.wantEnvironmentType {
				t.Fatalf("environment_hint.type = %v, want %s", environmentHint["type"], tc.wantEnvironmentType)
			}

			blockers, ok := payload["visibility_blockers"].([]any)
			if !ok {
				t.Fatalf("visibility_blockers = %T, want []any", payload["visibility_blockers"])
			}
			if len(blockers) != tc.wantBlockers {
				t.Fatalf("len(visibility_blockers) = %d, want %d", len(blockers), tc.wantBlockers)
			}
		})
	}
}

func TestWhoAmITableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"whoami"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"Cluster",
		"API Server",
		"Identity",
		"Identity Confidence",
		"Foothold Family",
		"Environment Hint",
		"Auth Material",
		"Identity Evidence",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}

func TestInventoryOutputStaysOrientationOnly(t *testing.T) {
	payload, err := buildCommandPayload("inventory", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	for _, key := range []string{
		"visibility",
		"environment",
		"exposure_footprint",
		"risky_workload_footprint",
		"identity_footprint",
		"next_commands",
	} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("inventory payload missing %q", key)
		}
	}

	for _, forbidden := range []string{"role_grants", "service_accounts", "workload_assets", "exposure_assets"} {
		if _, ok := payload[forbidden]; ok {
			t.Fatalf("inventory payload should stay orientation-only, but included %q", forbidden)
		}
	}
}

func TestInventoryTableOutputHighlightsRouting(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"inventory"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"Visibility",
		"Environment",
		"Exposure Footprint",
		"Risky Workloads",
		"Identity Footprint",
		"Next Commands",
		"exposure:",
		"rbac:",
		"workloads:",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}

func TestInventoryKeepsOrientationSignalWhenSupportReadFails(t *testing.T) {
	payload, err := buildInventoryPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			Namespace:   "default",
		},
		inventoryData: model.InventoryData{
			KubernetesCounts: map[string]int{"namespaces": 2, "pods": 3},
			Issues:           []model.Issue{},
		},
		whoamiData: model.WhoAmIData{
			KubeContext: model.KubeContext{
				ClusterName:    "lab-cluster",
				CurrentContext: "lab-cluster",
				Namespace:      "default",
				Server:         "https://10.0.0.1:6443",
			},
			CurrentIdentity: model.CurrentIdentity{
				Label:      "fox-operator",
				Kind:       "User",
				Confidence: "direct",
			},
			Session: model.SessionProfile{
				AuthMaterialType: "exec-plugin",
				ExecutionOrigin:  "outside-cluster",
				FootholdFamily:   "cloud-bridged",
				VisibilityScope:  "cluster-scoped",
			},
		},
		workloadsErr: errors.New("forbidden"),
	}, provider.QueryOptions{})
	if err != nil {
		t.Fatalf("buildInventoryPayload() error = %v", err)
	}

	issues, ok := payload["issues"].([]any)
	if !ok {
		t.Fatalf("issues = %T, want []any", payload["issues"])
	}
	if len(issues) == 0 {
		t.Fatalf("expected propagated inventory issue")
	}

	found := false
	for _, item := range issues {
		issue := requireMap(t, item)
		if issue["scope"] == "inventory.workloads" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("inventory issues did not include workload collection failure: %#v", issues)
	}

	if _, ok := payload["visibility"]; !ok {
		t.Fatalf("inventory lost orientation signal after support read failure")
	}
}

func TestInventoryLootIsSmallerThanFullJSON(t *testing.T) {
	payload, err := buildCommandPayload("inventory", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	lootJSON, fullJSON, err := outputArtifactsForTest("inventory", payload)
	if err != nil {
		t.Fatalf("outputArtifactsForTest() error = %v", err)
	}

	if len(lootJSON) >= len(fullJSON) {
		t.Fatalf("loot payload should be smaller than full JSON: loot=%d full=%d", len(lootJSON), len(fullJSON))
	}

	var lootPayload map[string]any
	if err := json.Unmarshal(lootJSON, &lootPayload); err != nil {
		t.Fatalf("json.Unmarshal() loot error = %v", err)
	}
	if _, ok := lootPayload["kubernetes_counts"]; ok {
		t.Fatalf("inventory loot should omit full counts")
	}
	if _, ok := lootPayload["next_commands"]; !ok {
		t.Fatalf("inventory loot should keep next_commands")
	}
}

func TestInventoryVisibilityKeepsBlockersVisibleInBroadSlice(t *testing.T) {
	visibility := deriveInventoryVisibility(
		map[string]int{
			"namespaces":   4,
			"nodes":        2,
			"pods":         8,
			"deployments":  2,
			"daemonsets":   1,
			"statefulsets": 1,
		},
		model.WhoAmIData{
			VisibilityBlockers: []string{
				"Current scope does not confirm every namespace or object family cleanly.",
			},
		},
	)

	if !strings.Contains(visibility.Summary, "Visibility blockers are still present") {
		t.Fatalf("visibility summary should keep blockers visible, got %q", visibility.Summary)
	}
}

func TestInventoryNextCommandsIncludesRBACWhenGrantsAreVisible(t *testing.T) {
	hints := deriveInventoryNextCommands(
		model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{Confidence: "direct"},
		},
		model.ExposureData{},
		model.WorkloadsData{},
		model.ServiceAccountsData{},
		model.RBACData{
			RoleGrants: []model.RBACGrant{
				{ID: "grant-1"},
			},
		},
	)

	found := false
	for _, hint := range hints {
		if hint.Command == "rbac" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected inventory next commands to include rbac when grants are visible")
	}
}

func TestRbacPayloadRanksClusterWideAdminPathFirst(t *testing.T) {
	payload, err := buildCommandPayload("rbac", Options{FixtureDir: testFixtureDir(t)})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	grants, ok := payload["role_grants"].([]any)
	if !ok || len(grants) == 0 {
		t.Fatalf("role_grants = %T, want non-empty []any", payload["role_grants"])
	}

	first := requireMap(t, grants[0])
	if first["subject_display"] != "ServiceAccount default/fox-admin" {
		t.Fatalf("first subject_display = %v, want ServiceAccount default/fox-admin", first["subject_display"])
	}
	if first["priority"] != "high" {
		t.Fatalf("first priority = %v, want high", first["priority"])
	}
	if first["role_display_name"] != "cluster-admin*" {
		t.Fatalf("first role_display_name = %v, want cluster-admin*", first["role_display_name"])
	}
}

func TestRbacPayloadMarksImpersonationSignals(t *testing.T) {
	payload, err := buildCommandPayload("rbac", Options{FixtureDir: rbacFixtureCaseDir(t, "impersonate")})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	grants := payload["role_grants"].([]any)
	first := requireMap(t, grants[0])
	rights, ok := first["dangerous_rights"].([]any)
	if !ok {
		t.Fatalf("dangerous_rights = %T, want []any", first["dangerous_rights"])
	}
	found := false
	for _, item := range rights {
		if item == "impersonate serviceaccounts" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dangerous_rights = %#v, want impersonate serviceaccounts", rights)
	}
}

func TestRbacKeepsGrantVisibleWhenRoleRulesAreBlocked(t *testing.T) {
	payload, err := buildCommandPayload("rbac", Options{FixtureDir: rbacFixtureCaseDir(t, "partial_read")})
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	grants := payload["role_grants"].([]any)
	first := requireMap(t, grants[0])
	if first["evidence_status"] != "visibility blocked" {
		t.Fatalf("evidence_status = %v, want visibility blocked", first["evidence_status"])
	}
	if !strings.Contains(first["why_care"].(string), "not visible from current credentials") {
		t.Fatalf("why_care = %q, want clearer visibility reason", first["why_care"])
	}

	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) == 0 {
		t.Fatalf("issues = %T, want non-empty []any", payload["issues"])
	}
}

func TestRbacTableOutputStaysOperatorReadable(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"rbac"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := stdout.String()
	for _, want := range []string{
		"priority",
		"scope",
		"subject",
		"role",
		"signal",
		"why_care",
		"cluster-admin*",
		"ServiceAccount default/fox-admin",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}

func testFixtureDir(t *testing.T) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "lab_cluster"))
}

func testGoldenDir(t *testing.T) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "golden"))
}

func whoamiFixtureCaseDir(t *testing.T, name string) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "whoami_cases", name))
}

func rbacFixtureCaseDir(t *testing.T, name string) string {
	t.Helper()
	return absPath(t, filepath.Join("..", "..", "testdata", "fixtures", "rbac_cases", name))
}

func absPath(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", path, err)
	}
	return absolute
}

func decodeJSONMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	return payload
}

func requireMap(t *testing.T, value any) map[string]any {
	t.Helper()
	mapping, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %T, want map[string]any", value)
	}
	return mapping
}

func normalizeGeneratedAt(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}

	normalized := decodeJSONMap(t, data)
	metadata := requireMap(t, normalized["metadata"])
	metadata["generated_at"] = "<generated_at>"
	return normalized
}

type stubInventoryProvider struct {
	metadataContext     model.MetadataContext
	metadataContextErr  error
	inventoryData       model.InventoryData
	inventoryErr        error
	whoamiData          model.WhoAmIData
	whoamiErr           error
	rbacData            model.RBACData
	rbacErr             error
	serviceAccountsData model.ServiceAccountsData
	serviceAccountsErr  error
	workloadsData       model.WorkloadsData
	workloadsErr        error
	exposuresData       model.ExposureData
	exposuresErr        error
}

func (s stubInventoryProvider) MetadataContext(provider.QueryOptions) (model.MetadataContext, error) {
	return s.metadataContext, s.metadataContextErr
}

func (s stubInventoryProvider) WhoAmI(provider.QueryOptions) (model.WhoAmIData, error) {
	return s.whoamiData, s.whoamiErr
}

func (s stubInventoryProvider) Inventory(provider.QueryOptions) (model.InventoryData, error) {
	return s.inventoryData, s.inventoryErr
}

func (s stubInventoryProvider) RBACBindings(provider.QueryOptions) (model.RBACData, error) {
	return s.rbacData, s.rbacErr
}

func (s stubInventoryProvider) ServiceAccounts(provider.QueryOptions) (model.ServiceAccountsData, error) {
	return s.serviceAccountsData, s.serviceAccountsErr
}

func (s stubInventoryProvider) Workloads(provider.QueryOptions) (model.WorkloadsData, error) {
	return s.workloadsData, s.workloadsErr
}

func (s stubInventoryProvider) Exposures(provider.QueryOptions) (model.ExposureData, error) {
	return s.exposuresData, s.exposuresErr
}

func outputArtifactsForTest(command string, payload map[string]any) ([]byte, []byte, error) {
	tmpDir, err := os.MkdirTemp("", "harrierops-loot-test")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	paths, err := output.WriteArtifacts(command, payload, tmpDir)
	if err != nil {
		return nil, nil, err
	}
	lootBytes, err := os.ReadFile(paths["loot"])
	if err != nil {
		return nil, nil, err
	}
	jsonBytes, err := os.ReadFile(paths["json"])
	if err != nil {
		return nil, nil, err
	}
	return lootBytes, jsonBytes, nil
}

func findServiceAccountRow(t *testing.T, rows []any, namespace string, name string) map[string]any {
	t.Helper()
	for _, row := range rows {
		mapping := requireMap(t, row)
		if mapping["namespace"] == namespace && mapping["name"] == name {
			return mapping
		}
	}
	t.Fatalf("service account row %s/%s not found", namespace, name)
	return nil
}

func findWorkloadRow(t *testing.T, rows []any, namespace string, name string) map[string]any {
	t.Helper()
	for _, row := range rows {
		mapping := requireMap(t, row)
		if mapping["namespace"] == namespace && mapping["name"] == name {
			return mapping
		}
	}
	t.Fatalf("workload row %s/%s not found", namespace, name)
	return nil
}

func findExposureRow(t *testing.T, rows []any, namespace string, name string) map[string]any {
	t.Helper()
	for _, row := range rows {
		mapping := requireMap(t, row)
		if mapping["namespace"] == namespace && mapping["name"] == name {
			return mapping
		}
	}
	t.Fatalf("exposure row %s/%s not found", namespace, name)
	return nil
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
