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

func normalizedRenderText(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func normalizedTableText(text string) string {
	lines := strings.Split(text, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Trim(trimmed, "+-|") == "" {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "|")
		trimmed = strings.TrimSuffix(trimmed, "|")
		trimmed = strings.ReplaceAll(trimmed, "|", " ")
		parts = append(parts, trimmed)
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

func TestCLICommandsSmoke(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	commands := []string{
		"whoami",
		"chains",
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
				[]string{command, "--outdir", outDir, "--output", "json"},
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

func TestCLIAllowsContextFlagAfterCommand(t *testing.T) {
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

func TestCLIAllowsSharedFlagsAfterCommand(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	outDir := t.TempDir()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"inventory", "--context", "lab-cluster", "--output", "json", "--outdir", outDir},
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

func TestChainsAllowsFamilyBeforeSharedFlags(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"chains", "workload-identity-pivot", "--output", "json"},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	payload := decodeJSONMap(t, stdout.Bytes())
	if payload["family"] != "workload-identity-pivot" {
		t.Fatalf("family = %v, want workload-identity-pivot", payload["family"])
	}
}

func TestCLIRejectsFlagsBeforeCommand(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"--context", "lab-cluster", "inventory"},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "command must come first") {
		t.Fatalf("stderr = %q, want command-first guidance", stderr.String())
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
		"implemented commands: whoami, chains, inventory, rbac, service-accounts, workloads, exposure, permissions, secrets, privesc",
		"planned phase 1 commands: none",
		"later depth surfaces: images",
		"implemented sections: identity, orchestration, core, workload, exposure, secrets",
		"harrierops-kube help [command]",
		"harrierops-kube chains [family] [global options]",
		"harrierops-kube <command> help",
		"run `harrierops-kube help <command>` or `harrierops-kube <command> help` for operator-readable command summaries",
	} {
		if !strings.Contains(usage, want) {
			t.Fatalf("usage text missing %q in %q", want, usage)
		}
	}
}

func TestNoArgsShowDedicatedRootHelpSurface(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(nil, stdout, stderr, nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	rendered := normalizedRenderText(stdout.String())
	for _, want := range []string{
		"HarrierOps Kube Help",
		"harrierops-kube help <command>",
		"Sections:",
		"Commands:",
		"whoami",
		"chains",
		"permissions",
		"Later depth surfaces:",
		"images",
		"`chains` now has a family overview plus a runnable `workload-identity-pivot` family",
		"`rbac` marks known built-in roles with `*`",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("help output missing %q in %q", want, rendered)
		}
	}
}

func TestCommandHelpShowsTopicAfterCommand(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"permissions", "help"}, stdout, stderr, nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	rendered := normalizedRenderText(stdout.String())
	for _, want := range []string{
		"HarrierOps Kube Help :: permissions",
		"Status: implemented command.",
		"Section: identity",
		"Offensive question: What can this current foothold do next from visible scope?",
		"Kube frame: Collapse raw RBAC into practical capability rows for the current session.",
		"Output highlights:",
		"best known current identity plus `(current session)`",
		"Security value: Secret read, workload change, exec, impersonation, bind, or escalate rights can justify immediate follow-up.",
		"Why care: This is where a visible foothold stops looking theoretical and starts looking action-capable.",
		"An empty result means no visible grant matched the current session identity from current scope.",
		"harrierops-kube permissions --output table",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("help topic output missing %q in %q", want, rendered)
		}
	}
}

func TestChainsHelpShowsRunnableFamilyTopic(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"chains", "help"}, stdout, stderr, nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	rendered := normalizedRenderText(stdout.String())
	for _, want := range []string{
		"HarrierOps Kube Help :: chains",
		"Status: implemented command.",
		"Section: orchestration",
		"Offensive question: What bounded chained story is already visible from current scope?",
		"Grouped family overview plus the first runnable defended path family from current scope.",
		"workload-identity-pivot",
		"path type",
		"internal proof ladder",
		"kubernetes control",
		"Live row wording stays evidence-bounded",
		"Exact non-env workload patch-surface rows stay suppressed unless the family can tie the exact action edge and visible change surface to the same workload honestly.",
		"Service-account repointing rows name one exact replacement only when current scope makes that target specific; otherwise the family keeps the lead broader.",
		"harrierops-kube chains workload-identity-pivot --output table",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("chains help output missing %q in %q", want, rendered)
		}
	}
}

func TestChainsSelectedFamilyCSVOutputIncludesLiveRows(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	outDir := t.TempDir()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run(
		[]string{"chains", "workload-identity-pivot", "--output", "csv", "--outdir", outDir},
		stdout,
		stderr,
		[]string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + fixtureDir},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := normalizedRenderText(stdout.String())
	for _, want := range []string{
		"priority",
		"source_asset",
		"subversion_point",
		"default/fox-admin",
		"review visible workload-linked token path",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("csv output missing %q in %q", want, rendered)
		}
	}

	artifactPath := filepath.Join(outDir, "csv", "chains.csv")
	artifactBytes, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read csv artifact: %v", err)
	}

	artifact := string(artifactBytes)
	for _, want := range []string{
		"priority",
		"source_asset",
		"default/fox-admin",
	} {
		if !strings.Contains(artifact, want) {
			t.Fatalf("csv artifact missing %q in %q", want, artifact)
		}
	}
}

func TestCommandHelpShowsLaterDepthTopic(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"images", "help"}, stdout, stderr, nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := normalizedTableText(stdout.String())
	for _, want := range []string{
		"HarrierOps Kube Help :: images",
		"Status: later-depth surface.",
		"Workload-linked image triage",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("later-depth help output missing %q in %q", want, rendered)
		}
	}
}

func TestHelpCommandAliasShowsTopic(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"help", "permissions"}, stdout, stderr, nil)
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	rendered := normalizedTableText(stdout.String())
	for _, want := range []string{
		"HarrierOps Kube Help :: permissions",
		"Offensive question: What can this current foothold do next from visible scope?",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("help alias output missing %q in %q", want, rendered)
		}
	}
}

func TestCommandHelpRejectsUnknownCommand(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"unknown-surface", "help"}, stdout, stderr, nil)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{
		`unknown command "unknown-surface"`,
		"usage: harrierops-kube <command> [global options]",
		"implemented commands:",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q in %q", want, stderr.String())
		}
	}
}

func TestGoldenOutputsForImplementedCommands(t *testing.T) {
	fixtureDir := testFixtureDir(t)
	goldenDir := testGoldenDir(t)

	for _, command := range []string{
		"whoami",
		"chains",
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

func TestChainsPayloadShowsSelectedFamilyContract(t *testing.T) {
	payload, err := buildCommandPayload("chains", Options{FixtureDir: testFixtureDir(t)}, "workload-identity-pivot")
	if err != nil {
		t.Fatalf("buildCommandPayload() error = %v", err)
	}

	if payload["grouped_command_name"] != "chains" {
		t.Fatalf("grouped_command_name = %v, want chains", payload["grouped_command_name"])
	}
	if payload["command_state"] != "ok" {
		t.Fatalf("command_state = %v, want ok", payload["command_state"])
	}
	if payload["family"] != "workload-identity-pivot" {
		t.Fatalf("family = %v, want workload-identity-pivot", payload["family"])
	}
	if payload["input_mode"] != "live" {
		t.Fatalf("input_mode = %v, want live", payload["input_mode"])
	}

	paths, ok := payload["paths"].([]any)
	if !ok {
		t.Fatalf("paths = %T, want []any", payload["paths"])
	}
	if len(paths) == 0 {
		t.Fatalf("len(paths) = %d, want at least 1", len(paths))
	}

	first := requireMap(t, paths[0])
	if first["source_asset"] != "default/fox-admin" {
		t.Fatalf("first.source_asset = %v, want default/fox-admin", first["source_asset"])
	}
	if first["path_type"] != "direct control not confirmed" {
		t.Fatalf("first.path_type = %v, want direct control not confirmed", first["path_type"])
	}
	if first["visibility_tier"] != "medium" {
		t.Fatalf("first.visibility_tier = %v, want medium", first["visibility_tier"])
	}
}

func TestChainsCommandRejectsUnknownFamily(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"chains", "banana-path"}, stdout, stderr, nil)
	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown chain family "banana-path"`) {
		t.Fatalf("stderr = %q, want unknown chain family guidance", stderr.String())
	}
}

func TestChainsTableOutputStaysOperatorReadable(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	exitCode := Run([]string{"chains", "workload-identity-pivot"}, stdout, stderr, []string{"HARRIEROPS_KUBE_FIXTURE_DIR=" + testFixtureDir(t)})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}

	rendered := normalizedTableText(stdout.String())
	for _, want := range []string{
		"priority",
		"workload",
		"subversion point",
		"kubernetes control",
		"visibility",
		"note",
		"default/fox-admin",
		"review visible",
		"workload-linked token",
		"path",
		"direct control not",
		"confirmed",
		"attached service",
		"account has",
		"cluster-wide admin-like access",
		"medium",
		"Current scope confirms a workload-linked token path is visible, but runtime inspection is not yet proven.",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q in %q", want, rendered)
		}
	}
}

func TestBuildSelectedChainPayloadKeepsRunnableRowsWhenExposureSupportReadFails(t *testing.T) {
	namespace := "app"
	payload, err := buildSelectedChainPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			ClusterName: "lab-cluster",
			Namespace:   namespace,
		},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "fox-operator",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{
					ID:                 "pod:app:web",
					Name:               "web",
					Namespace:          namespace,
					Kind:               "Pod",
					ServiceAccountName: "web",
					Images:             []string{"nginx"},
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{
					ID:        "serviceaccount:app:web",
					Name:      "web",
					Namespace: namespace,
				},
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					ID:             "grant:user:exec",
					BindingName:    "user-exec",
					Scope:          "namespace/app",
					SubjectKind:    "User",
					SubjectName:    "fox-operator",
					EvidenceStatus: "direct",
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "exec",
							TargetGroup:     "pods",
							TargetResources: []string{"pods/exec"},
							Summary:         "can exec into pods",
						},
					},
				},
				{
					ID:               "grant:sa:secret-read",
					BindingName:      "web-secret-read",
					Scope:            "namespace/app",
					SubjectKind:      "ServiceAccount",
					SubjectName:      "web",
					SubjectNamespace: &namespace,
					EvidenceStatus:   "direct",
					DangerousRights:  []string{"read secrets"},
				},
			},
		},
		exposuresErr: errors.New("forbidden"),
	}, provider.QueryOptions{}, "workload-identity-pivot")
	if err != nil {
		t.Fatalf("buildSelectedChainPayload() error = %v", err)
	}

	if payload["family"] != "workload-identity-pivot" {
		t.Fatalf("family = %v, want workload-identity-pivot", payload["family"])
	}

	paths, ok := payload["paths"].([]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("paths = %#v, want non-empty []any", payload["paths"])
	}

	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) == 0 {
		t.Fatalf("issues = %#v, want support-read issue", payload["issues"])
	}

	foundExposureIssue := false
	for _, issue := range issues {
		scope, _ := requireMap(t, issue)["scope"].(string)
		if scope == "chains.exposure" {
			foundExposureIssue = true
			break
		}
	}
	if !foundExposureIssue {
		t.Fatalf("issues = %#v, want chains.exposure issue", issues)
	}
}

func TestBuildSelectedChainPayloadBuildsExactEnvPatchRowWhenCurrentSessionCanPatchPods(t *testing.T) {
	namespace := "default"
	payload, err := buildSelectedChainPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			ClusterName: "lab-cluster",
			Namespace:   namespace,
		},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "fox-operator",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{
					ID:                 "pod:default:fox-admin",
					Name:               "fox-admin",
					Namespace:          namespace,
					Kind:               "Pod",
					ServiceAccountName: "fox-admin",
					Images:             []string{"ghcr.io/example/fox-admin:latest"},
					EnvNames:           []string{"TOKEN_PATH"},
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{
					ID:        "serviceaccount:default:fox-admin",
					Name:      "fox-admin",
					Namespace: namespace,
				},
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					ID:             "grant:user:patch-pods",
					BindingName:    "user-patch-pods",
					Scope:          "namespace/default",
					SubjectKind:    "User",
					SubjectName:    "fox-operator",
					EvidenceStatus: "direct",
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "patch",
							TargetGroup:     "pods",
							TargetResources: []string{"pods"},
							Summary:         "can patch pods",
						},
					},
				},
				{
					ID:               "grant:sa:cluster-admin",
					BindingName:      "fox-admin-cluster-admin",
					Scope:            "cluster-wide",
					SubjectKind:      "ServiceAccount",
					SubjectName:      "fox-admin",
					SubjectNamespace: &namespace,
					EvidenceStatus:   "direct",
					DangerousRights:  []string{"admin-like wildcard access"},
				},
			},
		},
	}, provider.QueryOptions{}, "workload-identity-pivot")
	if err != nil {
		t.Fatalf("buildSelectedChainPayload() error = %v", err)
	}

	paths, ok := payload["paths"].([]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("paths = %#v, want non-empty []any", payload["paths"])
	}

	found := false
	for _, raw := range paths {
		row := requireMap(t, raw)
		if row["subversion_point"] != "patch env on workload default/fox-admin" {
			continue
		}
		found = true
		if row["path_type"] != "direct control visible" {
			t.Fatalf("path_type = %v, want direct control visible", row["path_type"])
		}
		if row["visibility_tier"] != "high" {
			t.Fatalf("visibility_tier = %v, want high", row["visibility_tier"])
		}
		if row["confidence_boundary"] != "Current scope confirms these workload fields are changeable: image, env, service account." {
			t.Fatalf("confidence_boundary = %v", row["confidence_boundary"])
		}
	}
	if !found {
		t.Fatalf("paths = %#v, want exact env patch row", paths)
	}
}

func TestBuildSelectedChainPayloadBuildsExactServiceAccountSwitchRowWhenOneStrongerCandidateIsVisible(t *testing.T) {
	namespace := "default"
	payload, err := buildSelectedChainPayload(stubInventoryProvider{
		metadataContext: model.MetadataContext{
			ContextName: "lab-cluster",
			ClusterName: "lab-cluster",
			Namespace:   namespace,
		},
		whoamiData: model.WhoAmIData{
			CurrentIdentity: model.CurrentIdentity{
				Label:      "fox-operator",
				Kind:       "User",
				Confidence: "direct",
			},
		},
		workloadsData: model.WorkloadsData{
			WorkloadAssets: []model.Workload{
				{
					ID:                 "pod:default:web",
					Name:               "web",
					Namespace:          namespace,
					Kind:               "Pod",
					ServiceAccountName: "web",
					Images:             []string{"nginx:1.27"},
				},
				{
					ID:                 "pod:default:fox-admin",
					Name:               "fox-admin",
					Namespace:          namespace,
					Kind:               "Pod",
					ServiceAccountName: "fox-admin",
					Images:             []string{"ghcr.io/example/fox-admin:latest"},
				},
				{
					ID:                 "pod:default:builder",
					Name:               "builder",
					Namespace:          namespace,
					Kind:               "Pod",
					ServiceAccountName: "builder",
					Images:             []string{"ghcr.io/example/builder:latest"},
				},
			},
		},
		serviceAccountsData: model.ServiceAccountsData{
			ServiceAccounts: []model.ServiceAccount{
				{
					ID:        "serviceaccount:default:web",
					Name:      "web",
					Namespace: namespace,
				},
				{
					ID:        "serviceaccount:default:fox-admin",
					Name:      "fox-admin",
					Namespace: namespace,
				},
				{
					ID:        "serviceaccount:default:builder",
					Name:      "builder",
					Namespace: namespace,
				},
			},
		},
		rbacData: model.RBACData{
			RoleGrants: []model.RBACGrant{
				{
					ID:             "grant:user:patch-pods",
					BindingName:    "user-patch-pods",
					Scope:          "namespace/default",
					SubjectKind:    "User",
					SubjectName:    "fox-operator",
					EvidenceStatus: "direct",
					WorkloadActions: []model.WorkloadAction{
						{
							Verb:            "patch",
							TargetGroup:     "pods",
							TargetResources: []string{"pods"},
							Summary:         "can patch pods",
						},
					},
				},
				{
					ID:               "grant:sa:cluster-admin",
					BindingName:      "fox-admin-cluster-admin",
					Scope:            "cluster-wide",
					SubjectKind:      "ServiceAccount",
					SubjectName:      "fox-admin",
					SubjectNamespace: &namespace,
					EvidenceStatus:   "direct",
					DangerousRights:  []string{"admin-like wildcard access"},
				},
				{
					ID:               "grant:sa:builder-workloads",
					BindingName:      "builder-workloads",
					Scope:            "namespace/default",
					SubjectKind:      "ServiceAccount",
					SubjectName:      "builder",
					SubjectNamespace: &namespace,
					EvidenceStatus:   "direct",
					DangerousRights:  []string{"change workloads"},
				},
			},
		},
	}, provider.QueryOptions{}, "workload-identity-pivot")
	if err != nil {
		t.Fatalf("buildSelectedChainPayload() error = %v", err)
	}

	paths, ok := payload["paths"].([]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("paths = %#v, want non-empty []any", payload["paths"])
	}

	found := false
	for _, raw := range paths {
		row := requireMap(t, raw)
		if row["path_type"] != "direct control visible" {
			continue
		}
		if row["likely_kubernetes_control"] != "service account default/fox-admin has cluster-wide admin-like access" {
			continue
		}
		found = true
		if row["confidence_boundary"] != "Current scope confirms the workload service account field is changeable, and namespace default shows one visible replacement service account with stronger downstream control: default/fox-admin." {
			t.Fatalf("confidence_boundary = %v", row["confidence_boundary"])
		}
	}
	if !found {
		t.Fatalf("paths = %#v, want exact service-account switch row", paths)
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

	rendered := normalizedTableText(stdout.String())
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

	rendered := normalizedTableText(stdout.String())
	for _, want := range []string{
		"priority",
		"scope",
		"subject",
		"role",
		"signal",
		"attack angle",
		"cluster-admin*",
		"ServiceAccount",
		"default/fox-admin",
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
