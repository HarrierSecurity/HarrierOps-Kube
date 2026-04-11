package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	liptable "github.com/charmbracelet/lipgloss/table"

	"harrierops-kube/internal/model"
)

var rowCollections = map[string]string{
	"chains":           "families",
	"rbac":             "role_grants",
	"service-accounts": "service_accounts",
	"exposure":         "exposure_assets",
	"workloads":        "workload_assets",
	"permissions":      "permissions",
	"secrets":          "secret_paths",
	"privesc":          "escalation_paths",
	"images":           "image_assets",
}

func WriteArtifacts(command string, payload map[string]any, outDir string) (map[string]string, error) {
	jsonPayload, err := marshalJSON(payload)
	if err != nil {
		return nil, err
	}
	lootPayload, err := marshalLoot(command, payload)
	if err != nil {
		return nil, err
	}

	tablePayload, err := renderTable(command, payload)
	if err != nil {
		return nil, err
	}

	csvPayload, err := renderCSV(command, payload)
	if err != nil {
		return nil, err
	}

	paths := map[string]string{
		"loot":  filepath.Join(outDir, "loot", command+".json"),
		"json":  filepath.Join(outDir, "json", command+".json"),
		"table": filepath.Join(outDir, "table", command+".txt"),
		"csv":   filepath.Join(outDir, "csv", command+".csv"),
	}

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}

	if err := os.WriteFile(paths["loot"], lootPayload, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["json"], jsonPayload, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["table"], []byte(tablePayload), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["csv"], []byte(csvPayload), 0o644); err != nil {
		return nil, err
	}

	return paths, nil
}

func Render(mode string, command string, payload map[string]any) (string, error) {
	switch mode {
	case "table":
		return renderTable(command, payload)
	case "json":
		data, err := marshalJSON(payload)
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	case "csv":
		return renderCSV(command, payload)
	default:
		return "", fmt.Errorf("unsupported output mode: %s", mode)
	}
}

func marshalJSON(payload map[string]any) ([]byte, error) {
	return json.MarshalIndent(payload, "", "  ")
}

func marshalLoot(command string, payload map[string]any) ([]byte, error) {
	lootPayload := payload
	if command == "chains" {
		return json.MarshalIndent(lootPayload, "", "  ")
	}
	if command == "inventory" {
		lootPayload = selectLootFields(payload, "metadata", "visibility", "environment", "exposure_footprint", "risky_workload_footprint", "identity_footprint", "next_commands", "issues")
	}
	if command == "rbac" {
		lootPayload = selectLootFields(payload, "metadata", "issues")
		if grants, err := rowsForKey(payload, "role_grants"); err == nil {
			lootPayload["role_grants"] = selectLootRows(grants)
		}
	}
	if command == "service-accounts" {
		lootPayload = selectLootFields(payload, "metadata", "findings", "issues")
		if serviceAccounts, err := rowsForKey(payload, "service_accounts"); err == nil {
			lootPayload["service_accounts"] = selectLootRows(serviceAccounts)
		}
	}
	if command == "workloads" {
		lootPayload = selectLootFields(payload, "metadata", "findings", "issues")
		if workloads, err := rowsForKey(payload, "workload_assets"); err == nil {
			lootPayload["workload_assets"] = selectLootRows(workloads)
		}
	}
	if command == "exposure" {
		lootPayload = selectLootFields(payload, "metadata", "findings", "issues")
		if exposures, err := rowsForKey(payload, "exposure_assets"); err == nil {
			lootPayload["exposure_assets"] = selectLootRows(exposures)
		}
	}
	if command == "permissions" {
		lootPayload = selectLootFields(payload, "metadata", "issues")
		if permissions, err := rowsForKey(payload, "permissions"); err == nil {
			lootPayload["permissions"] = selectLootRows(permissions)
		}
	}
	if command == "secrets" {
		lootPayload = selectLootFields(payload, "metadata", "issues")
		if secretPaths, err := rowsForKey(payload, "secret_paths"); err == nil {
			lootPayload["secret_paths"] = selectLootRows(secretPaths)
		}
	}
	if command == "privesc" {
		lootPayload = selectLootFields(payload, "metadata", "issues")
		if escalationPaths, err := rowsForKey(payload, "escalation_paths"); err == nil {
			lootPayload["escalation_paths"] = selectLootRows(escalationPaths)
		}
	}

	return json.MarshalIndent(lootPayload, "", "  ")
}

func renderTable(command string, payload map[string]any) (string, error) {
	var rendered string
	var err error

	if command == "whoami" {
		rendered, err = renderWhoAmITable(payload)
	} else if command == "chains" {
		rendered, err = renderChainsTable(payload)
	} else if command == "inventory" {
		rendered, err = renderInventoryTable(payload)
	} else if command == "rbac" {
		rendered, err = renderRBACTable(payload)
	} else if command == "service-accounts" {
		rendered, err = renderServiceAccountsTable(payload)
	} else if command == "workloads" {
		rendered, err = renderWorkloadsTable(payload)
	} else if command == "exposure" {
		rendered, err = renderExposureTable(payload)
	} else if command == "permissions" {
		rendered, err = renderPermissionsTable(payload)
	} else if command == "secrets" {
		rendered, err = renderSecretsTable(payload)
	} else if command == "privesc" {
		rendered, err = renderPrivescTable(payload)
	} else {
		rowKey, ok := rowCollections[command]
		if !ok {
			rendered, err = renderKeyValueTable(payload)
		} else {
			rows, rowsErr := rowsForKey(payload, rowKey)
			if rowsErr != nil {
				return "", rowsErr
			}
			if len(rows) == 0 {
				rendered, err = renderSimpleTableWithLipgloss([]string{"info"}, [][]string{{"No records"}})
			} else {
				headers := collectHeaders(rows)
				records := make([][]string, 0, len(rows))
				for _, row := range rows {
					values := make([]string, 0, len(headers))
					for _, header := range headers {
						values = append(values, stringify(row[header]))
					}
					records = append(records, values)
				}
				rendered, err = renderSimpleTableWithLipgloss(headers, records)
			}
		}
	}
	if err != nil {
		return "", err
	}

	if command == "chains" {
		return rendered, nil
	}

	title := "harrierops-kube " + command
	if strings.TrimSpace(rendered) == "" {
		return title + "\n", nil
	}
	return title + "\n\n" + rendered, nil
}

func renderCSV(command string, payload map[string]any) (string, error) {
	rowKey, ok := rowCollections[command]
	if !ok {
		rowKey = ""
	}
	if command == "chains" {
		if _, hasPaths := payload["paths"]; hasPaths {
			rowKey = "paths"
		}
	}

	var rows []map[string]any
	var err error
	if rowKey == "" {
		rows = []map[string]any{payload}
	} else {
		rows, err = rowsForKey(payload, rowKey)
		if err != nil {
			return "", err
		}
	}

	if len(rows) == 0 {
		return "", nil
	}

	headers := collectHeaders(rows)
	buffer := &bytes.Buffer{}
	writer := csv.NewWriter(buffer)

	if err := writer.Write(headers); err != nil {
		return "", err
	}

	for _, row := range rows {
		record := make([]string, 0, len(headers))
		for _, header := range headers {
			record = append(record, stringify(row[header]))
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func renderKeyValueTable(payload map[string]any) (string, error) {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	records := make([][]string, 0, len(keys))
	for _, key := range keys {
		records = append(records, []string{key, stringify(payload[key])})
	}
	return renderSimpleTableWithLipgloss([]string{"field", "value"}, records)
}

func renderChainsTable(payload map[string]any) (string, error) {
	if _, ok := payload["paths"]; ok {
		return renderChainsFamilyTable(payload)
	}

	allRows, err := rowsForKey(payload, "families")
	if err != nil {
		return "", err
	}
	rows := make([]map[string]any, 0, len(allRows))
	for _, row := range allRows {
		if stringify(row["state"]) == "implemented" {
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		if len(allRows) > 0 {
			return "harrierops-kube chains\n\n" + renderTriageEmptyState(payload, "No runnable chain families are currently registered. The default overview shows runnable families only."), nil
		}
		return "harrierops-kube chains\n\n" + renderTriageEmptyState(payload, "No chain families are currently registered."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		sourceCommands := "none"
		if sources, ok := row["source_commands"].([]any); ok && len(sources) > 0 {
			parts := make([]string, 0, len(sources))
			for _, source := range sources {
				if mapping, ok := source.(map[string]any); ok {
					parts = append(parts, stringify(mapping["command"]))
				}
			}
			if len(parts) > 0 {
				sourceCommands = strings.Join(parts, ", ")
			}
		}

		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["family"]),
				stringify(row["summary"]),
				sourceCommands,
				chainsFamilyNote(row),
			},
			detail: chainsFamilyOperatorGuide(row),
		})
	}

	rendered, err := renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"family", "summary", "backing commands", "offensive value"},
		records,
		"attack briefing",
		"No runnable chain families are currently registered.",
		"",
	)
	if err != nil {
		return "", err
	}
	headerLines := []string{"harrierops-kube chains"}
	if len(rows) != len(allRows) {
		omitted := len(allRows) - len(rows)
		headerLines = append(headerLines, fmt.Sprintf("Showing runnable families only; %d non-runnable famil%s omitted.", omitted, pluralSuffix(omitted, "y", "ies")))
	}
	return strings.Join(headerLines, "\n") + "\n\n" + rendered, nil
}

func renderChainsFamilyTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "paths")
	if err != nil {
		return "", err
	}
	header := renderChainsFamilyHeader(payload)
	if len(rows) == 0 {
		return header + "\n\n" + renderTriageEmptyState(payload, "No bounded workload-identity pivot rows were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		control := stringify(row["likely_kubernetes_control"])
		if control == "" {
			control = "control still bounded"
		}

		detailParts := []string{}
		if missing := chainsMissingStep(row); missing != "" {
			detailParts = append(detailParts, "Missing step:\n"+missing)
		}
		if boundary := stringify(row["confidence_boundary"]); boundary != "" {
			detailParts = append(detailParts, "Boundary:\n"+boundary)
		}
		if reason := stringify(row["why_stop_here"]); reason != "" {
			detailParts = append(detailParts, "Why this stops here:\n"+reason)
		}
		if summary := stringify(row["summary"]); summary != "" {
			detailParts = append(detailParts, "Read:\n"+summary)
		}

		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				stringify(row["source_asset"]),
				stringify(row["subversion_point"]),
				stringify(row["path_type"]),
				control,
				stringify(row["visibility_tier"]),
				chainsMissingStep(row),
			},
			detail: strings.Join(detailParts, "\n\n"),
		})
	}

	rendered, err := renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "workload", "subversion point", "path type", "kubernetes control", "visibility", "missing step"},
		records,
		"note",
		"No bounded workload-identity pivot rows were confirmed from current scope.",
		"",
	)
	if err != nil {
		return "", err
	}
	return header + "\n\n" + rendered, nil
}

func renderChainsFamilyHeader(payload map[string]any) string {
	title := "harrierops-kube chains"
	if family := stringify(payload["family"]); family != "" {
		title += " " + family
	}

	lines := []string{title}
	if summary := stringify(payload["summary"]); summary != "" {
		lines = append(lines, "Summary: "+summary)
	}
	if backingCommands := stringifyAnySlice(payload["backing_commands"], ", "); backingCommands != "" {
		lines = append(lines, "Backing commands: "+backingCommands)
	}
	return strings.Join(lines, "\n")
}

func renderWhoAmITable(payload map[string]any) (string, error) {
	var rows [][2]string

	addValueRow := func(label string, value any) {
		text := stringify(value)
		if text == "" || text == "null" {
			return
		}
		rows = append(rows, [2]string{label, text})
	}
	addStringSliceRow := func(label string, value any) {
		items, ok := value.([]any)
		if !ok || len(items) == 0 {
			return
		}

		parts := make([]string, 0, len(items))
		for _, item := range items {
			part := stringify(item)
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) == 0 {
			return
		}
		rows = append(rows, [2]string{label, strings.Join(parts, "; ")})
	}

	kubeContext, _ := payload["kube_context"].(map[string]any)
	currentIdentity, _ := payload["current_identity"].(map[string]any)
	session, _ := payload["session"].(map[string]any)

	addValueRow("Cluster", kubeContext["cluster_name"])
	addValueRow("API Server", kubeContext["server"])
	addValueRow("Context", kubeContext["current_context"])
	addValueRow("Namespace", kubeContext["namespace"])
	addValueRow("Kubeconfig User", kubeContext["user"])
	addValueRow("Server Version", kubeContext["server_version"])

	addValueRow("Identity", currentIdentity["label"])
	addValueRow("Identity Kind", currentIdentity["kind"])
	addValueRow("Identity Namespace", currentIdentity["namespace"])
	addValueRow("Identity Confidence", currentIdentity["confidence"])

	addValueRow("Foothold Family", session["foothold_family"])
	addValueRow("Auth Material", session["auth_material_type"])
	addValueRow("Execution Origin", session["execution_origin"])
	addValueRow("Visibility Scope", session["visibility_scope"])
	addValueRow("Environment Hint", pathValue(payload, "environment_hint", "summary"))
	addValueRow("Environment Type", pathValue(payload, "environment_hint", "type"))
	addValueRow("Environment Confidence", pathValue(payload, "environment_hint", "confidence"))
	addStringSliceRow("Environment Evidence", pathValue(payload, "environment_hint", "evidence"))

	addStringSliceRow("Identity Evidence", payload["identity_evidence"])
	addStringSliceRow("Visibility Blockers", payload["visibility_blockers"])
	if issues, ok := payload["issues"].([]any); ok && len(issues) > 0 {
		parts := make([]string, 0, len(issues))
		for _, issue := range issues {
			if mapping, ok := issue.(map[string]any); ok {
				message := stringify(mapping["message"])
				scope := stringify(mapping["scope"])
				if scope != "" && message != "" {
					parts = append(parts, scope+": "+message)
					continue
				}
			}
			parts = append(parts, stringify(issue))
		}
		rows = append(rows, [2]string{"Issues", strings.Join(parts, "; ")})
	}

	records := make([][]string, 0, len(rows))
	for _, row := range rows {
		records = append(records, []string{row[0], row[1]})
	}
	return renderSimpleTableWithLipgloss([]string{"field", "value"}, records)
}

func renderInventoryTable(payload map[string]any) (string, error) {
	var rows [][2]string
	addValueRow := func(label string, value any) {
		text := stringify(value)
		if text == "" || text == "null" {
			return
		}
		rows = append(rows, [2]string{label, text})
	}

	addValueRow("Visibility", pathValue(payload, "visibility", "summary"))
	addValueRow("Visibility Scope", pathValue(payload, "visibility", "scope"))
	addValueRow("Visibility Assessment", pathValue(payload, "visibility", "assessment"))

	addValueRow("Environment", pathValue(payload, "environment", "summary"))
	addValueRow("Environment Type", pathValue(payload, "environment", "type"))
	addValueRow("Environment Confidence", pathValue(payload, "environment", "confidence"))
	if evidence, ok := pathValue(payload, "environment", "evidence").([]any); ok && len(evidence) > 0 {
		parts := make([]string, 0, len(evidence))
		for _, item := range evidence {
			parts = append(parts, stringify(item))
		}
		rows = append(rows, [2]string{"Environment Evidence", strings.Join(parts, "; ")})
	}

	addValueRow("Exposure Footprint", pathValue(payload, "exposure_footprint", "summary"))
	addValueRow("Public Paths", pathValue(payload, "exposure_footprint", "public_paths"))
	addValueRow("Ingresses", pathValue(payload, "exposure_footprint", "ingresses"))
	addValueRow("LoadBalancers", pathValue(payload, "exposure_footprint", "load_balancers"))
	addValueRow("NodePorts", pathValue(payload, "exposure_footprint", "node_ports"))
	addValueRow("Host Exposure Pods", pathValue(payload, "exposure_footprint", "host_exposure_pods"))

	addValueRow("Risky Workloads", pathValue(payload, "risky_workload_footprint", "summary"))
	addValueRow("Privileged Workloads", pathValue(payload, "risky_workload_footprint", "privileged_workloads"))
	addValueRow("Host-Touching Workloads", pathValue(payload, "risky_workload_footprint", "host_touching_workloads"))
	addValueRow("Host Namespace Workloads", pathValue(payload, "risky_workload_footprint", "host_namespace_workloads"))
	addValueRow("Docker Socket Workloads", pathValue(payload, "risky_workload_footprint", "docker_socket_workloads"))

	addValueRow("Identity Footprint", pathValue(payload, "identity_footprint", "summary"))
	addValueRow("Service Accounts", pathValue(payload, "identity_footprint", "service_accounts"))
	addValueRow("Role Grants", pathValue(payload, "identity_footprint", "role_grants"))
	addValueRow("Cluster-Wide Grants", pathValue(payload, "identity_footprint", "cluster_wide_role_grants"))
	addValueRow("High-Impact Service Accounts", pathValue(payload, "identity_footprint", "high_impact_service_accounts"))

	if nextCommands, ok := payload["next_commands"].([]any); ok && len(nextCommands) > 0 {
		parts := make([]string, 0, len(nextCommands))
		for _, item := range nextCommands {
			commandHint, ok := item.(map[string]any)
			if !ok {
				continue
			}
			command := stringify(commandHint["command"])
			why := stringify(commandHint["why"])
			if command != "" && why != "" {
				parts = append(parts, command+": "+why)
			}
		}
		if len(parts) > 0 {
			rows = append(rows, [2]string{"Next Commands", strings.Join(parts, "; ")})
		}
	}

	countSections := []struct {
		label string
		key   string
	}{
		{label: "Kubernetes Counts", key: "kubernetes_counts"},
		{label: "Docker Counts", key: "docker_counts"},
	}
	for _, section := range countSections {
		mapping, ok := payload[section.key].(map[string]any)
		if !ok || len(mapping) == 0 {
			continue
		}
		keys := make([]string, 0, len(mapping))
		for key := range mapping {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+stringify(mapping[key]))
		}
		rows = append(rows, [2]string{section.label, strings.Join(parts, ", ")})
	}

	records := make([][]string, 0, len(rows))
	for _, row := range rows {
		records = append(records, []string{row[0], row[1]})
	}
	return renderSimpleTableWithLipgloss([]string{"field", "value"}, records)
}

func renderRBACTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "role_grants")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible RBAC grants were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		signal := stringify(row["evidence_status"])
		if dangerous, ok := row["dangerous_rights"].([]any); ok && len(dangerous) > 0 {
			parts := make([]string, 0, len(dangerous))
			for _, item := range dangerous {
				parts = append(parts, stringify(item))
			}
			signal = strings.Join(parts, "; ")
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				stringify(row["scope"]),
				stringify(row["subject_display"]),
				stringify(row["role_display_name"]),
				stringify(row["binding_name"]),
				signal,
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "scope", "subject", "role", "binding", "signal"},
		records,
		"attack angle",
		"No visible RBAC grants were confirmed from current scope.",
		"RBAC grant(s)",
	)
}

func renderServiceAccountsTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "service_accounts")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible service-account identity paths were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		serviceAccount := strings.TrimPrefix(stringify(row["namespace"])+"/"+stringify(row["name"]), "/")
		workloads := stringify(row["workload_count"]) + " visible workload"
		if stringify(row["workload_count"]) != "1" {
			workloads += "s"
		}
		if related, ok := row["related_workloads"].([]any); ok && len(related) == 1 {
			workloads = stringify(related[0])
		}
		power := stringify(row["power_summary"])
		if power == "" {
			power = "no strong power signal"
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				serviceAccount,
				workloads,
				power,
				stringify(row["token_posture"]),
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "service_account", "workloads", "power", "token_posture"},
		records,
		"attack angle",
		"No visible service-account identity paths were confirmed from current scope.",
		"service-account identity path(s)",
	)
}

func renderWorkloadsTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "workload_assets")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible workloads rose into triage from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		workload := strings.TrimPrefix(stringify(row["namespace"])+"/"+stringify(row["name"]), "/")
		exposure := "no exposed path seen"
		if related, ok := row["related_exposures"].([]any); ok && len(related) > 0 {
			parts := make([]string, 0, len(related))
			for _, item := range related {
				parts = append(parts, stringify(item))
			}
			exposure = strings.Join(parts, "; ")
		}
		execution := "none seen"
		if riskSignals, ok := row["risk_signals"].([]any); ok && len(riskSignals) > 0 {
			execution = strings.Join(stringifyAnySliceParts(riskSignals), "; ")
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				workload,
				stringify(row["identity_summary"]),
				exposure,
				execution,
			},
			detail: workloadAttackAngle(row),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "workload", "identity", "exposure", "execution"},
		records,
		"attack angle",
		"No visible workloads rose into triage from current scope.",
		"workload row(s)",
	)
}

func renderExposureTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "exposure_assets")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible exposure paths were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		exposure := stringify(row["exposure_type"]) + " " + strings.TrimPrefix(stringify(row["namespace"])+"/"+stringify(row["name"]), "/")
		targets := "no visible external target"
		if externalTargets, ok := row["external_targets"].([]any); ok && len(externalTargets) > 0 {
			parts := make([]string, 0, len(externalTargets))
			for _, item := range externalTargets {
				parts = append(parts, stringify(item))
			}
			targets = strings.Join(parts, "; ")
		}
		attribution := stringify(row["attribution_status"])
		if related, ok := row["related_workloads"].([]any); ok && len(related) > 0 {
			parts := make([]string, 0, len(related))
			for _, item := range related {
				parts = append(parts, stringify(item))
			}
			attribution += " -> " + strings.Join(parts, "; ")
		}
		backend := stringify(row["backend_signal"])
		if identitySummary := stringify(row["identity_summary"]); identitySummary != "" {
			backend = identitySummary
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				exposure,
				targets,
				attribution,
				backend,
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "exposure", "targets", "attribution", "backend"},
		records,
		"attack angle",
		"No visible exposure paths were confirmed from current scope.",
		"exposure path(s)",
	)
}

func renderPermissionsTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "permissions")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible current-session capability paths were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				stringify(row["subject"]),
				stringify(row["subject_confidence"]),
				stringify(row["evidence_source"]),
				stringify(row["action_summary"]),
				stringify(row["scope"]),
				stringify(row["next_review"]),
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "subject", "confidence", "source", "action", "scope", "next_review"},
		records,
		"attack angle",
		"No visible current-session capability paths were confirmed from current scope.",
		"current-session capability path(s)",
	)
}

func renderSecretsTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "secret_paths")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible secret paths were confirmed from current scope."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		path := stringify(row["source_surface"]) + ": " + stringify(row["safe_label"])
		linkage := stringify(row["subject"])
		if related, ok := row["related_workloads"].([]any); ok && len(related) > 0 {
			parts := make([]string, 0, len(related))
			for _, item := range related {
				parts = append(parts, stringify(item))
			}
			linkage += " -> " + strings.Join(parts, "; ")
		}
		target := stringify(row["likely_secret_type"])
		if family := stringify(row["likely_target_family"]); family != "" {
			target += " -> " + family
		}
		if directUse := stringify(row["direct_use_confidence"]); directUse != "" {
			target += " (" + directUse + ")"
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				stringify(row["secret_story"]),
				path,
				linkage,
				target,
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "story", "path", "linkage", "target"},
		records,
		"attack angle",
		"No visible secret paths were confirmed from current scope.",
		"secret path(s)",
	)
}

func renderPrivescTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "escalation_paths")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return renderTriageEmptyState(payload, "No visible escalation paths were confirmed from the current foothold."), nil
	}

	records := make([]detailTableRecord, 0, len(rows))
	for _, row := range rows {
		outcome := stringify(row["stronger_outcome"])
		if power := stringify(row["outcome_power"]); power != "" {
			outcome += " -> " + power
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				stringify(row["path_class"]),
				stringify(row["starting_foothold"]),
				stringify(row["action"]),
				outcome,
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTableWithLipgloss(
		payload,
		[]string{"priority", "class", "foothold", "action", "outcome"},
		records,
		"attack angle",
		"No visible escalation paths were confirmed from the current foothold.",
		"escalation path(s)",
	)
}

func stringifyAnySliceParts(value any) []string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		part := stringify(item)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func workloadAttackAngle(row map[string]any) string {
	parts := []string{}
	if stringify(row["public_exposure"]) == "true" {
		parts = append(parts, "outside-facing traffic lands on this workload.")
	} else if related := stringifyAnySlice(row["related_exposures"], "; "); related != "" {
		parts = append(parts, "an exposed path is visible for this workload.")
	}

	if power := stringify(row["service_account_power"]); power != "" {
		parts = append(parts, "this workload runs as an identity that "+power+".")
	}

	if riskSignals, ok := row["risk_signals"].([]any); ok && len(riskSignals) > 0 {
		if translation := model.WorkloadRiskAttackAngle(stringifyAnySliceParts(riskSignals)); translation != "" {
			parts = append(parts, translation)
		}
	}

	if len(parts) == 0 {
		return stringify(row["why_care"])
	}
	return strings.Join(parts, " ")
}

func chainsFamilyNote(row map[string]any) string {
	if meaning := stringify(row["meaning"]); meaning != "" {
		return meaning
	}
	if stringify(row["state"]) == "planned" {
		return "Scaffold only; runnable grouped path rows are not implemented yet."
	}
	return stringify(row["summary"])
}

// Keep the grouped-family truth model, but render it with operator-facing labels
// so the overview reads like an attack briefing instead of internal contract prose.
func chainsFamilyOperatorGuide(row map[string]any) string {
	sections := []string{
		"What this surfaces:\n" + chainsOperatorQuestion(row),
		"Current family coverage:\n" + stringify(row["allowed_claim"]),
		"Current family coverage limits:\n" + stringify(row["current_gap"]),
	}
	if guide := stringifyChainsPathTypeGuide(row["path_type_guide"]); guide != "" {
		sections = append(sections, "Row types you may see:\n- "+strings.ReplaceAll(guide, " | ", "\n- "))
	}
	if examples := stringifyAnySlice(row["best_current_examples"], "; "); examples != "" {
		sections = append(sections, "Current evidence joins in this family:\n- "+strings.ReplaceAll(examples, "; ", "\n- "))
	}
	return strings.Join(sections, "\n\n")
}

func chainsOperatorQuestion(row map[string]any) string {
	if summary := stringify(row["summary"]); summary != "" {
		return summary
	}
	if meaning := stringify(row["meaning"]); meaning != "" {
		return meaning
	}
	return "Which grouped path family is most worth running from current scope?"
}

func chainsMissingStep(row map[string]any) string {
	return stringify(row["missing_confirmation"])
}

func pluralSuffix(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func stringifyChainsPathTypeGuide(value any) string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		mapping, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringify(mapping["name"])
		meaning := stringify(mapping["meaning"])
		if name == "" || meaning == "" {
			continue
		}
		parts = append(parts, name+": "+meaning)
	}
	return strings.Join(parts, " | ")
}

func stringifyAnySlice(value any, separator string) string {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		part := stringify(item)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, separator)
}

type detailTableRecord struct {
	columns []string
	detail  string
}

func renderDetailedTriageTableWithLipgloss(payload map[string]any, headers []string, records []detailTableRecord, detailLabel string, emptyMessage string, takeawayNoun string) (string, error) {
	if len(records) == 0 {
		return renderTriageEmptyState(payload, emptyMessage), nil
	}

	rawRecords := make([][]string, 0, len(records))
	for _, record := range records {
		rawRecords = append(rawRecords, record.columns)
	}
	widths := boundedASCIIWidths(headers, rawRecords)

	var builder strings.Builder
	for index, record := range records {
		rendered, err := renderDetailedRecordTableWithLipgloss(headers, widths, record.columns, detailLabel, record.detail)
		if err != nil {
			return "", err
		}
		builder.WriteString(rendered)
		if index != len(records)-1 {
			builder.WriteByte('\n')
		}
	}
	spanWidth := asciiTableSpanWidth(widths)
	appendIssueSection(&builder, payload, spanWidth)
	appendTakeaway(&builder, takeawayNoun, records, spanWidth)
	return builder.String(), nil
}

func renderTriageEmptyState(payload map[string]any, emptyMessage string) string {
	var builder strings.Builder
	rendered, err := renderSimpleTableWithLipgloss([]string{"info"}, [][]string{{emptyMessage}})
	if err == nil {
		builder.WriteString(rendered)
	}
	appendIssueSection(&builder, payload, 0)
	return builder.String()
}

func appendIssueSection(builder *strings.Builder, payload map[string]any, width int) {
	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) == 0 {
		return
	}

	rows := make([]string, 0, len(issues))
	for _, issue := range issues {
		rows = append(rows, formatIssue(issue))
	}

	rendered, err := renderLabeledRowsTable(width, "Issues", rows)
	if err != nil {
		return
	}

	builder.WriteByte('\n')
	builder.WriteString(rendered)
	if !strings.HasSuffix(rendered, "\n") {
		builder.WriteByte('\n')
	}
}

func appendTakeaway(builder *strings.Builder, noun string, records []detailTableRecord, width int) {
	if noun == "" || len(records) == 0 {
		return
	}

	counts := map[string]int{}
	for _, record := range records {
		if len(record.columns) == 0 {
			continue
		}
		priority := strings.ToLower(strings.TrimSpace(record.columns[0]))
		if priority != "" {
			counts[priority]++
		}
	}

	summary := fmt.Sprintf("%d visible %s", len(records), noun)
	if counts["high"] > 0 || counts["medium"] > 0 || counts["low"] > 0 {
		summary += fmt.Sprintf("; %d high, %d medium, %d low", counts["high"], counts["medium"], counts["low"])
	}
	summary += "."

	rendered, err := renderLabeledRowsTable(width, "Takeaway:", []string{summary})
	if err != nil {
		builder.WriteString("\nTakeaway: ")
		builder.WriteString(summary)
		builder.WriteByte('\n')
		return
	}

	builder.WriteByte('\n')
	builder.WriteString(rendered)
	if !strings.HasSuffix(rendered, "\n") {
		builder.WriteByte('\n')
	}
}

func renderLabeledRowsTable(width int, label string, rows []string) (string, error) {
	if len(rows) == 0 {
		return "", nil
	}
	if width <= 0 {
		records := make([][]string, 0, len(rows))
		for _, row := range rows {
			records = append(records, []string{row})
		}
		return renderSimpleTableWithLipgloss([]string{label}, records)
	}

	table := newCalloutLipglossTable(width, label)
	for _, row := range rows {
		table.Row(row)
	}
	return table.String(), nil
}

func formatIssue(issue any) string {
	mapping, ok := issue.(map[string]any)
	if !ok {
		return stringify(issue)
	}

	kind := stringify(mapping["kind"])
	scope := stringify(mapping["scope"])
	message := stringify(mapping["message"])
	if kind != "" && scope != "" && message != "" {
		return kind + " (" + scope + "): " + message
	}
	if kind != "" && message != "" {
		return kind + ": " + message
	}
	if scope != "" && message != "" {
		return scope + ": " + message
	}
	if message != "" {
		return message
	}
	return stringify(issue)
}

func renderSimpleTableWithLipgloss(headers []string, records [][]string) (string, error) {
	if len(headers) == 0 {
		return "", nil
	}

	widths := boundedASCIIWidths(headers, records)
	table := newStandardLipglossTable(widths).Headers(headers...)
	for _, record := range records {
		table.Row(record...)
	}
	return table.String(), nil
}

func renderUnicodeTable(headers []string, widths []int, records [][]string) string {
	var builder strings.Builder
	builder.WriteString(unicodeTableBorder(widths, '┏', '┳', '┓', '━'))
	builder.WriteByte('\n')
	builder.WriteString(unicodeTableRow(headers, widths))
	builder.WriteByte('\n')
	builder.WriteString(unicodeTableBorder(widths, '┡', '╇', '┩', '━'))
	builder.WriteByte('\n')
	for _, record := range records {
		for _, line := range unicodeWrappedRowLines(record, widths) {
			builder.WriteString(line)
			builder.WriteByte('\n')
		}
	}
	builder.WriteString(unicodeTableBorder(widths, '└', '┴', '┘', '─'))
	builder.WriteByte('\n')
	return builder.String()
}

func renderUnicodeDetailTable(header string, width int, detail string) string {
	headers := []string{header}
	widths := []int{width}
	records := [][]string{{detail}}
	return renderUnicodeTable(headers, widths, records)
}

func renderDetailedRecordTableWithLipgloss(headers []string, widths []int, record []string, detailLabel string, detail string) (string, error) {
	if len(headers) == 0 {
		return "", nil
	}

	var builder strings.Builder
	builder.WriteString(newStandardLipglossTable(widths).Headers(headers...).Row(record...).String())
	if detail == "" {
		return builder.String(), nil
	}

	builder.WriteByte('\n')
	builder.WriteString(newAttachedDetailLipglossTable(asciiTableSpanWidth(widths), detailLabel).Row(detail).String())
	return builder.String(), nil
}

func newStandardLipglossTable(widths []int) *liptable.Table {
	return liptable.New().
		Border(lipgloss.ASCIIBorder()).
		BorderTop(true).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		BorderHeader(true).
		BorderColumn(true).
		BorderRow(false).
		StyleFunc(func(row, col int) lipgloss.Style {
			return lipgloss.NewStyle().
				Padding(0, 1).
				Width(lipglossCellWidth(lipglossColumnWidth(widths, col)))
		})
}

func newAttachedDetailLipglossTable(width int, label string) *liptable.Table {
	return liptable.New().
		Border(lipgloss.ASCIIBorder()).
		BorderTop(false).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		BorderHeader(true).
		BorderColumn(true).
		BorderRow(false).
		Headers(label).
		StyleFunc(func(row, col int) lipgloss.Style {
			return lipgloss.NewStyle().
				Padding(0, 1).
				Width(lipglossCellWidth(width))
		})
}

func newCalloutLipglossTable(width int, label string) *liptable.Table {
	return liptable.New().
		Border(lipgloss.ASCIIBorder()).
		BorderTop(true).
		BorderBottom(true).
		BorderLeft(true).
		BorderRight(true).
		BorderHeader(true).
		BorderColumn(true).
		BorderRow(false).
		Headers(label).
		StyleFunc(func(row, col int) lipgloss.Style {
			return lipgloss.NewStyle().
				Padding(0, 1).
				Width(lipglossCellWidth(width))
		})
}

func lipglossColumnWidth(widths []int, index int) int {
	if index < 0 || index >= len(widths) {
		return 0
	}
	return widths[index]
}

func lipglossCellWidth(contentWidth int) int {
	if contentWidth <= 0 {
		return 0
	}
	return contentWidth + 2
}

func selectLootFields(payload map[string]any, keys ...string) map[string]any {
	lootPayload := map[string]any{}
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			lootPayload[key] = value
		}
	}
	return lootPayload
}

func selectLootRows(rows []map[string]any) []map[string]any {
	selected := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if stringify(row["priority"]) == "high" {
			selected = append(selected, row)
		}
	}
	if len(selected) == 0 && len(rows) > 0 {
		limit := min(3, len(rows))
		selected = append(selected, rows[:limit]...)
	}
	return selected
}

func unicodeTableBorder(widths []int, left rune, middle rune, right rune, fill rune) string {
	var builder strings.Builder
	builder.WriteRune(left)
	for index, width := range widths {
		builder.WriteString(strings.Repeat(string(fill), width+2))
		if index == len(widths)-1 {
			builder.WriteRune(right)
			continue
		}
		builder.WriteRune(middle)
	}
	return builder.String()
}

func unicodeTableRow(values []string, widths []int) string {
	lines := unicodeWrappedRowLines(values, widths)
	return strings.Join(lines, "\n")
}

func unicodeWrappedRowLines(values []string, widths []int) []string {
	wrappedColumns := make([][]string, len(widths))
	maxLines := 1
	for index, width := range widths {
		value := ""
		if index < len(values) {
			value = values[index]
		}
		wrapped := wrapTableText(value, width)
		if len(wrapped) == 0 {
			wrapped = []string{""}
		}
		wrappedColumns[index] = wrapped
		if len(wrapped) > maxLines {
			maxLines = len(wrapped)
		}
	}

	lines := make([]string, 0, maxLines)
	for lineIndex := 0; lineIndex < maxLines; lineIndex++ {
		var builder strings.Builder
		builder.WriteRune('│')
		for columnIndex, width := range widths {
			value := ""
			if lineIndex < len(wrappedColumns[columnIndex]) {
				value = normalizeTableCell(wrappedColumns[columnIndex][lineIndex])
			}
			builder.WriteByte(' ')
			builder.WriteString(value)
			builder.WriteString(strings.Repeat(" ", width-len(value)))
			builder.WriteByte(' ')
			builder.WriteRune('│')
		}
		lines = append(lines, builder.String())
	}
	return lines
}

func unicodeTableTotalWidth(widths []int) int {
	return len(unicodeTableBorder(widths, '┏', '┳', '┓', '━'))
}

func unicodeTableInnerWidth(widths []int) int {
	return unicodeTableTotalWidth(widths) - 4
}

func centerTableTitle(title string, width int) string {
	if width <= len(title) {
		return title
	}
	padding := width - len(title)
	left := padding / 2
	right := padding - left
	return strings.Repeat(" ", left) + title + strings.Repeat(" ", right)
}

func asciiTableSpanWidth(widths []int) int {
	total := 0
	for _, width := range widths {
		total += width
	}
	if len(widths) > 1 {
		total += 3 * (len(widths) - 1)
	}
	return total
}

func boundedASCIIWidths(headers []string, records [][]string) []int {
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = len(normalizeTableCell(header))
	}
	for _, record := range records {
		for index := 0; index < len(headers) && index < len(record); index++ {
			cellWidth := len(normalizeTableCell(record[index]))
			if cellWidth > widths[index] {
				widths[index] = cellWidth
			}
		}
	}

	if len(headers) == 1 {
		if widths[0] > 96 {
			widths[0] = 96
		}
		return widths
	}

	if len(headers) == 2 && strings.EqualFold(headers[0], "field") {
		if widths[0] > 24 {
			widths[0] = 24
		}
		if widths[1] > 88 {
			widths[1] = 88
		}
		return widths
	}

	maxPerColumn := 28
	minPerColumn := 10
	targetTotal := 136

	for index := range widths {
		if widths[index] > maxPerColumn {
			widths[index] = maxPerColumn
		}
	}

	for asciiTableTotalWidth(widths) > targetTotal {
		widestIndex := -1
		widestWidth := 0
		for index, width := range widths {
			minimum := len(normalizeTableCell(headers[index]))
			if minimum < minPerColumn {
				minimum = minPerColumn
			}
			if width <= minimum {
				continue
			}
			if width > widestWidth {
				widestWidth = width
				widestIndex = index
			}
		}
		if widestIndex == -1 {
			break
		}
		widths[widestIndex]--
	}

	return widths
}

func asciiTableTotalWidth(widths []int) int {
	if len(widths) == 0 {
		return 1
	}
	total := 1
	for _, width := range widths {
		total += width + 3
	}
	return total
}

func wrapTableText(value string, width int) []string {
	text := normalizeTableCell(value)
	if width <= 0 || len(text) <= width {
		return []string{text}
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}

	lines := make([]string, 0, 4)
	current := words[0]
	for _, word := range words[1:] {
		candidate := current + " " + word
		if len(candidate) <= width {
			current = candidate
			continue
		}
		if len(current) > width {
			lines = append(lines, hardWrapTableText(current, width)...)
		} else {
			lines = append(lines, current)
		}
		current = word
	}
	if len(current) > width {
		lines = append(lines, hardWrapTableText(current, width)...)
	} else {
		lines = append(lines, current)
	}
	return lines
}

func hardWrapTableText(value string, width int) []string {
	if width <= 0 || len(value) <= width {
		return []string{value}
	}

	lines := make([]string, 0, (len(value)/width)+1)
	for start := 0; start < len(value); start += width {
		end := start + width
		if end > len(value) {
			end = len(value)
		}
		lines = append(lines, value[start:end])
	}
	return lines
}

func normalizeTableCell(value string) string {
	return strings.ReplaceAll(value, "\n", " ")
}

func rowsForKey(payload map[string]any, key string) ([]map[string]any, error) {
	rawRows, ok := payload[key]
	if !ok {
		return nil, nil
	}

	items, ok := rawRows.([]any)
	if !ok {
		return nil, fmt.Errorf("payload field %q is not a list", key)
	}

	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("payload field %q contains a non-object row", key)
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func collectHeaders(rows []map[string]any) []string {
	seen := map[string]struct{}{}
	for _, row := range rows {
		for key := range row {
			seen[key] = struct{}{}
		}
	}

	headers := make([]string, 0, len(seen))
	for key := range seen {
		headers = append(headers, key)
	}
	sort.Strings(headers)
	return headers
}

func pathValue(payload map[string]any, path ...string) any {
	current := any(payload)
	for _, part := range path {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = mapping[part]
	}
	return current
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		if typed == float64(int64(typed)) {
			return fmt.Sprintf("%d", int64(typed))
		}
		return fmt.Sprintf("%v", typed)
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(data)
	}
}

func min(left int, right int) int {
	if left < right {
		return left
	}
	return right
}
