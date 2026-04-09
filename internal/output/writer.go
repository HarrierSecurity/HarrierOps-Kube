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
)

var rowCollections = map[string]string{
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
	if command == "inventory" {
		lootPayload = map[string]any{}
		for _, key := range []string{
			"metadata",
			"visibility",
			"environment",
			"exposure_footprint",
			"risky_workload_footprint",
			"identity_footprint",
			"next_commands",
			"issues",
		} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
	}
	if command == "rbac" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if grants, err := rowsForKey(payload, "role_grants"); err == nil {
			selected := make([]map[string]any, 0, len(grants))
			for _, grant := range grants {
				if stringify(grant["priority"]) == "high" {
					selected = append(selected, grant)
				}
			}
			if len(selected) == 0 && len(grants) > 0 {
				limit := min(3, len(grants))
				selected = append(selected, grants[:limit]...)
			}
			lootPayload["role_grants"] = selected
		}
	}
	if command == "service-accounts" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "findings", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if serviceAccounts, err := rowsForKey(payload, "service_accounts"); err == nil {
			selected := make([]map[string]any, 0, len(serviceAccounts))
			for _, row := range serviceAccounts {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(serviceAccounts) > 0 {
				limit := min(3, len(serviceAccounts))
				selected = append(selected, serviceAccounts[:limit]...)
			}
			lootPayload["service_accounts"] = selected
		}
	}
	if command == "workloads" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "findings", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if workloads, err := rowsForKey(payload, "workload_assets"); err == nil {
			selected := make([]map[string]any, 0, len(workloads))
			for _, row := range workloads {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(workloads) > 0 {
				limit := min(3, len(workloads))
				selected = append(selected, workloads[:limit]...)
			}
			lootPayload["workload_assets"] = selected
		}
	}
	if command == "exposure" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "findings", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if exposures, err := rowsForKey(payload, "exposure_assets"); err == nil {
			selected := make([]map[string]any, 0, len(exposures))
			for _, row := range exposures {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(exposures) > 0 {
				limit := min(3, len(exposures))
				selected = append(selected, exposures[:limit]...)
			}
			lootPayload["exposure_assets"] = selected
		}
	}
	if command == "permissions" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if permissions, err := rowsForKey(payload, "permissions"); err == nil {
			selected := make([]map[string]any, 0, len(permissions))
			for _, row := range permissions {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(permissions) > 0 {
				limit := min(3, len(permissions))
				selected = append(selected, permissions[:limit]...)
			}
			lootPayload["permissions"] = selected
		}
	}
	if command == "secrets" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if secretPaths, err := rowsForKey(payload, "secret_paths"); err == nil {
			selected := make([]map[string]any, 0, len(secretPaths))
			for _, row := range secretPaths {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(secretPaths) > 0 {
				limit := min(3, len(secretPaths))
				selected = append(selected, secretPaths[:limit]...)
			}
			lootPayload["secret_paths"] = selected
		}
	}
	if command == "privesc" {
		lootPayload = map[string]any{}
		for _, key := range []string{"metadata", "issues"} {
			if value, ok := payload[key]; ok {
				lootPayload[key] = value
			}
		}
		if escalationPaths, err := rowsForKey(payload, "escalation_paths"); err == nil {
			selected := make([]map[string]any, 0, len(escalationPaths))
			for _, row := range escalationPaths {
				if stringify(row["priority"]) == "high" {
					selected = append(selected, row)
				}
			}
			if len(selected) == 0 && len(escalationPaths) > 0 {
				limit := min(3, len(escalationPaths))
				selected = append(selected, escalationPaths[:limit]...)
			}
			lootPayload["escalation_paths"] = selected
		}
	}

	return json.MarshalIndent(lootPayload, "", "  ")
}

func renderTable(command string, payload map[string]any) (string, error) {
	var rendered string
	var err error

	if command == "whoami" {
		rendered, err = renderWhoAmITable(payload)
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
				rendered, err = renderSimpleTable([]string{"info"}, [][]string{{"No records"}})
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
				rendered, err = renderSimpleTable(headers, records)
			}
		}
	}
	if err != nil {
		return "", err
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
	return renderSimpleTable([]string{"field", "value"}, records)
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
	return renderSimpleTable([]string{"field", "value"}, records)
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
	return renderSimpleTable([]string{"field", "value"}, records)
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

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "scope", "subject", "role", "binding", "signal"},
		records,
		"why_care",
		"No visible RBAC grants were confirmed from current scope.",
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

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "service_account", "workloads", "power", "token_posture"},
		records,
		"why_care",
		"No visible service-account identity paths were confirmed from current scope.",
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
		exposure := "no visible exposure path"
		if related, ok := row["related_exposures"].([]any); ok && len(related) > 0 {
			parts := make([]string, 0, len(related))
			for _, item := range related {
				parts = append(parts, stringify(item))
			}
			exposure = strings.Join(parts, "; ")
		}
		execution := "no strong risky execution signal"
		if riskSignals, ok := row["risk_signals"].([]any); ok && len(riskSignals) > 0 {
			parts := make([]string, 0, len(riskSignals))
			for _, item := range riskSignals {
				parts = append(parts, stringify(item))
			}
			execution = strings.Join(parts, "; ")
		}
		records = append(records, detailTableRecord{
			columns: []string{
				stringify(row["priority"]),
				workload,
				stringify(row["identity_summary"]),
				exposure,
				execution,
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "workload", "identity", "exposure", "execution"},
		records,
		"why_care",
		"No visible workloads rose into triage from current scope.",
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

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "exposure", "targets", "attribution", "backend"},
		records,
		"why_care",
		"No visible exposure paths were confirmed from current scope.",
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
				stringify(row["action_summary"]),
				stringify(row["scope"]),
				stringify(row["next_review"]),
			},
			detail: stringify(row["why_care"]),
		})
	}

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "subject", "confidence", "action", "scope", "next_review"},
		records,
		"why_care",
		"No visible current-session capability paths were confirmed from current scope.",
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

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "story", "path", "linkage", "target"},
		records,
		"why_care",
		"No visible secret paths were confirmed from current scope.",
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

	return renderDetailedTriageTable(
		payload,
		[]string{"priority", "class", "foothold", "action", "outcome"},
		records,
		"why_care",
		"No visible escalation paths were confirmed from the current foothold.",
	)
}

type detailTableRecord struct {
	columns []string
	detail  string
}

func renderDetailedTriageTable(payload map[string]any, headers []string, records []detailTableRecord, detailLabel string, emptyMessage string) (string, error) {
	if len(records) == 0 {
		return renderTriageEmptyState(payload, emptyMessage), nil
	}

	var builder strings.Builder
	for index, record := range records {
		rendered, err := renderDetailedRecordTable(headers, record.columns, detailLabel, record.detail)
		if err != nil {
			return "", err
		}
		builder.WriteString(rendered)
		if index != len(records)-1 {
			builder.WriteByte('\n')
		}
	}
	appendIssueSection(&builder, payload)
	return builder.String(), nil
}

func renderTriageEmptyState(payload map[string]any, emptyMessage string) string {
	var builder strings.Builder
	rendered, err := renderSimpleTable([]string{"info"}, [][]string{{emptyMessage}})
	if err == nil {
		builder.WriteString(rendered)
	}
	appendIssueSection(&builder, payload)
	return builder.String()
}

func appendIssueSection(builder *strings.Builder, payload map[string]any) {
	issues, ok := payload["issues"].([]any)
	if !ok || len(issues) == 0 {
		return
	}

	builder.WriteString("\nIssues:\n")
	for _, issue := range issues {
		builder.WriteString("- ")
		builder.WriteString(formatIssue(issue))
		builder.WriteString("\n")
	}
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

func renderSimpleTable(headers []string, records [][]string) (string, error) {
	if len(headers) == 0 {
		return "", nil
	}

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

	var builder strings.Builder
	border := asciiTableBorder(widths)
	builder.WriteString(border)
	builder.WriteByte('\n')
	builder.WriteString(asciiTableRow(headers, widths))
	builder.WriteByte('\n')
	builder.WriteString(border)
	builder.WriteByte('\n')
	for _, record := range records {
		row := make([]string, len(headers))
		for index := range headers {
			if index < len(record) {
				row[index] = record[index]
			}
		}
		builder.WriteString(asciiTableRow(row, widths))
		builder.WriteByte('\n')
	}
	builder.WriteString(border)
	builder.WriteByte('\n')
	return builder.String(), nil
}

func renderDetailedRecordTable(headers []string, record []string, detailLabel string, detail string) (string, error) {
	if len(headers) == 0 {
		return "", nil
	}

	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = len(normalizeTableCell(header))
	}
	for index := 0; index < len(headers) && index < len(record); index++ {
		cellWidth := len(normalizeTableCell(record[index]))
		if cellWidth > widths[index] {
			widths[index] = cellWidth
		}
	}

	border := asciiTableBorder(widths)
	var builder strings.Builder
	builder.WriteString(border)
	builder.WriteByte('\n')
	builder.WriteString(asciiTableRow(headers, widths))
	builder.WriteByte('\n')
	builder.WriteString(border)
	builder.WriteByte('\n')

	row := make([]string, len(headers))
	copy(row, record)
	builder.WriteString(asciiTableRow(row, widths))
	builder.WriteByte('\n')

	if detail != "" {
		spanWidth := asciiTableSpanWidth(widths)
		spanBorder := asciiTableBorder([]int{spanWidth})
		detailText := detailLabel + ": " + detail
		builder.WriteString(spanBorder)
		builder.WriteByte('\n')
		for _, line := range wrapTableText(detailText, spanWidth) {
			builder.WriteString(asciiTableSpanningRow(line, asciiTableSpanWidth(widths)))
			builder.WriteByte('\n')
		}
		builder.WriteString(spanBorder)
		builder.WriteByte('\n')
		return builder.String(), nil
	}

	builder.WriteString(border)
	builder.WriteByte('\n')
	return builder.String(), nil
}

func asciiTableBorder(widths []int) string {
	var builder strings.Builder
	builder.WriteByte('+')
	for _, width := range widths {
		builder.WriteString(strings.Repeat("-", width+2))
		builder.WriteByte('+')
	}
	return builder.String()
}

func asciiTableRow(values []string, widths []int) string {
	var builder strings.Builder
	builder.WriteByte('|')
	for index, width := range widths {
		value := ""
		if index < len(values) {
			value = normalizeTableCell(values[index])
		}
		builder.WriteByte(' ')
		builder.WriteString(value)
		builder.WriteString(strings.Repeat(" ", width-len(value)))
		builder.WriteByte(' ')
		builder.WriteByte('|')
	}
	return builder.String()
}

func asciiTableDetailRow(value string, width int) string {
	var builder strings.Builder
	text := normalizeTableCell(value)
	builder.WriteByte('|')
	builder.WriteByte(' ')
	builder.WriteString(text)
	builder.WriteString(strings.Repeat(" ", width-len(text)))
	builder.WriteByte(' ')
	builder.WriteByte('|')
	return builder.String()
}

func asciiTableSpanningRow(value string, width int) string {
	return asciiTableDetailRow(value, width)
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
