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
	"text/tabwriter"
)

var rowCollections = map[string]string{
	"rbac":             "role_grants",
	"service-accounts": "service_accounts",
	"exposure":         "exposure_assets",
	"workloads":        "workload_assets",
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

	return json.MarshalIndent(lootPayload, "", "  ")
}

func renderTable(command string, payload map[string]any) (string, error) {
	if command == "whoami" {
		return renderWhoAmITable(payload)
	}
	if command == "inventory" {
		return renderInventoryTable(payload)
	}
	if command == "rbac" {
		return renderRBACTable(payload)
	}

	rowKey, ok := rowCollections[command]
	if !ok {
		return renderKeyValueTable(payload)
	}

	rows, err := rowsForKey(payload, rowKey)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}

	headers := collectHeaders(rows)
	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)

	fmt.Fprintln(writer, strings.Join(headers, "\t"))
	for _, row := range rows {
		values := make([]string, 0, len(headers))
		for _, header := range headers {
			values = append(values, stringify(row[header]))
		}
		fmt.Fprintln(writer, strings.Join(values, "\t"))
	}

	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
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

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	for _, key := range keys {
		fmt.Fprintf(writer, "%s\t%s\n", key, stringify(payload[key]))
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
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

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
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

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(writer, "%s\t%s\n", row[0], row[1])
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func renderRBACTable(payload map[string]any) (string, error) {
	rows, err := rowsForKey(payload, "role_grants")
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}

	var builder strings.Builder
	writer := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, strings.Join([]string{"priority", "scope", "subject", "role", "binding", "signal", "why_care"}, "\t"))
	for _, row := range rows {
		signal := stringify(row["evidence_status"])
		if dangerous, ok := row["dangerous_rights"].([]any); ok && len(dangerous) > 0 {
			parts := make([]string, 0, len(dangerous))
			for _, item := range dangerous {
				parts = append(parts, stringify(item))
			}
			signal = strings.Join(parts, "; ")
		}
		fmt.Fprintln(writer, strings.Join([]string{
			stringify(row["priority"]),
			stringify(row["scope"]),
			stringify(row["subject_display"]),
			stringify(row["role_display_name"]),
			stringify(row["binding_name"]),
			signal,
			stringify(row["why_care"]),
		}, "\t"))
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return builder.String(), nil
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
