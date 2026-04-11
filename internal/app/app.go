package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"harrierops-kube/internal/chains"
	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
	"harrierops-kube/internal/output"
	"harrierops-kube/internal/provider"
)

const (
	OutputTable = "table"
	OutputJSON  = "json"
	OutputCSV   = "csv"
)

type Options struct {
	Context    string
	Namespace  string
	Output     string
	OutDir     string
	Debug      bool
	FixtureDir string
}

type CommandSpec struct {
	Name    string
	Section string
	Status  string
}

var commandSpecs = []CommandSpec{
	{Name: "whoami", Section: "identity", Status: "implemented"},
	{Name: "chains", Section: "orchestration", Status: "implemented"},
	{Name: "inventory", Section: "core", Status: "implemented"},
	{Name: "rbac", Section: "identity", Status: "implemented"},
	{Name: "service-accounts", Section: "identity", Status: "implemented"},
	{Name: "workloads", Section: "workload", Status: "implemented"},
	{Name: "exposure", Section: "exposure", Status: "implemented"},
	{Name: "permissions", Section: "identity", Status: "implemented"},
	{Name: "secrets", Section: "secrets", Status: "implemented"},
	{Name: "privesc", Section: "identity", Status: "implemented"},
	{Name: "images", Section: "supply-chain", Status: "later-depth"},
}

func Run(args []string, stdout io.Writer, stderr io.Writer, env []string) int {
	if len(args) == 0 {
		if _, err := io.WriteString(stdout, rootHelpText()); err != nil {
			fmt.Fprintf(stderr, "error: %s\n", err)
			return 1
		}
		return 0
	}

	if args[0] == "help" {
		if len(args) == 1 {
			if _, err := io.WriteString(stdout, rootHelpText()); err != nil {
				fmt.Fprintf(stderr, "error: %s\n", err)
				return 1
			}
			return 0
		}
		if len(args) == 2 {
			topic, ok := helpTopic(args[1])
			if !ok {
				fmt.Fprintf(stderr, "help for command %q is not available\n", args[1])
				return 2
			}
			if _, err := io.WriteString(stdout, commandHelpText(topic)); err != nil {
				fmt.Fprintf(stderr, "error: %s\n", err)
				return 1
			}
			return 0
		}
		fmt.Fprintf(stderr, "unexpected arguments after help: %s\n", strings.Join(args[1:], " "))
		return 2
	}

	if isFlagToken(args[0]) {
		fmt.Fprintln(stderr, "command must come first; use `harrierops-kube <command> [flags]` or `harrierops-kube <command> help`")
		fmt.Fprintln(stderr, usageText())
		return 2
	}

	command := args[0]

	spec, ok := commandSpec(command)
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n", command)
		fmt.Fprintln(stderr, usageText())
		return 2
	}

	if len(args) > 1 && args[1] == "help" {
		if len(args) > 2 {
			fmt.Fprintf(stderr, "unexpected arguments after help for command %q: %s\n", command, strings.Join(args[2:], " "))
			return 2
		}
		topic, ok := helpTopic(command)
		if !ok {
			fmt.Fprintf(stderr, "help for command %q is not available\n", command)
			return 2
		}
		if _, err := io.WriteString(stdout, commandHelpText(topic)); err != nil {
			fmt.Fprintf(stderr, "error: %s\n", err)
			return 1
		}
		return 0
	}

	selectedFamily := ""
	parseArgs := args[1:]
	if command == chains.GroupedCommandName && len(args) > 1 && !isFlagToken(args[1]) {
		selectedFamily = args[1]
		parseArgs = args[2:]
	}

	options, remaining, err := parseRootOptions(parseArgs, stderr, env)
	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 2
	}

	if len(remaining) > 0 {
		if command != chains.GroupedCommandName || selectedFamily != "" || len(remaining) > 1 {
			fmt.Fprintf(stderr, "unexpected arguments after command %q: %s\n", command, strings.Join(remaining, " "))
			return 2
		}
		selectedFamily = remaining[0]
	}

	if spec.Status != "implemented" {
		fmt.Fprintln(stderr, commandStatusText(spec))
		return 2
	}

	return runSingleCommand(options, command, selectedFamily, stdout, stderr)
}

func parseRootOptions(args []string, stderr io.Writer, env []string) (Options, []string, error) {
	options := Options{
		Output: OutputTable,
	}

	flags := flag.NewFlagSet("harrierops-kube", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.Context, "context", "", "Kubernetes context name")
	flags.StringVar(&options.Namespace, "namespace", "", "Kubernetes namespace")
	flags.StringVar(&options.Output, "output", OutputTable, "Output format: table, json, csv")
	flags.StringVar(&options.OutDir, "outdir", "", "Output directory for emitted artifacts")
	flags.BoolVar(&options.Debug, "debug", false, "Enable verbose errors")

	if err := flags.Parse(args); err != nil {
		return Options{}, nil, err
	}

	options.FixtureDir = resolveFixtureDir(env)
	options.Output = strings.ToLower(options.Output)
	if options.OutDir != "" {
		options.OutDir = filepath.Clean(options.OutDir)
	}

	if !validOutput(options.Output) {
		return Options{}, nil, fmt.Errorf("invalid output %q; valid values: table, json, csv", options.Output)
	}

	return options, flags.Args(), nil
}

func isFlagToken(token string) bool {
	return strings.HasPrefix(token, "-") && token != "-"
}

func rootFlagConsumesNextArg(token string) bool {
	name, _, hasInlineValue := strings.Cut(trimFlagPrefix(token), "=")
	if hasInlineValue {
		return false
	}

	switch name {
	case "context", "namespace", "output", "outdir":
		return true
	default:
		return false
	}
}

func trimFlagPrefix(token string) string {
	return strings.TrimLeft(token, "-")
}

func runSingleCommand(options Options, command string, selectedFamily string, stdout io.Writer, stderr io.Writer) int {
	payload, err := buildCommandPayload(command, options, selectedFamily)
	if err != nil {
		writeError(stderr, err, options.Debug)
		return 2
	}

	if options.OutDir != "" {
		if _, err := output.WriteArtifacts(command, payload, options.OutDir); err != nil {
			writeError(stderr, err, options.Debug)
			return 1
		}
	}

	rendered, err := output.Render(options.Output, command, payload)
	if err != nil {
		writeError(stderr, err, options.Debug)
		return 1
	}

	if _, err := io.WriteString(stdout, rendered); err != nil {
		writeError(stderr, err, options.Debug)
		return 1
	}

	return 0
}

func buildCommandPayload(command string, options Options, selection ...string) (map[string]any, error) {
	selectedFamily := ""
	if len(selection) > 0 {
		selectedFamily = selection[0]
	}

	if command == chains.GroupedCommandName {
		return buildChainsPayload(selectedFamily, options)
	}

	factProvider, err := provider.NewProvider(options.FixtureDir)
	if err != nil {
		return nil, err
	}

	query := provider.QueryOptions{
		ContextName: options.Context,
		Namespace:   options.Namespace,
	}
	switch command {
	case "whoami":
		metadataContext, err := factProvider.MetadataContext(query)
		if err != nil {
			return nil, err
		}
		data, err := factProvider.WhoAmI(query)
		if err != nil {
			return nil, err
		}
		metadata := buildMetadata(command, metadataContext, data.KubeContext.ClusterName)
		return structToMap(model.WhoAmIOutput{
			Metadata:           metadata,
			KubeContext:        data.KubeContext,
			CurrentIdentity:    data.CurrentIdentity,
			Session:            data.Session,
			EnvironmentHint:    data.EnvironmentHint,
			IdentityEvidence:   data.IdentityEvidence,
			VisibilityBlockers: data.VisibilityBlockers,
			Issues:             data.Issues,
		})
	case "inventory":
		return buildInventoryPayload(factProvider, query)
	case "rbac":
		return buildRBACPayload(factProvider, query)
	case "service-accounts":
		return buildServiceAccountsPayload(factProvider, query)
	case "workloads":
		return buildWorkloadsPayload(factProvider, query)
	case "exposure":
		return buildExposurePayload(factProvider, query)
	case "permissions":
		return buildPermissionsPayload(factProvider, query)
	case "secrets":
		return buildSecretsPayload(factProvider, query)
	case "privesc":
		return buildPrivescPayload(factProvider, query)
	default:
		return nil, fmt.Errorf("unsupported implemented command %q", command)
	}
}

func buildMetadata(command string, metadataContext model.MetadataContext, clusterName string) contracts.Metadata {
	return contracts.Metadata{
		Command:       command,
		ContextName:   contracts.OptionalString(metadataContext.ContextName),
		ClusterName:   contracts.OptionalString(clusterName),
		Namespace:     contracts.OptionalString(metadataContext.Namespace),
		DockerContext: contracts.OptionalString(metadataContext.DockerContext),
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		SchemaVersion: contracts.SchemaVersion,
	}
}

func commandSpec(name string) (CommandSpec, bool) {
	for _, spec := range commandSpecs {
		if spec.Name == name {
			return spec, true
		}
	}
	return CommandSpec{}, false
}

func commandNamesWithStatus(status string) []string {
	filtered := make([]string, 0, len(commandSpecs))
	for _, spec := range commandSpecs {
		if spec.Status == status {
			filtered = append(filtered, spec.Name)
		}
	}
	return filtered
}

func implementedSectionNames() []string {
	seen := map[string]struct{}{}
	sections := make([]string, 0, len(commandSpecs))
	for _, spec := range commandSpecs {
		if spec.Status != "implemented" {
			continue
		}
		if _, ok := seen[spec.Section]; ok {
			continue
		}
		seen[spec.Section] = struct{}{}
		sections = append(sections, spec.Section)
	}
	return sections
}

func validOutput(output string) bool {
	switch output {
	case OutputTable, OutputJSON, OutputCSV:
		return true
	default:
		return false
	}
}

func resolveFixtureDir(env []string) string {
	envMap := map[string]string{}
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if ok {
			envMap[key] = value
		}
	}

	if value := envMap["HARRIEROPS_KUBE_FIXTURE_DIR"]; value != "" {
		return value
	}
	return ""
}

func usageText() string {
	return strings.Join([]string{
		"usage: harrierops-kube <command> [global options]",
		"       harrierops-kube help [command]",
		"       harrierops-kube chains [family] [global options]",
		"       harrierops-kube <command> help",
		"",
		commandListLine("implemented commands", commandNamesWithStatus("implemented")),
		commandListLine("planned phase 1 commands", commandNamesWithStatus("planned-phase1")),
		commandListLine("later depth surfaces", commandNamesWithStatus("later-depth")),
		commandListLine("implemented sections", implementedSectionNames()),
		"run `harrierops-kube help <command>` or `harrierops-kube <command> help` for operator-readable command summaries",
	}, "\n")
}

func commandListLine(label string, values []string) string {
	if len(values) == 0 {
		return label + ": none"
	}
	return label + ": " + strings.Join(values, ", ")
}

func commandStatusText(spec CommandSpec) string {
	switch spec.Status {
	case "planned-phase1":
		return fmt.Sprintf("command %q is planned for Phase 1 but is not implemented yet", spec.Name)
	case "later-depth":
		return fmt.Sprintf("command %q is a later depth surface and is not in the current runnable Phase 1 set", spec.Name)
	default:
		return fmt.Sprintf("command %q is not runnable", spec.Name)
	}
}

func writeError(stderr io.Writer, err error, debug bool) {
	if debug {
		fmt.Fprintf(stderr, "error: %+v\n", err)
		return
	}
	fmt.Fprintf(stderr, "error: %s\n", err)
}

func buildInventoryPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, issue := deriveInventoryMetadataContext(factProvider, query)
	issues := []model.Issue{}
	if issue != nil {
		issues = append(issues, *issue)
	}

	inventoryData, inventoryIssue := loadInventoryDataForInventory(factProvider, query)
	if inventoryIssue != nil {
		issues = append(issues, *inventoryIssue)
	}
	issues = append(issues, inventoryData.Issues...)

	whoamiData, whoamiIssue := loadWhoAmIDataForInventory(factProvider, query)
	if whoamiIssue != nil {
		issues = append(issues, *whoamiIssue)
	}
	issues = append(issues, whoamiData.Issues...)

	rbacData, rbacIssue := loadRBACDataForInventory(factProvider, query)
	if rbacIssue != nil {
		issues = append(issues, *rbacIssue)
	}
	issues = append(issues, rbacData.Issues...)

	serviceAccountData, serviceAccountIssue := loadServiceAccountsDataForInventory(factProvider, query)
	if serviceAccountIssue != nil {
		issues = append(issues, *serviceAccountIssue)
	}
	issues = append(issues, serviceAccountData.Issues...)

	workloadData, workloadIssue := loadWorkloadsDataForInventory(factProvider, query)
	if workloadIssue != nil {
		issues = append(issues, *workloadIssue)
	}
	issues = append(issues, workloadData.Issues...)

	exposureData, exposureIssue := loadExposureDataForInventory(factProvider, query)
	if exposureIssue != nil {
		issues = append(issues, *exposureIssue)
	}
	issues = append(issues, exposureData.Issues...)

	if len(inventoryData.KubernetesCounts) == 0 &&
		len(exposureData.ExposureAssets) == 0 &&
		len(workloadData.WorkloadAssets) == 0 &&
		len(serviceAccountData.ServiceAccounts) == 0 &&
		len(rbacData.RoleGrants) == 0 {
		return nil, fmt.Errorf("inventory could not collect enough orientation signal to answer honestly")
	}

	metadata := buildMetadata("inventory", metadataContext, "")
	output := model.InventoryOutput{
		Metadata:               metadata,
		Visibility:             deriveInventoryVisibility(inventoryData.KubernetesCounts, whoamiData),
		Environment:            deriveInventoryEnvironment(whoamiData),
		ExposureFootprint:      deriveInventoryExposure(exposureData),
		RiskyWorkloadFootprint: deriveInventoryRiskyWorkloads(workloadData),
		IdentityFootprint:      deriveInventoryIdentity(serviceAccountData, rbacData),
		NextCommands: deriveInventoryNextCommands(
			whoamiData,
			exposureData,
			workloadData,
			serviceAccountData,
			rbacData,
		),
		KubernetesCounts: inventoryData.KubernetesCounts,
		DockerCounts:     inventoryData.DockerCounts,
		Issues:           issues,
	}

	return structToMap(output)
}

func deriveInventoryMetadataContext(factProvider provider.Provider, query provider.QueryOptions) (model.MetadataContext, *model.Issue) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err == nil {
		return metadataContext, nil
	}

	return model.MetadataContext{
			ContextName: query.ContextName,
			Namespace:   query.Namespace,
		}, &model.Issue{
			Kind:    "collection",
			Scope:   "inventory.metadata",
			Message: "Inventory could not fully confirm session metadata from `whoami`, so metadata defaults may be partial.",
		}
}

func loadInventoryDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.InventoryData, *model.Issue) {
	data, err := factProvider.Inventory(query)
	if err == nil {
		return data, nil
	}
	return model.InventoryData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "inventory",
		Message: "Inventory counts could not be collected from the primary inventory source.",
	}
}

func loadWhoAmIDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.WhoAmIData, *model.Issue) {
	data, err := factProvider.WhoAmI(query)
	if err == nil {
		return data, nil
	}
	return model.WhoAmIData{
			Session: model.SessionProfile{
				AuthMaterialType: "unknown",
				ExecutionOrigin:  "unknown",
				FootholdFamily:   "unknown",
				VisibilityScope:  "unknown",
			},
			CurrentIdentity: model.CurrentIdentity{
				Label:      "unknown current identity",
				Kind:       "Unknown",
				Confidence: "blocked",
			},
			VisibilityBlockers: []string{
				"Current scope does not confirm the acting identity or visibility shape through `whoami` support reads.",
			},
		}, &model.Issue{
			Kind:    "collection",
			Scope:   "inventory.whoami",
			Message: "Inventory could not collect `whoami` support data, so session-grounding clues are partial.",
		}
}

func loadRBACDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.RBACData, *model.Issue) {
	data, err := factProvider.RBACBindings(query)
	if err == nil {
		return data, nil
	}
	return model.RBACData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "inventory.rbac",
		Message: "Inventory could not collect RBAC support data, so identity-control sprawl may be understated.",
	}
}

func loadServiceAccountsDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "inventory.service-accounts",
		Message: "Inventory could not collect service-account support data, so identity-path breadth may be understated.",
	}
}

func loadWorkloadsDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "inventory.workloads",
		Message: "Inventory could not collect workload support data, so risky workload cues may be understated.",
	}
}

func loadExposureDataForInventory(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "inventory.exposure",
		Message: "Inventory could not collect exposure support data, so outside-facing paths may be understated.",
	}
}

func deriveInventoryVisibility(counts map[string]int, whoamiData model.WhoAmIData) model.VisibilitySummary {
	namespaces := counts["namespaces"]
	nodes := counts["nodes"]
	workloads := counts["pods"] + counts["deployments"] + counts["daemonsets"] + counts["statefulsets"]

	scope := "unclear slice"
	assessment := "partial"
	summary := "Current scope only shows a thin Kubernetes slice, so treat quiet areas cautiously."

	switch {
	case namespaces >= 3 || nodes >= 2 || workloads >= 6:
		scope = "broad cluster slice"
		assessment = "broad"
		summary = fmt.Sprintf(
			"Current scope shows %d namespaces, %d nodes, and %d visible workload objects, so this reads like a broad cluster orientation pass.",
			namespaces,
			nodes,
			workloads,
		)
	case namespaces >= 2 || workloads >= 3:
		scope = "mixed slice"
		assessment = "moderate"
		summary = fmt.Sprintf(
			"Current scope shows more than one namespace and %d visible workload objects, so this is wider than a single-app namespace view.",
			workloads,
		)
	}

	if len(whoamiData.VisibilityBlockers) > 0 {
		summary = summary + " Visibility blockers are still present, so some quiet areas may simply be unreadable."
	}

	return model.VisibilitySummary{
		Scope:      scope,
		Assessment: assessment,
		Summary:    summary,
	}
}

func deriveInventoryEnvironment(whoamiData model.WhoAmIData) model.EnvironmentSummary {
	server := strings.ToLower(whoamiData.KubeContext.Server)
	clusterName := strings.ToLower(whoamiData.KubeContext.ClusterName)

	environmentType := "unknown"
	confidence := "heuristic"
	summary := "Current slice does not show strong enough provider markers to call this managed or self-managed with confidence."
	evidence := []string{"The visible API endpoint and cluster name do not carry a strong managed-cluster marker."}

	switch {
	case strings.Contains(server, ".azmk8s.io") || strings.Contains(server, ".eks.amazonaws.com") || strings.Contains(server, ".gke.") || strings.Contains(clusterName, "aks") || strings.Contains(clusterName, "eks") || strings.Contains(clusterName, "gke"):
		environmentType = "managed-like"
		summary = "Visible endpoint naming looks managed-service-shaped, so cloud-cluster bridge assumptions deserve attention."
		evidence = []string{"The visible endpoint or cluster name matches a common managed Kubernetes naming pattern."}
	case strings.Contains(server, "10.") || strings.Contains(server, "172.") || strings.Contains(server, "192.168.") || strings.HasPrefix(server, "https://127.") || strings.HasPrefix(server, "https://localhost"):
		environmentType = "self-managed-like"
		summary = "The visible API endpoint looks private or lab-shaped rather than strongly managed-service-branded."
		evidence = []string{"The visible API endpoint is an internal-style address without strong managed-cluster branding."}
	}

	return model.EnvironmentSummary{
		Type:       environmentType,
		Confidence: confidence,
		Summary:    summary,
		Evidence:   evidence,
	}
}

func deriveInventoryExposure(exposureData model.ExposureData) model.ExposureFootprint {
	var ingresses, loadBalancers, nodePorts, hostExposurePods, publicPaths int
	for _, asset := range exposureData.ExposureAssets {
		if asset.Public {
			publicPaths++
		}
		switch asset.ExposureType {
		case "Ingress":
			ingresses++
		case "LoadBalancer":
			loadBalancers++
		case "NodePort":
			nodePorts++
		case "HostNetwork", "HostPort":
			hostExposurePods++
		}
	}

	summary := "No obvious outside-facing exposure footprint is visible in the current slice."
	switch {
	case publicPaths >= 3:
		summary = fmt.Sprintf("%d public-looking exposure paths are visible, so `exposure` should likely be the next stop.", publicPaths)
	case publicPaths > 0:
		summary = fmt.Sprintf("%d public-looking exposure path(s) are visible, which is enough to justify checking `exposure` early.", publicPaths)
	case hostExposurePods > 0:
		summary = fmt.Sprintf("%d host-network or host-port workload exposure clue(s) are visible even without a clearly public edge.", hostExposurePods)
	}

	return model.ExposureFootprint{
		PublicPaths:      publicPaths,
		Ingresses:        ingresses,
		LoadBalancers:    loadBalancers,
		NodePorts:        nodePorts,
		HostExposurePods: hostExposurePods,
		Summary:          summary,
	}
}

func deriveInventoryRiskyWorkloads(workloadData model.WorkloadsData) model.RiskyWorkloadFootprint {
	var privileged, hostTouching, hostNamespaces, dockerSocket int
	for _, workload := range workloadData.WorkloadAssets {
		if workload.Privileged {
			privileged++
		}
		if workload.DockerSocketMount {
			dockerSocket++
		}
		if workload.HostNetwork || workload.HostPID || workload.HostIPC {
			hostNamespaces++
		}
		if workload.DockerSocketMount || len(workload.HostPathMounts) > 0 || workload.HostNetwork || workload.HostPID || workload.HostIPC {
			hostTouching++
		}
	}

	summary := "Visible workloads do not yet suggest a strong risky-execution pattern."
	switch {
	case privileged > 0 || hostTouching >= 2 || dockerSocket > 0:
		summary = fmt.Sprintf("%d privileged and %d host-touching workload clue(s) are visible, so `workloads` should help quickly.", privileged, hostTouching)
	case hostNamespaces > 0:
		summary = fmt.Sprintf("%d workload(s) share host namespaces, which is enough to make execution posture worth checking.", hostNamespaces)
	}

	return model.RiskyWorkloadFootprint{
		PrivilegedWorkloads:    privileged,
		HostTouchingWorkloads:  hostTouching,
		HostNamespaceWorkloads: hostNamespaces,
		DockerSocketWorkloads:  dockerSocket,
		Summary:                summary,
	}
}

func deriveInventoryIdentity(serviceAccountData model.ServiceAccountsData, rbacData model.RBACData) model.IdentityFootprint {
	serviceAccounts := len(serviceAccountData.ServiceAccounts)
	roleGrants := len(rbacData.RoleGrants)
	clusterWide := 0
	highImpactServiceAccounts := 0

	for _, grant := range rbacData.RoleGrants {
		if grant.BindingKind == "ClusterRoleBinding" || grant.Namespace == nil {
			clusterWide++
		}
	}
	for _, account := range serviceAccountData.ServiceAccounts {
		for _, role := range account.BoundRoles {
			if role == "cluster-admin" || role == "edit" || role == "admin" {
				highImpactServiceAccounts++
				break
			}
		}
	}

	summary := "Identity and control sprawl look limited from the current slice."
	switch {
	case serviceAccounts >= 3 || roleGrants >= 3 || highImpactServiceAccounts > 0:
		summary = fmt.Sprintf("%d service accounts, %d visible role grants, and %d higher-impact service-account path(s) are visible.", serviceAccounts, roleGrants, highImpactServiceAccounts)
	case serviceAccounts > 0 || roleGrants > 0:
		summary = fmt.Sprintf("%d service accounts and %d visible role grants are enough to justify an identity pass soon.", serviceAccounts, roleGrants)
	}

	return model.IdentityFootprint{
		ServiceAccounts:           serviceAccounts,
		RoleGrants:                roleGrants,
		ClusterWideRoleGrants:     clusterWide,
		HighImpactServiceAccounts: highImpactServiceAccounts,
		Summary:                   summary,
	}
}

func deriveInventoryNextCommands(
	whoamiData model.WhoAmIData,
	exposureData model.ExposureData,
	workloadData model.WorkloadsData,
	serviceAccountData model.ServiceAccountsData,
	rbacData model.RBACData,
) []model.NextCommandHint {
	hints := []model.NextCommandHint{}

	publicPaths := 0
	for _, asset := range exposureData.ExposureAssets {
		if asset.Public {
			publicPaths++
		}
	}
	hostTouching := 0
	for _, workload := range workloadData.WorkloadAssets {
		if workload.DockerSocketMount || len(workload.HostPathMounts) > 0 || workload.HostNetwork || workload.HostPID || workload.HostIPC || workload.Privileged {
			hostTouching++
		}
	}

	if publicPaths > 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "exposure",
			Why:     fmt.Sprintf("%d public-looking exposure path(s) are visible, so the cluster edge deserves review first.", publicPaths),
		})
	}
	if hostTouching > 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "workloads",
			Why:     fmt.Sprintf("%d visible workload(s) already carry privileged or host-touching clues.", hostTouching),
		})
	}
	if len(serviceAccountData.ServiceAccounts) > 0 || len(rbacData.RoleGrants) > 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "service-accounts",
			Why:     "Visible service-account use and RBAC grants suggest identity paths are already worth triaging.",
		})
	}
	if len(rbacData.RoleGrants) > 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "rbac",
			Why:     "Visible role grants are already on screen, so `rbac` can ground the assignment evidence directly.",
		})
	}
	if whoamiData.CurrentIdentity.Confidence != "direct" || len(whoamiData.VisibilityBlockers) > 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "whoami",
			Why:     "Current session grounding is still weaker than ideal, so verify the foothold before leaning too hard on cluster shape.",
		})
	}
	if len(hints) == 0 {
		hints = append(hints, model.NextCommandHint{
			Command: "whoami",
			Why:     "If the cluster shape feels quiet, confirm the current session first so a narrow foothold does not masquerade as a quiet environment.",
		})
	}
	return hints
}

func structToMap(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}
