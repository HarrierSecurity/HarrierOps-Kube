package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildPermissionsPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
	metadataContext, err := factProvider.MetadataContext(query)
	if err != nil {
		return nil, err
	}

	whoamiData, err := factProvider.WhoAmI(query)
	if err != nil {
		return nil, err
	}

	rbacData, err := factProvider.RBACBindings(query)
	if err != nil {
		return nil, err
	}

	rows, permissionIssues := loadPermissionPaths(factProvider, query, whoamiData.CurrentIdentity, rbacData.RoleGrants)
	if rows == nil {
		rows = []model.PermissionPath{}
	}

	issues := append([]model.Issue{}, whoamiData.Issues...)
	issues = append(issues, rbacData.Issues...)
	issues = append(issues, permissionIssues...)

	return structToMap(model.PermissionsOutput{
		Metadata:    buildMetadata("permissions", metadataContext, ""),
		Permissions: rows,
		Issues:      issues,
	})
}

type currentSessionPermissionProvider interface {
	CurrentSessionPermissions(provider.QueryOptions, model.CurrentIdentity) ([]model.PermissionPath, []model.Issue, error)
}

func loadPermissionPaths(
	factProvider provider.Provider,
	query provider.QueryOptions,
	currentIdentity model.CurrentIdentity,
	grants []model.RBACGrant,
) ([]model.PermissionPath, []model.Issue) {
	derivedRows, derivedIssues := derivePermissionPaths(currentIdentity, grants)

	liveProvider, ok := factProvider.(currentSessionPermissionProvider)
	if !ok {
		return derivedRows, derivedIssues
	}

	directRows, directIssues, err := liveProvider.CurrentSessionPermissions(query, currentIdentity)
	if err != nil {
		return derivedRows, append(derivedIssues, model.Issue{
			Kind:    "collection",
			Scope:   "permissions.authorization",
			Message: "Current scope could not confirm direct authorization-review surfaces, so capability rows fell back to RBAC-derived evidence.",
		})
	}

	return mergePermissionRows(directRows, derivedRows), append(directIssues, derivedIssues...)
}

func mergePermissionRows(preferred []model.PermissionPath, fallback []model.PermissionPath) []model.PermissionPath {
	merged := map[string]model.PermissionPath{}
	order := []string{}

	for _, row := range fallback {
		key := permissionMergeKey(row)
		if _, ok := merged[key]; !ok {
			order = append(order, key)
		}
		merged[key] = row
	}
	for _, row := range preferred {
		key := permissionMergeKey(row)
		if existing, ok := merged[key]; ok {
			merged[key] = mergePermissionEvidence(existing, row)
			continue
		}
		order = append(order, key)
		merged[key] = row
	}

	rows := make([]model.PermissionPath, 0, len(order))
	for _, key := range order {
		rows = append(rows, merged[key])
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if priorityOrder(rows[i].Priority) != priorityOrder(rows[j].Priority) {
			return priorityOrder(rows[i].Priority) < priorityOrder(rows[j].Priority)
		}
		if permissionScopeRank(rows[i].Scope) != permissionScopeRank(rows[j].Scope) {
			return permissionScopeRank(rows[i].Scope) > permissionScopeRank(rows[j].Scope)
		}
		if permissionActionScore(rows[i].ActionSummary) != permissionActionScore(rows[j].ActionSummary) {
			return permissionActionScore(rows[i].ActionSummary) > permissionActionScore(rows[j].ActionSummary)
		}
		return rows[i].ActionSummary < rows[j].ActionSummary
	})
	return rows
}

func permissionMergeKey(row model.PermissionPath) string {
	return strings.Join([]string{
		row.Scope,
		row.ActionSummary,
		row.ActionVerb,
		row.TargetGroup,
	}, "|")
}

func mergePermissionEvidence(existing model.PermissionPath, preferred model.PermissionPath) model.PermissionPath {
	merged := preferred
	if merged.ActionVerb == "" {
		merged.ActionVerb = existing.ActionVerb
	}
	if merged.TargetGroup == "" {
		merged.TargetGroup = existing.TargetGroup
	}
	merged.TargetResources = mergeUniqueStrings(existing.TargetResources, preferred.TargetResources)
	merged.RelatedBindings = mergeUniqueStrings(existing.RelatedBindings, preferred.RelatedBindings)
	if merged.EvidenceSource == "" {
		merged.EvidenceSource = existing.EvidenceSource
	} else if existing.EvidenceSource != "" && existing.EvidenceSource != merged.EvidenceSource {
		merged.EvidenceSource = mergeEvidenceSources(existing.EvidenceSource, merged.EvidenceSource)
	}
	if merged.WhyCare == "" {
		merged.WhyCare = existing.WhyCare
	}
	if merged.NextReview == "" {
		merged.NextReview = existing.NextReview
	}
	return merged
}

func mergeEvidenceSources(left string, right string) string {
	sources := mergeUniqueStrings(strings.Split(left, " + "), strings.Split(right, " + "))
	return strings.Join(sources, " + ")
}

func mergeUniqueStrings(left []string, right []string) []string {
	seen := map[string]bool{}
	merged := make([]string, 0, len(left)+len(right))
	for _, item := range append(append([]string{}, left...), right...) {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		merged = append(merged, item)
	}
	sort.Strings(merged)
	return merged
}

type permissionAggregation struct {
	ActionSummary   string
	ActionVerb      string
	TargetGroup     string
	TargetResources []string
	Scope           string
	EvidenceStatus  string
	RelatedBindings []string
	GrantScore      int
	PriorityScore   int
	WhyCare         string
	NextReview      string
}

type permissionActionCandidate struct {
	ActionSummary   string
	ActionVerb      string
	TargetGroup     string
	TargetResources []string
	BaseScore       int
	NextReview      string
}

func derivePermissionPaths(currentIdentity model.CurrentIdentity, grants []model.RBACGrant) ([]model.PermissionPath, []model.Issue) {
	subject := currentSessionSubjectLabel(currentIdentity)

	// Keep the command honest: without a visible current identity, we cannot attribute effective power.
	if currentIdentity.Confidence == "blocked" || currentIdentity.Kind == "Unknown" {
		return nil, []model.Issue{{
			Kind:    "visibility",
			Scope:   "permissions.identity",
			Message: "Current session identity is not visible from current credentials, so current-foothold capability triage is incomplete.",
		}}
	}

	aggregated := map[string]*permissionAggregation{}
	for _, grant := range grants {
		if !grantMatchesCurrentIdentity(grant, currentIdentity) {
			continue
		}
		if grant.EvidenceStatus != "direct" {
			continue
		}

		for _, workloadAction := range grant.WorkloadActions {
			upsertPermissionAggregate(
				aggregated,
				permissionCandidateFromWorkloadAction(workloadAction),
				grant,
				currentIdentity.Confidence,
				permissionWorkloadActionPriorityScore(workloadAction, grant.Scope, currentIdentity.Confidence),
			)
		}

		for _, dangerousRight := range grant.DangerousRights {
			if len(grant.WorkloadActions) > 0 && (dangerousRight == "change workloads" || dangerousRight == "exec into pods") {
				continue
			}
			candidate, ok := permissionCandidateFromDangerousRight(dangerousRight)
			if !ok {
				continue
			}
			upsertPermissionAggregate(
				aggregated,
				candidate,
				grant,
				currentIdentity.Confidence,
				permissionPriorityScore(dangerousRight, grant.Scope, currentIdentity.Confidence),
			)
		}
	}

	rows := make([]model.PermissionPath, 0, len(aggregated))
	for _, aggregate := range aggregated {
		sort.Strings(aggregate.RelatedBindings)
		rows = append(rows, model.PermissionPath{
			ID:                permissionPathID(currentIdentity, aggregate.ActionSummary),
			Subject:           subject,
			SubjectConfidence: currentIdentity.Confidence,
			Scope:             aggregate.Scope,
			ActionVerb:        aggregate.ActionVerb,
			TargetGroup:       aggregate.TargetGroup,
			TargetResources:   aggregate.TargetResources,
			ActionSummary:     aggregate.ActionSummary,
			EvidenceStatus:    aggregate.EvidenceStatus,
			EvidenceSource:    "RBAC-derived",
			RelatedBindings:   aggregate.RelatedBindings,
			Priority:          semanticPriority(aggregate.PriorityScore),
			WhyCare:           aggregate.WhyCare,
			NextReview:        aggregate.NextReview,
		})
	}

	sort.SliceStable(rows, func(i, j int) bool {
		if priorityOrder(rows[i].Priority) != priorityOrder(rows[j].Priority) {
			return priorityOrder(rows[i].Priority) < priorityOrder(rows[j].Priority)
		}
		if permissionScopeRank(rows[i].Scope) != permissionScopeRank(rows[j].Scope) {
			return permissionScopeRank(rows[i].Scope) > permissionScopeRank(rows[j].Scope)
		}
		if permissionActionScore(rows[i].ActionSummary) != permissionActionScore(rows[j].ActionSummary) {
			return permissionActionScore(rows[i].ActionSummary) > permissionActionScore(rows[j].ActionSummary)
		}
		return rows[i].ActionSummary < rows[j].ActionSummary
	})

	return rows, nil
}

func currentSessionSubjectLabel(currentIdentity model.CurrentIdentity) string {
	return currentIdentity.Label + " (current session)"
}

func grantMatchesCurrentIdentity(grant model.RBACGrant, currentIdentity model.CurrentIdentity) bool {
	switch currentIdentity.Kind {
	case "User":
		return grant.SubjectKind == "User" && grant.SubjectName == currentIdentity.Label
	case "Group":
		return grant.SubjectKind == "Group" && grant.SubjectName == currentIdentity.Label
	case "ServiceAccount":
		if grant.SubjectKind != "ServiceAccount" {
			return false
		}
		if derefString(grant.SubjectNamespace) != derefString(currentIdentity.Namespace) {
			return false
		}
		return grant.SubjectName == currentIdentitySubjectName(currentIdentity)
	default:
		return false
	}
}

func currentIdentitySubjectName(currentIdentity model.CurrentIdentity) string {
	if currentIdentity.Kind != "ServiceAccount" || currentIdentity.Namespace == nil {
		return currentIdentity.Label
	}

	prefix := "system:serviceaccount:" + *currentIdentity.Namespace + ":"
	if strings.HasPrefix(currentIdentity.Label, prefix) {
		return strings.TrimPrefix(currentIdentity.Label, prefix)
	}

	if _, suffix, ok := strings.Cut(currentIdentity.Label, "/"); ok {
		return suffix
	}

	return currentIdentity.Label
}

func permissionActionSummary(dangerousRight string) string {
	switch dangerousRight {
	case "admin-like wildcard access":
		return "has cluster-wide admin-like access"
	case "read secrets":
		return "can read secrets"
	case "change workloads":
		return "can change workloads"
	case "exec into pods":
		return "can exec into pods"
	case "bind roles":
		return "can bind roles"
	case "escalate roles":
		return "can escalate roles"
	case "change admission or policy":
		return "can change admission or policy"
	case "touch nodes":
		return "can touch nodes"
	case "impersonate serviceaccounts":
		return "can impersonate serviceaccounts"
	case "impersonate users":
		return "can impersonate users"
	case "impersonate groups":
		return "can impersonate groups"
	case "impersonate identities":
		return "can impersonate identities"
	default:
		return ""
	}
}

func permissionActionScore(actionSummary string) int {
	switch actionSummary {
	case "has cluster-wide admin-like access":
		return providerDangerSignalScore("admin-like wildcard access")
	case "can read secrets":
		return providerDangerSignalScore("read secrets")
	case "can create pods":
		return 35
	case "can create workload controllers":
		return 32
	case "can patch workload controllers":
		return 34
	case "can update workload controllers":
		return 33
	case "can delete workload controllers":
		return 29
	case "can patch pods":
		return 31
	case "can update pods":
		return 30
	case "can delete pods":
		return 29
	case "can change workloads":
		return providerDangerSignalScore("change workloads")
	case "can exec into pods":
		return providerDangerSignalScore("exec into pods")
	case "can bind roles":
		return providerDangerSignalScore("bind roles")
	case "can escalate roles":
		return providerDangerSignalScore("escalate roles")
	case "can change admission or policy":
		return providerDangerSignalScore("change admission or policy")
	case "can touch nodes":
		return providerDangerSignalScore("touch nodes")
	case "can impersonate serviceaccounts":
		return providerDangerSignalScore("impersonate serviceaccounts")
	case "can impersonate users":
		return providerDangerSignalScore("impersonate users")
	case "can impersonate groups":
		return providerDangerSignalScore("impersonate groups")
	case "can impersonate identities":
		return providerDangerSignalScore("impersonate identities")
	default:
		return 0
	}
}

func permissionPathID(currentIdentity model.CurrentIdentity, actionSummary string) string {
	parts := []string{
		"current-session",
		strings.ToLower(currentIdentity.Kind),
		strings.ToLower(strings.ReplaceAll(currentIdentity.Label, " ", "-")),
		strings.ToLower(strings.ReplaceAll(actionSummary, " ", "-")),
	}
	return strings.Join(parts, ":")
}

func permissionPriorityScore(dangerousRight string, scope string, subjectConfidence string) int {
	score := providerDangerSignalScore(dangerousRight)
	switch scope {
	case "cluster-wide":
		score += 35
	default:
		score += 10
	}
	if subjectConfidence == "inferred" {
		score -= 10
	}
	return score
}

func upsertPermissionAggregate(
	aggregated map[string]*permissionAggregation,
	candidate permissionActionCandidate,
	grant model.RBACGrant,
	subjectConfidence string,
	candidateScore int,
) {
	aggregate := aggregated[candidate.ActionSummary]
	if aggregate == nil {
		aggregate = &permissionAggregation{
			ActionSummary:   candidate.ActionSummary,
			ActionVerb:      candidate.ActionVerb,
			TargetGroup:     candidate.TargetGroup,
			TargetResources: append([]string(nil), candidate.TargetResources...),
			Scope:           grant.Scope,
			EvidenceStatus:  grant.EvidenceStatus,
			RelatedBindings: []string{},
			GrantScore:      candidate.BaseScore,
			PriorityScore:   candidateScore,
			WhyCare:         derivePermissionWhyCare(candidate.ActionSummary, grant.Scope, subjectConfidence),
			NextReview:      candidate.NextReview,
		}
		aggregated[candidate.ActionSummary] = aggregate
	}

	aggregate.TargetResources = mergeSortedStrings(aggregate.TargetResources, candidate.TargetResources)
	aggregate.RelatedBindings = append(aggregate.RelatedBindings, grant.BindingName)
	if candidateScore <= aggregate.PriorityScore {
		return
	}

	aggregate.Scope = grant.Scope
	aggregate.PriorityScore = candidateScore
	aggregate.GrantScore = candidate.BaseScore
	aggregate.WhyCare = derivePermissionWhyCare(candidate.ActionSummary, grant.Scope, subjectConfidence)
	aggregate.NextReview = candidate.NextReview
}

func permissionWorkloadActionPriorityScore(action model.WorkloadAction, scope string, subjectConfidence string) int {
	score := permissionWorkloadActionBaseScore(action)
	switch scope {
	case "cluster-wide":
		score += 35
	default:
		score += 10
	}
	if subjectConfidence == "inferred" {
		score -= 10
	}
	return score
}

func permissionScopeRank(scope string) int {
	if scope == "cluster-wide" {
		return 2
	}
	if strings.HasPrefix(scope, "namespace/") {
		return 1
	}
	return 0
}

func derivePermissionWhyCare(actionSummary string, scope string, subjectConfidence string) string {
	switch subjectConfidence {
	case "inferred":
		return fmt.Sprintf("Current session probably %s in %s, but the identity match is inferred from visible session clues rather than directly confirmed.", permissionAbilityPhrase(actionSummary), scope)
	default:
		switch actionSummary {
		case "has cluster-wide admin-like access":
			return "Current session already has admin-like control across the cluster, which can shorten the path to broader abuse immediately."
		case "can read secrets":
			return fmt.Sprintf("Current session can read secrets in %s right now, which can widen access beyond this foothold.", scope)
		case "can create pods":
			return fmt.Sprintf("Current session can create pods in %s right now, which can start a fresh workload path from this foothold.", scope)
		case "can create workload controllers":
			return fmt.Sprintf("Current session can create workload controllers in %s right now, which can launch stronger workload paths without waiting on existing pods.", scope)
		case "can patch workload controllers":
			return fmt.Sprintf("Current session can patch workload controllers in %s right now, which can rewrite how existing workloads start or run.", scope)
		case "can update workload controllers":
			return fmt.Sprintf("Current session can update workload controllers in %s right now, which can replace workload definitions and change what runs next.", scope)
		case "can delete workload controllers":
			return fmt.Sprintf("Current session can delete workload controllers in %s right now, which can disrupt or reshape workload paths tied to this namespace.", scope)
		case "can patch pods":
			return fmt.Sprintf("Current session can patch pods in %s right now, which can change live workload state without waiting on a new deploy.", scope)
		case "can update pods":
			return fmt.Sprintf("Current session can update pods in %s right now, which can change live workload state directly from this foothold.", scope)
		case "can delete pods":
			return fmt.Sprintf("Current session can delete pods in %s right now, which can disrupt running workloads and force follow-on recovery paths.", scope)
		case "can change workloads":
			return fmt.Sprintf("Current session can change workloads in %s right now, which can turn cluster access into code-execution leverage.", scope)
		case "can exec into pods":
			return fmt.Sprintf("Current session can exec into pods in %s right now, which can expose runtime secrets and attached identities quickly.", scope)
		case "can bind roles":
			return fmt.Sprintf("Current session can bind roles in %s right now, which can turn visible access into stronger identity control.", scope)
		case "can escalate roles":
			return fmt.Sprintf("Current session can escalate roles in %s right now, which can turn visible access into stronger identity control.", scope)
		case "can touch nodes":
			return fmt.Sprintf("Current session can touch node-level paths in %s right now, which can move this foothold closer to host or control-plane influence.", scope)
		case "can change admission or policy":
			return fmt.Sprintf("Current session can change admission or policy in %s right now, which can reshape what workloads or identities are allowed next.", scope)
		case "can impersonate serviceaccounts", "can impersonate users", "can impersonate groups", "can impersonate identities":
			return fmt.Sprintf("Current session %s in %s right now, which can pivot this foothold into stronger identity control quickly.", permissionAbilityPhrase(actionSummary), scope)
		default:
			return fmt.Sprintf("Current session %s in %s right now, which changes what this foothold can do next.", permissionAbilityPhrase(actionSummary), scope)
		}
	}
}

func permissionAbilityPhrase(actionSummary string) string {
	if strings.HasPrefix(actionSummary, "can ") || strings.HasPrefix(actionSummary, "has ") {
		return actionSummary
	}
	return "can " + actionSummary
}

func permissionNextReview(dangerousRight string) string {
	switch dangerousRight {
	case "read secrets":
		return "secrets"
	case "change workloads", "exec into pods":
		return "workloads"
	case "touch nodes", "change admission or policy", "bind roles", "escalate roles", "admin-like wildcard access":
		return "privesc"
	default:
		return "rbac"
	}
}

func permissionNextReviewFromSummary(actionSummary string) string {
	switch actionSummary {
	case "has cluster-wide admin-like access":
		return "privesc"
	case "can read secrets":
		return "secrets"
	case "can bind roles", "can escalate roles", "can touch nodes", "can change admission or policy", "can impersonate serviceaccounts", "can impersonate users", "can impersonate groups", "can impersonate identities":
		return "privesc"
	}
	switch {
	case strings.HasPrefix(actionSummary, "can create pods"),
		strings.HasPrefix(actionSummary, "can create workload controllers"),
		strings.HasPrefix(actionSummary, "can patch workload controllers"),
		strings.HasPrefix(actionSummary, "can update workload controllers"),
		strings.HasPrefix(actionSummary, "can delete workload controllers"),
		strings.HasPrefix(actionSummary, "can patch pods"),
		strings.HasPrefix(actionSummary, "can update pods"),
		strings.HasPrefix(actionSummary, "can delete pods"),
		actionSummary == "can exec into pods":
		return "workloads"
	}
	return "rbac"
}

func permissionWorkloadActionBaseScore(action model.WorkloadAction) int {
	switch {
	case action.Verb == "exec":
		return 35
	case action.Verb == "create" && action.TargetGroup == "pods":
		return 35
	case action.Verb == "patch" && action.TargetGroup == "workload-controllers":
		return 34
	case action.Verb == "update" && action.TargetGroup == "workload-controllers":
		return 33
	case action.Verb == "create" && action.TargetGroup == "workload-controllers":
		return 32
	case action.Verb == "patch" && action.TargetGroup == "pods":
		return 31
	case action.Verb == "update" && action.TargetGroup == "pods":
		return 30
	case action.Verb == "delete":
		return 29
	default:
		return 28
	}
}

func permissionCandidateFromWorkloadAction(action model.WorkloadAction) permissionActionCandidate {
	return permissionActionCandidate{
		ActionSummary:   action.Summary,
		ActionVerb:      action.Verb,
		TargetGroup:     action.TargetGroup,
		TargetResources: append([]string(nil), action.TargetResources...),
		BaseScore:       permissionWorkloadActionBaseScore(action),
		NextReview:      permissionNextReviewFromSummary(action.Summary),
	}
}

func permissionCandidateFromDangerousRight(dangerousRight string) (permissionActionCandidate, bool) {
	actionSummary := permissionActionSummary(dangerousRight)
	if actionSummary == "" {
		return permissionActionCandidate{}, false
	}

	return permissionActionCandidate{
		ActionSummary:   actionSummary,
		ActionVerb:      permissionActionVerb(actionSummary),
		TargetGroup:     permissionTargetGroup(actionSummary),
		TargetResources: permissionTargetResources(actionSummary),
		BaseScore:       providerDangerSignalScore(dangerousRight),
		NextReview:      permissionNextReview(dangerousRight),
	}, true
}

func permissionActionVerb(actionSummary string) string {
	switch {
	case strings.HasPrefix(actionSummary, "can "):
		parts := strings.Fields(strings.TrimPrefix(actionSummary, "can "))
		if len(parts) > 0 {
			return parts[0]
		}
	case strings.HasPrefix(actionSummary, "has "):
		return "admin"
	}
	return ""
}

func permissionTargetGroup(actionSummary string) string {
	switch {
	case strings.Contains(actionSummary, "workload controllers"):
		return "workload-controllers"
	case strings.Contains(actionSummary, "pods"):
		return "pods"
	default:
		return ""
	}
}

func permissionTargetResources(actionSummary string) []string {
	switch actionSummary {
	case "can exec into pods":
		return []string{"pods/exec"}
	case "can create pods", "can patch pods", "can update pods", "can delete pods":
		return []string{"pods"}
	case "can create workload controllers", "can patch workload controllers", "can update workload controllers", "can delete workload controllers":
		return []string{"cronjobs", "daemonsets", "deployments", "jobs", "statefulsets"}
	default:
		return nil
	}
}

func mergeSortedStrings(existing []string, additions []string) []string {
	seen := map[string]struct{}{}
	merged := make([]string, 0, len(existing)+len(additions))
	for _, item := range existing {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		merged = append(merged, item)
	}
	for _, item := range additions {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		merged = append(merged, item)
	}
	sort.Strings(merged)
	return merged
}
