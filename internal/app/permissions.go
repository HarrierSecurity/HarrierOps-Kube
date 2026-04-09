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

	rows, permissionIssues := derivePermissionPaths(whoamiData.CurrentIdentity, rbacData.RoleGrants)
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

type permissionAggregation struct {
	ActionSummary   string
	Scope           string
	EvidenceStatus  string
	RelatedBindings []string
	GrantScore      int
	PriorityScore   int
	WhyCare         string
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

		for _, dangerousRight := range grant.DangerousRights {
			actionSummary := permissionActionSummary(dangerousRight)
			if actionSummary == "" {
				continue
			}

			candidateScore := permissionPriorityScore(dangerousRight, grant.Scope, currentIdentity.Confidence)
			aggregate := aggregated[actionSummary]
			if aggregate == nil {
				aggregate = &permissionAggregation{
					ActionSummary:   actionSummary,
					Scope:           grant.Scope,
					EvidenceStatus:  grant.EvidenceStatus,
					RelatedBindings: []string{},
					GrantScore:      providerDangerSignalScore(dangerousRight),
					PriorityScore:   candidateScore,
					WhyCare:         derivePermissionWhyCare(actionSummary, grant.Scope, currentIdentity.Confidence),
					NextReview:      permissionNextReview(dangerousRight),
				}
				aggregated[actionSummary] = aggregate
			}

			aggregate.RelatedBindings = append(aggregate.RelatedBindings, grant.BindingName)
			if candidateScore > aggregate.PriorityScore {
				aggregate.Scope = grant.Scope
				aggregate.PriorityScore = candidateScore
				aggregate.GrantScore = providerDangerSignalScore(dangerousRight)
				aggregate.WhyCare = derivePermissionWhyCare(actionSummary, grant.Scope, currentIdentity.Confidence)
				aggregate.NextReview = permissionNextReview(dangerousRight)
			}
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
			ActionSummary:     aggregate.ActionSummary,
			EvidenceStatus:    aggregate.EvidenceStatus,
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
