package app

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
	"harrierops-kube/internal/provider"
)

func buildPrivescPayload(factProvider provider.Provider, query provider.QueryOptions) (map[string]any, error) {
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

	serviceAccountData, serviceAccountIssue := loadServiceAccountsSupportForPrivesc(factProvider, query)
	workloadData, workloadIssue := loadWorkloadsSupportForPrivesc(factProvider, query)
	exposureData, exposureIssue := loadExposuresSupportForPrivesc(factProvider, query)

	permissionRows, permissionIssues := derivePermissionPaths(whoamiData.CurrentIdentity, rbacData.RoleGrants)
	secretRows := enrichSecretPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	serviceAccountRows := enrichServiceAccountPaths(serviceAccountData.ServiceAccounts, workloadData, exposureData, rbacData)
	workloadRows := enrichWorkloadPaths(workloadData, serviceAccountData, exposureData, rbacData)
	escalationRows := derivePrivescPaths(
		whoamiData.CurrentIdentity,
		permissionRows,
		secretRows,
		serviceAccountRows,
		workloadRows,
	)
	if escalationRows == nil {
		escalationRows = []model.PrivescPath{}
	}

	issues := append([]model.Issue{}, whoamiData.Issues...)
	issues = append(issues, rbacData.Issues...)
	issues = append(issues, permissionIssues...)
	issues = append(issues, serviceAccountData.Issues...)
	issues = append(issues, workloadData.Issues...)
	issues = append(issues, exposureData.Issues...)
	if serviceAccountIssue != nil {
		issues = append(issues, *serviceAccountIssue)
	}
	if workloadIssue != nil {
		issues = append(issues, *workloadIssue)
	}
	if exposureIssue != nil {
		issues = append(issues, *exposureIssue)
	}

	return structToMap(model.PrivescOutput{
		Metadata:   buildMetadata("privesc", metadataContext, ""),
		Escalation: escalationRows,
		Issues:     issues,
	})
}

func loadServiceAccountsSupportForPrivesc(factProvider provider.Provider, query provider.QueryOptions) (model.ServiceAccountsData, *model.Issue) {
	data, err := factProvider.ServiceAccounts(query)
	if err == nil {
		return data, nil
	}
	return model.ServiceAccountsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "privesc.service-accounts",
		Message: "Escalation triage could not load service-account support data, so identity-backed leads may be understated.",
	}
}

func loadWorkloadsSupportForPrivesc(factProvider provider.Provider, query provider.QueryOptions) (model.WorkloadsData, *model.Issue) {
	data, err := factProvider.Workloads(query)
	if err == nil {
		return data, nil
	}
	return model.WorkloadsData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "privesc.workloads",
		Message: "Escalation triage could not load workload support data, so execution-backed leads may be understated.",
	}
}

func loadExposuresSupportForPrivesc(factProvider provider.Provider, query provider.QueryOptions) (model.ExposureData, *model.Issue) {
	data, err := factProvider.Exposures(query)
	if err == nil {
		return data, nil
	}
	return model.ExposureData{}, &model.Issue{
		Kind:    "collection",
		Scope:   "privesc.exposure",
		Message: "Escalation triage could not load exposure support data, so public-facing workload leverage may be understated.",
	}
}

func derivePrivescPaths(
	currentIdentity model.CurrentIdentity,
	permissionRows []model.PermissionPath,
	secretRows []model.SecretPath,
	serviceAccountRows []model.ServiceAccountPath,
	workloadRows []model.WorkloadPath,
) []model.PrivescPath {
	startingFoothold := currentFootholdLabel(currentIdentity)
	rows := []model.PrivescPath{}

	rows = append(rows, deriveImmediatePrivescRows(startingFoothold, currentIdentity.Confidence, permissionRows)...)
	rows = append(rows, deriveSecretBackedPrivescRows(startingFoothold, currentIdentity.Confidence, permissionRows, secretRows)...)
	rows = append(rows, derivePostureOnlyPrivescRows(startingFoothold, currentIdentity.Confidence, serviceAccountRows, workloadRows)...)

	sort.SliceStable(rows, func(i, j int) bool {
		if priorityOrder(rows[i].Priority) != priorityOrder(rows[j].Priority) {
			return priorityOrder(rows[i].Priority) < priorityOrder(rows[j].Priority)
		}
		if privescClassRank(rows[i].PathClass) != privescClassRank(rows[j].PathClass) {
			return privescClassRank(rows[i].PathClass) > privescClassRank(rows[j].PathClass)
		}
		if privescSignalRank(rows[i].OperatorSignal) != privescSignalRank(rows[j].OperatorSignal) {
			return privescSignalRank(rows[i].OperatorSignal) > privescSignalRank(rows[j].OperatorSignal)
		}
		return rows[i].Action < rows[j].Action
	})

	return rows
}

func deriveImmediatePrivescRows(startingFoothold string, subjectConfidence string, permissionRows []model.PermissionPath) []model.PrivescPath {
	rows := []model.PrivescPath{}
	for _, permissionRow := range permissionRows {
		switch permissionRow.ActionSummary {
		case "has cluster-wide admin-like access", "can impersonate serviceaccounts", "can impersonate users", "can impersonate groups", "can impersonate identities", "can bind roles", "can escalate roles":
			rows = append(rows, model.PrivescPath{
				ID:                "privesc:" + strings.ReplaceAll(permissionRow.ID, "current-session:", ""),
				StartingFoothold:  startingFoothold,
				SubjectConfidence: subjectConfidence,
				PathClass:         "identity-control-immediate",
				Action:            permissionRow.ActionSummary,
				StrongerOutcome:   identityControlOutcome(permissionRow.ActionSummary),
				OutcomePower:      permissionRow.ActionSummary,
				Confidence:        privescRowConfidence(subjectConfidence, "direct"),
				OperatorSignal:    privescSignalForClass("identity-control-immediate", permissionRow.Priority),
				Priority:          permissionRow.Priority,
				WhatIsProven:      fmt.Sprintf("%s can %s in %s now.", startingFoothold, strings.TrimPrefix(permissionRow.ActionSummary, "can "), permissionRow.Scope),
				WhatIsMissing:     identityControlMissing(permissionRow.ActionSummary),
				WhyCare:           deriveImmediatePrivescWhyCare("identity-control-immediate", permissionRow),
				NextReview:        "rbac",
			})
		case "can touch nodes", "can change admission or policy":
			rows = append(rows, model.PrivescPath{
				ID:                "privesc:" + strings.ReplaceAll(permissionRow.ID, "current-session:", ""),
				StartingFoothold:  startingFoothold,
				SubjectConfidence: subjectConfidence,
				PathClass:         "execution-control-immediate",
				Action:            permissionRow.ActionSummary,
				StrongerOutcome:   executionControlOutcome(permissionRow),
				OutcomePower:      permissionRow.ActionSummary,
				Confidence:        privescRowConfidence(subjectConfidence, "direct"),
				OperatorSignal:    privescSignalForClass("execution-control-immediate", permissionRow.Priority),
				Priority:          permissionRow.Priority,
				WhatIsProven:      fmt.Sprintf("%s can %s in %s now.", startingFoothold, strings.TrimPrefix(permissionRow.ActionSummary, "can "), permissionRow.Scope),
				WhatIsMissing:     executionControlMissing(permissionRow),
				WhyCare:           deriveImmediatePrivescWhyCare("execution-control-immediate", permissionRow),
				NextReview:        "workloads",
			})
		default:
			if !isImmediateExecutionPermission(permissionRow) {
				continue
			}
			rows = append(rows, model.PrivescPath{
				ID:                "privesc:" + strings.ReplaceAll(permissionRow.ID, "current-session:", ""),
				StartingFoothold:  startingFoothold,
				SubjectConfidence: subjectConfidence,
				PathClass:         "execution-control-immediate",
				Action:            permissionRow.ActionSummary,
				StrongerOutcome:   executionControlOutcome(permissionRow),
				OutcomePower:      permissionRow.ActionSummary,
				Confidence:        privescRowConfidence(subjectConfidence, "direct"),
				OperatorSignal:    privescSignalForClass("execution-control-immediate", permissionRow.Priority),
				Priority:          permissionRow.Priority,
				WhatIsProven:      fmt.Sprintf("%s can %s in %s now.", startingFoothold, strings.TrimPrefix(permissionRow.ActionSummary, "can "), permissionRow.Scope),
				WhatIsMissing:     executionControlMissing(permissionRow),
				WhyCare:           deriveImmediatePrivescWhyCare("execution-control-immediate", permissionRow),
				NextReview:        "workloads",
			})
		}
	}
	return rows
}

func deriveSecretBackedPrivescRows(
	startingFoothold string,
	subjectConfidence string,
	permissionRows []model.PermissionPath,
	secretRows []model.SecretPath,
) []model.PrivescPath {
	canReadSecrets := false
	for _, permissionRow := range permissionRows {
		if permissionRow.ActionSummary == "can read secrets" || permissionRow.ActionSummary == "has cluster-wide admin-like access" {
			canReadSecrets = true
			break
		}
	}
	if !canReadSecrets {
		return nil
	}

	rows := []model.PrivescPath{}
	for _, secretRow := range secretRows {
		if secretRow.SecretStory != "stores-secret" {
			continue
		}
		if secretRow.LikelySecretType != "service-account token" && secretRow.LikelySecretType != "projected service-account token" && secretRow.LikelySecretType != "registry credential" {
			continue
		}
		rows = append(rows, model.PrivescPath{
			ID:                "privesc:" + secretRow.ID,
			StartingFoothold:  startingFoothold,
			SubjectConfidence: subjectConfidence,
			PathClass:         "workload-control-backed",
			Action:            "read secret path " + secretRow.SafeLabel,
			StrongerOutcome:   secretBackedOutcome(secretRow),
			OutcomePower:      secretRow.LikelyTargetFamily,
			Confidence:        privescRowConfidence(subjectConfidence, "likely"),
			OperatorSignal:    privescSignalForClass("workload-control-backed", secretRow.Priority),
			Priority:          secretRow.Priority,
			WhatIsProven:      fmt.Sprintf("%s can already read secrets, and %s is visible through %s.", startingFoothold, secretRow.SafeLabel, secretRow.SourceSurface),
			WhatIsMissing:     secretBackedMissing(secretRow),
			WhyCare:           deriveSecretBackedPrivescWhyCare(secretRow),
			NextReview:        secretRow.NextReview,
		})
		if len(rows) == 2 {
			break
		}
	}
	return rows
}

func derivePostureOnlyPrivescRows(
	startingFoothold string,
	subjectConfidence string,
	serviceAccountRows []model.ServiceAccountPath,
	workloadRows []model.WorkloadPath,
) []model.PrivescPath {
	rows := []model.PrivescPath{}

	for _, serviceAccountRow := range serviceAccountRows {
		if serviceAccountRow.Priority != "high" {
			continue
		}
		rows = append(rows, model.PrivescPath{
			ID:                "privesc:posture:service-account:" + serviceAccountRow.Namespace + ":" + serviceAccountRow.Name,
			StartingFoothold:  startingFoothold,
			SubjectConfidence: subjectConfidence,
			PathClass:         "posture-only",
			Action:            "no current action is proven against " + serviceAccountRow.Namespace + "/" + serviceAccountRow.Name,
			StrongerOutcome:   "stronger service-account path if control is gained",
			OutcomePower:      serviceAccountRow.PowerSummary,
			Confidence:        "possible",
			OperatorSignal:    "bookmark",
			Priority:          "low",
			WhatIsProven:      fmt.Sprintf("Service account %s/%s has a stronger identity path visible now.", serviceAccountRow.Namespace, serviceAccountRow.Name),
			WhatIsMissing:     "Current foothold control of that service account, token path, or attached workload is not proven.",
			WhyCare:           fmt.Sprintf("Lead stays visible because %s.", lowerFirst(serviceAccountRow.WhyCare)),
			NextReview:        "service-accounts",
		})
		break
	}

	for _, workloadRow := range workloadRows {
		if workloadRow.Priority != "high" {
			continue
		}
		rows = append(rows, model.PrivescPath{
			ID:                "privesc:posture:workload:" + workloadRow.Namespace + ":" + workloadRow.Name,
			StartingFoothold:  startingFoothold,
			SubjectConfidence: subjectConfidence,
			PathClass:         "posture-only",
			Action:            "no current action is proven against " + workloadRow.Namespace + "/" + workloadRow.Name,
			StrongerOutcome:   "stronger execution path if workload control is gained",
			OutcomePower:      workloadRow.ServiceAccountPower,
			Confidence:        "possible",
			OperatorSignal:    "bookmark",
			Priority:          "low",
			WhatIsProven:      fmt.Sprintf("Workload %s/%s is already visible as a strong execution or identity lead.", workloadRow.Namespace, workloadRow.Name),
			WhatIsMissing:     "Current foothold control of that workload, its token path, or its service account is not proven.",
			WhyCare:           fmt.Sprintf("Lead stays visible because %s.", lowerFirst(workloadRow.WhyCare)),
			NextReview:        "workloads",
		})
		if len(rows) == 2 {
			break
		}
	}

	return rows
}

func currentFootholdLabel(currentIdentity model.CurrentIdentity) string {
	return currentIdentity.Label + " (current foothold)"
}

func privescClassRank(pathClass string) int {
	switch pathClass {
	case "identity-control-immediate":
		return 4
	case "execution-control-immediate":
		return 3
	case "workload-control-backed":
		return 2
	default:
		return 1
	}
}

func privescSignalRank(signal string) int {
	switch signal {
	case "pivot-now":
		return 3
	case "review-soon":
		return 2
	default:
		return 1
	}
}

func privescSignalForClass(pathClass string, priority string) string {
	switch pathClass {
	case "identity-control-immediate", "execution-control-immediate":
		if priority == "high" {
			return "pivot-now"
		}
		return "review-soon"
	case "workload-control-backed":
		if priority == "high" {
			return "review-soon"
		}
		return "bookmark"
	default:
		return "bookmark"
	}
}

func privescRowConfidence(subjectConfidence string, base string) string {
	if subjectConfidence == "inferred" && base == "direct" {
		return "likely"
	}
	return base
}

func identityControlOutcome(action string) string {
	switch action {
	case "has cluster-wide admin-like access":
		return "cluster-wide identity and control leverage"
	case "can bind roles", "can escalate roles":
		return "stronger RBAC control"
	case "can impersonate users", "can impersonate groups":
		return "stronger human or group identity control"
	default:
		return "stronger service-account or identity control"
	}
}

func executionControlOutcome(permissionRow model.PermissionPath) string {
	switch permissionRow.ActionSummary {
	case "can touch nodes":
		return "host or control-plane adjacent access"
	case "can change admission or policy":
		return "disable guardrails and create stronger workloads"
	case "can exec into pods":
		return "runtime secret or attached identity access"
	case "can create pods":
		return "create a new workload execution foothold"
	case "can create workload controllers":
		return "create a new workload-controller foothold"
	case "can patch workload controllers", "can update workload controllers":
		return "rewrite existing workload behavior"
	case "can patch pods", "can update pods":
		return "change live workload behavior"
	case "can delete workload controllers", "can delete pods":
		return "disrupt workload paths and force recovery"
	default:
		return "stronger workload execution foothold"
	}
}

func identityControlMissing(action string) string {
	switch action {
	case "has cluster-wide admin-like access":
		return "Need exact abuse path selection and target confirmation, not more proof that broad control exists."
	case "can bind roles", "can escalate roles":
		return "Need exact target role or binding review to show which stronger identity path to take first."
	default:
		return "Need exact target identity selection to show which stronger identity path matters first."
	}
}

func executionControlMissing(permissionRow model.PermissionPath) string {
	switch permissionRow.ActionSummary {
	case "can change admission or policy":
		return "Need exact policy target review to show which guardrail can be removed or reshaped first."
	case "can touch nodes":
		return "Need exact node-touching target review to show whether the next move is workload, host, or control-plane adjacent."
	case "can create pods":
		return "Need exact namespace target review to show which new pod path is the best next move."
	case "can create workload controllers":
		return "Need exact controller target review to show which new workload definition changes the next move fastest."
	case "can patch workload controllers", "can update workload controllers":
		return "Need exact workload target review to show which existing controller should be changed first."
	case "can patch pods", "can update pods":
		return "Need exact pod target review to show which live workload can be changed first."
	case "can delete workload controllers", "can delete pods":
		return "Need exact workload target review to show whether disruption creates a meaningful follow-on path."
	default:
		return "Need exact workload target review to show which execution path yields the strongest follow-on foothold."
	}
}

func isImmediateExecutionPermission(permissionRow model.PermissionPath) bool {
	switch permissionRow.ActionSummary {
	case "can change workloads", "can exec into pods":
		return true
	}
	switch permissionRow.ActionVerb {
	case "create", "patch", "update", "delete", "exec":
		return permissionRow.TargetGroup == "pods" || permissionRow.TargetGroup == "workload-controllers"
	default:
		return false
	}
}

func deriveImmediatePrivescWhyCare(pathClass string, permissionRow model.PermissionPath) string {
	switch pathClass {
	case "identity-control-immediate":
		return fmt.Sprintf("Path rises because %s and that directly changes identity power without waiting on another foothold.", lowerFirst(permissionRow.WhyCare))
	default:
		return fmt.Sprintf("Path rises because %s and that directly changes execution control from the current foothold.", lowerFirst(permissionRow.WhyCare))
	}
}

func secretBackedOutcome(secretRow model.SecretPath) string {
	switch secretRow.LikelySecretType {
	case "service-account token", "projected service-account token":
		return "stronger Kubernetes identity foothold"
	case "registry credential":
		return "registry or workload supply-chain leverage"
	default:
		return "stronger trust path"
	}
}

func secretBackedMissing(secretRow model.SecretPath) string {
	switch secretRow.LikelySecretType {
	case "service-account token", "projected service-account token":
		return "Need secret read validation and follow-on identity scope confirmation before claiming the stronger foothold as proven."
	default:
		return "Need secret read or downstream trust confirmation before claiming the stronger outcome as proven."
	}
}

func deriveSecretBackedPrivescWhyCare(secretRow model.SecretPath) string {
	return fmt.Sprintf("Path rises because %s.", lowerFirst(secretRow.WhyCare))
}

func lowerFirst(text string) string {
	if text == "" {
		return text
	}
	if strings.HasSuffix(text, ".") {
		text = strings.TrimSuffix(text, ".")
	}
	return strings.ToLower(text[:1]) + text[1:]
}
