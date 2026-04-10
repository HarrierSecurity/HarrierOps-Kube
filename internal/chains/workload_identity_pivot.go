package chains

import (
	"fmt"
	"sort"
	"strings"

	"harrierops-kube/internal/contracts"
	"harrierops-kube/internal/model"
)

type WorkloadIdentityPivotInputs struct {
	StartingFoothold string
	Workloads        []model.WorkloadPath
	ServiceAccounts  []model.ServiceAccountPath
	Permissions      []model.PermissionPath
	Secrets          []model.SecretPath
	Issues           []model.Issue
}

func BuildWorkloadIdentityPivotOutput(metadata contracts.Metadata, inputs WorkloadIdentityPivotInputs) (model.ChainsOutput, error) {
	spec, ok := FamilySpecFor("workload-identity-pivot")
	if !ok {
		return model.ChainsOutput{}, fmt.Errorf("unknown chain family %q", "workload-identity-pivot")
	}

	rows := buildWorkloadIdentityPivotRows(inputs)
	sort.SliceStable(rows, func(i, j int) bool {
		leftPriority := chainPriorityOrder(rows[i].Priority)
		rightPriority := chainPriorityOrder(rows[j].Priority)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if visibilityTierRank(rows[i].VisibilityTier) != visibilityTierRank(rows[j].VisibilityTier) {
			return visibilityTierRank(rows[i].VisibilityTier) < visibilityTierRank(rows[j].VisibilityTier)
		}
		if chainPathTypeRank(rows[i].PathType) != chainPathTypeRank(rows[j].PathType) {
			return chainPathTypeRank(rows[i].PathType) < chainPathTypeRank(rows[j].PathType)
		}
		return rows[i].SourceAsset < rows[j].SourceAsset
	})

	summary := "No bounded workload-identity pivot rows were confirmed from current scope."
	commandState := "ok"
	if len(rows) > 0 {
		summary = fmt.Sprintf("%d workload-linked identity path", len(rows))
		if len(rows) == 1 {
			summary += " is"
		} else {
			summary += "s are"
		}
		summary += " ready for first review."
	}

	return model.ChainsOutput{
		Metadata:           metadata,
		GroupedCommandName: GroupedCommandName,
		Family:             "workload-identity-pivot",
		InputMode:          "live",
		CommandState:       commandState,
		Summary:            summary,
		ClaimBoundary:      spec.AllowedClaim,
		BackingCommands:    []string{"workloads", "service-accounts", "permissions", "secrets"},
		Paths:              rows,
		Issues:             inputs.Issues,
	}, nil
}

func buildWorkloadIdentityPivotRows(inputs WorkloadIdentityPivotInputs) []model.ChainPathRecord {
	workloadByLabel := map[string]model.WorkloadPath{}
	workloadByNamespace := map[string][]model.WorkloadPath{}
	for _, workload := range inputs.Workloads {
		label := workload.Namespace + "/" + workload.Name
		workloadByLabel[label] = workload
		workloadByNamespace[workload.Namespace] = append(workloadByNamespace[workload.Namespace], workload)
	}

	serviceAccountByKey := map[string]model.ServiceAccountPath{}
	for _, serviceAccount := range inputs.ServiceAccounts {
		serviceAccountByKey[serviceAccount.Namespace+"/"+serviceAccount.Name] = serviceAccount
	}

	rows := []model.ChainPathRecord{}
	rows = append(rows, buildExecIntoPodsRows(inputs, workloadByNamespace, serviceAccountByKey)...)
	rows = append(rows, buildReadSecretsRows(inputs, workloadByLabel, serviceAccountByKey)...)
	rows = append(rows, buildTokenPathVisibleRows(inputs, workloadByLabel, serviceAccountByKey)...)
	return rows
}

func buildExecIntoPodsRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, permission := range inputs.Permissions {
		if permission.ActionSummary != "can exec into pods" {
			continue
		}

		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		workload, ok := strongestWorkloadForScope(namespace, workloadByNamespace, serviceAccountByKey)
		if !ok {
			continue
		}

		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			SubversionPointVisible:  true,
			AttachedIdentityVisible: workload.ServiceAccountName != "",
			StrongerControlVisible:  serviceAccount.PowerSummary != "",
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowExecIntoPodsInNamespace,
		})
		if !decision.AllowedDefault {
			continue
		}

		controlSummary := "attached service account changes the next move"
		if serviceAccount.PowerSummary != "" {
			controlSummary = "attached service account " + serviceAccount.PowerSummary
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:exec:" + workload.Namespace + ":" + workload.Name,
			Priority:                workload.Priority,
			InternalProofState:      "path-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control visible",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "exec into pods in namespace " + workload.Namespace,
			LikelyKubernetesControl: controlSummary,
			Urgency:                 "now",
			WhyStopHere:             "current foothold can reach an already running workload with stronger identity",
			ConfidenceBoundary:      "Current scope confirms the current foothold can exec into pods in namespace " + workload.Namespace + ".",
			NextReview:              "workloads",
			Summary:                 visibility.OperatorWording,
			EvidenceCommands:        []string{"permissions", "workloads", "service-accounts"},
			RelatedIDs:              []string{workload.ID, serviceAccount.ID, permission.ID},
		})
	}
	return rows
}

func buildReadSecretsRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByLabel map[string]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, permission := range inputs.Permissions {
		if permission.ActionSummary != "can read secrets" {
			continue
		}

		namespace, ok := namespaceScope(permission.Scope)
		if !ok {
			continue
		}
		secretPath, workload, serviceAccount, ok := strongestSecretPathForScope(namespace, inputs.Secrets, workloadByLabel, serviceAccountByKey)
		if !ok {
			continue
		}

		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			SubversionPointVisible:  true,
			AttachedIdentityVisible: workload.ServiceAccountName != "",
			StrongerControlVisible:  serviceAccount.PowerSummary != "",
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowReadSecretsInNamespace,
		})
		if !decision.AllowedDefault {
			continue
		}

		controlSummary := secretPath.LikelyTargetFamily
		if serviceAccount.PowerSummary != "" {
			controlSummary = "attached service account " + serviceAccount.PowerSummary
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:secret-read:" + secretPath.Namespace + ":" + secretPath.SafeLabel,
			Priority:                secretPath.Priority,
			InternalProofState:      "path-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control visible",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "read secrets in namespace " + secretPath.Namespace,
			LikelyKubernetesControl: controlSummary,
			Urgency:                 "now",
			WhyStopHere:             "current foothold can read secret-backed workload trust material in this namespace",
			ConfidenceBoundary:      "Current scope confirms the current foothold can read secrets in namespace " + secretPath.Namespace + ".",
			NextReview:              secretPath.NextReview,
			Summary:                 visibility.OperatorWording,
			EvidenceCommands:        []string{"permissions", "secrets", "workloads", "service-accounts"},
			RelatedIDs:              []string{permission.ID, secretPath.ID, workload.ID, serviceAccount.ID},
		})
	}
	return rows
}

func buildTokenPathVisibleRows(
	inputs WorkloadIdentityPivotInputs,
	workloadByLabel map[string]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) []model.ChainPathRecord {
	rows := []model.ChainPathRecord{}
	for _, serviceAccount := range inputs.ServiceAccounts {
		if !strings.Contains(serviceAccount.TokenPosture, "visible token path") && !strings.Contains(serviceAccount.TokenPosture, "legacy token secret is visible") {
			continue
		}
		if len(serviceAccount.RelatedWorkloads) == 0 || serviceAccount.PowerSummary == "" {
			continue
		}

		workload, ok := workloadByLabel[serviceAccount.RelatedWorkloads[0]]
		if !ok {
			continue
		}

		visibility, ok := ClassifyWorkloadIdentityVisibility(WorkloadIdentityVisibilityInputs{
			WorkloadVisible:         true,
			AttachedIdentityVisible: true,
			StrongerControlVisible:  true,
			ExactBlockerKnown:       true,
			NextReviewSet:           true,
		})
		if !ok {
			continue
		}

		decision := EvaluateWorkloadIdentityDefaultRow(WorkloadIdentityDefaultRowInputs{
			Kind: WorkloadIdentityRowTokenPathVisible,
		})
		if !decision.AllowedDefault {
			continue
		}

		relatedIDs := []string{serviceAccount.ID}
		if workload.ID != "" {
			relatedIDs = append(relatedIDs, workload.ID)
		}
		if secretID, ok := strongestTokenSecretIDForWorkload(workload.Namespace+"/"+workload.Name, inputs.Secrets); ok {
			relatedIDs = append(relatedIDs, secretID)
		}

		rows = append(rows, model.ChainPathRecord{
			ChainID:                 "workload-identity-pivot:token-path:" + workload.Namespace + ":" + workload.Name,
			Priority:                serviceAccount.Priority,
			InternalProofState:      "target-confirmed",
			VisibilityTier:          visibility.Tier,
			PathType:                "direct control not confirmed",
			StartingFoothold:        inputs.StartingFoothold,
			SourceAsset:             workload.Namespace + "/" + workload.Name,
			SourceNamespace:         workload.Namespace,
			SubversionPoint:         "review visible workload-linked token path",
			LikelyKubernetesControl: "attached service account " + serviceAccount.PowerSummary,
			Urgency:                 "soon",
			WhyStopHere:             "current scope can see a workload-linked token path on stronger identity",
			ConfidenceBoundary:      "Current scope confirms a workload-linked token path is visible, but runtime inspection is not yet proven.",
			NextReview:              "workloads",
			Summary:                 visibility.OperatorWording,
			MissingConfirmation:     "Current foothold control of that workload or runtime token inspection is not yet proven.",
			EvidenceCommands:        []string{"service-accounts", "secrets", "workloads", "privesc"},
			RelatedIDs:              relatedIDs,
		})
	}
	return rows
}

func strongestWorkloadForScope(
	namespace string,
	workloadByNamespace map[string][]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (model.WorkloadPath, bool) {
	if namespace != "" {
		return strongestWorkload(workloadByNamespace[namespace], serviceAccountByKey)
	}

	all := []model.WorkloadPath{}
	for _, workloads := range workloadByNamespace {
		all = append(all, workloads...)
	}
	return strongestWorkload(all, serviceAccountByKey)
}

func strongestWorkload(workloads []model.WorkloadPath, serviceAccountByKey map[string]model.ServiceAccountPath) (model.WorkloadPath, bool) {
	bestIndex := -1
	bestScore := -1
	for index, workload := range workloads {
		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]
		if serviceAccount.PowerSummary == "" {
			continue
		}

		score := triageScore(workload.Priority)
		if workload.PublicExposure {
			score += 10
		}
		if len(workload.RiskSignals) > 0 {
			score += 5
		}
		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}
	if bestIndex == -1 {
		return model.WorkloadPath{}, false
	}
	return workloads[bestIndex], true
}

func strongestSecretPathForScope(
	namespace string,
	secrets []model.SecretPath,
	workloadByLabel map[string]model.WorkloadPath,
	serviceAccountByKey map[string]model.ServiceAccountPath,
) (model.SecretPath, model.WorkloadPath, model.ServiceAccountPath, bool) {
	bestIndex := -1
	bestScore := -1
	var bestWorkload model.WorkloadPath
	var bestServiceAccount model.ServiceAccountPath

	for index, secretPath := range secrets {
		if namespace != "" && secretPath.Namespace != namespace {
			continue
		}
		if len(secretPath.RelatedWorkloads) == 0 {
			continue
		}
		workload, ok := workloadByLabel[secretPath.RelatedWorkloads[0]]
		if !ok {
			continue
		}
		serviceAccount := serviceAccountByKey[workload.Namespace+"/"+workload.ServiceAccountName]

		score := triageScore(secretPath.Priority) + triageScore(workload.Priority)
		if serviceAccount.PowerSummary != "" {
			score += 10
		}
		if score > bestScore {
			bestScore = score
			bestIndex = index
			bestWorkload = workload
			bestServiceAccount = serviceAccount
		}
	}
	if bestIndex == -1 {
		return model.SecretPath{}, model.WorkloadPath{}, model.ServiceAccountPath{}, false
	}
	return secrets[bestIndex], bestWorkload, bestServiceAccount, true
}

func strongestTokenSecretIDForWorkload(workloadLabel string, secrets []model.SecretPath) (string, bool) {
	for _, secretPath := range secrets {
		if len(secretPath.RelatedWorkloads) == 0 {
			continue
		}
		if secretPath.RelatedWorkloads[0] != workloadLabel {
			continue
		}
		if secretPath.LikelySecretType == "service-account token" || secretPath.LikelySecretType == "projected service-account token" {
			return secretPath.ID, true
		}
	}
	return "", false
}

func triageScore(priority string) int {
	switch priority {
	case "high":
		return 30
	case "medium":
		return 20
	case "low":
		return 10
	default:
		return 0
	}
}

func chainPriorityOrder(priority string) int {
	switch priority {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func visibilityTierRank(tier string) int {
	switch tier {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

func chainPathTypeRank(pathType string) int {
	switch pathType {
	case "direct control visible":
		return 0
	case "workload pivot":
		return 1
	case "direct control not confirmed":
		return 2
	case "visibility blocked":
		return 3
	default:
		return 4
	}
}

func namespaceScope(scope string) (string, bool) {
	const prefix = "namespace/"
	if strings.HasPrefix(scope, prefix) {
		namespace := strings.TrimPrefix(scope, prefix)
		return namespace, namespace != ""
	}
	return "", false
}
