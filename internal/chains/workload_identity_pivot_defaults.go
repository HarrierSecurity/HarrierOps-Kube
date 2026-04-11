package chains

type WorkloadIdentityRowKind string

const (
	WorkloadIdentityRowExecIntoPodsInNamespace WorkloadIdentityRowKind = "exec-into-pods-in-namespace"
	WorkloadIdentityRowReadSecretsInNamespace  WorkloadIdentityRowKind = "read-secrets-in-namespace"
	WorkloadIdentityRowTokenPathVisible        WorkloadIdentityRowKind = "token-path-visible"
	WorkloadIdentityRowPatchSpecificSurface    WorkloadIdentityRowKind = "patch-specific-surface"
	WorkloadIdentityRowSwitchServiceAccount    WorkloadIdentityRowKind = "switch-service-account"
	WorkloadIdentityRowAddSidecar              WorkloadIdentityRowKind = "add-sidecar"
)

type WorkloadIdentityDefaultRowInputs struct {
	Kind                        WorkloadIdentityRowKind
	RuntimeInspectionProven     bool
	ExactActionProven           bool
	VisibleSurface              string
	VisibilityTier              string
	ConfidenceBoundaryAvailable bool
	ExactTargetNamed            bool
	WeakerFallbackAvailable     bool
}

type WorkloadIdentityDefaultRowDecision struct {
	AllowedDefault  bool
	SuppressDefault bool
	Reason          string
}

func WorkloadIdentityEarliestDefaultRowKinds() []WorkloadIdentityRowKind {
	return []WorkloadIdentityRowKind{
		WorkloadIdentityRowExecIntoPodsInNamespace,
		WorkloadIdentityRowReadSecretsInNamespace,
		WorkloadIdentityRowTokenPathVisible,
	}
}

func EvaluateWorkloadIdentityDefaultRow(inputs WorkloadIdentityDefaultRowInputs) WorkloadIdentityDefaultRowDecision {
	switch inputs.Kind {
	case WorkloadIdentityRowExecIntoPodsInNamespace:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  true,
			SuppressDefault: false,
			Reason:          "Safe earliest default: current scope already proves a workload-side execution lever in a bounded namespace.",
		}
	case WorkloadIdentityRowReadSecretsInNamespace:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  true,
			SuppressDefault: false,
			Reason:          "Safe earliest default: current scope already proves a bounded secret-read path that changes the next move.",
		}
	case WorkloadIdentityRowTokenPathVisible:
		if inputs.RuntimeInspectionProven {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: false,
				Reason:          "This is no longer the bounded token-path-visible row; direct runtime inspection is a different row type.",
			}
		}
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  true,
			SuppressDefault: false,
			Reason:          "Safe earliest default: current scope can report visible workload-linked token path without overstating runtime inspection.",
		}
	case WorkloadIdentityRowPatchSpecificSurface:
		if !inputs.ExactActionProven {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can prove the exact workload-changing edge for this row.",
			}
		}
		if !eligibleWorkloadPatchSurface(inputs.VisibleSurface) {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can name an exact visible patch surface that is safe for this row type.",
			}
		}
		if inputs.VisibilityTier == "" || inputs.VisibilityTier == "low" {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until visibility is strong enough that the exact patch row will not mislead.",
			}
		}
		if !inputs.ConfidenceBoundaryAvailable {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the row can state a positive evidence boundary.",
			}
		}
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  true,
			SuppressDefault: false,
			Reason:          "Safe exact-field default: current scope proves the workload-changing edge, the visible surface, and a positive confidence boundary on the same workload row.",
		}
	case WorkloadIdentityRowSwitchServiceAccount:
		if !inputs.ExactActionProven {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can prove the exact workload-changing edge for service-account repointing.",
			}
		}
		if inputs.VisibleSurface != "service account" {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can tie this row to the visible workload service-account field.",
			}
		}
		if inputs.VisibilityTier == "" || inputs.VisibilityTier == "low" {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until visibility is strong enough that the repointing row will not mislead.",
			}
		}
		if !inputs.ConfidenceBoundaryAvailable {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the row can state a positive evidence boundary.",
			}
		}
		if inputs.ExactTargetNamed {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  true,
				SuppressDefault: false,
				Reason:          "Safe exact-target default: current scope proves the service-account field is changeable and one stronger visible replacement is specific enough to name.",
			}
		}
		if inputs.WeakerFallbackAvailable {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  true,
				SuppressDefault: false,
				Reason:          "Safe family fallback: current scope proves the service-account field is changeable and stronger visible identity paths exist, but exact target selection would overclaim.",
			}
		}
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Keep out of default output until the family can either name one honest stronger target or keep the lead broader without misleading the operator.",
		}
	case WorkloadIdentityRowAddSidecar:
		if !inputs.ExactActionProven {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can prove the exact workload-changing edge for sidecar insertion.",
			}
		}
		if inputs.VisibleSurface != "sidecars" {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the family can tie this row to visible sidecar-related workload surfaces.",
			}
		}
		if inputs.VisibilityTier == "" || inputs.VisibilityTier == "low" {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until visibility is strong enough that sidecar wording will not mislead.",
			}
		}
		if !inputs.ConfidenceBoundaryAvailable {
			return WorkloadIdentityDefaultRowDecision{
				AllowedDefault:  false,
				SuppressDefault: true,
				Reason:          "Keep out of default output until the row can state a positive evidence boundary for sidecar-specific wording.",
			}
		}
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Keep out of default output until the family can prove honest insertion of a new sidecar, not just changeable sidecar-related workload surfaces.",
		}
	default:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Not part of the minimum honest first row set yet.",
		}
	}
}

func eligibleWorkloadPatchSurface(surface string) bool {
	switch surface {
	case "image":
		return true
	case "command":
		return true
	case "args":
		return true
	case "env":
		return true
	case "mounted secret refs":
		return true
	case "mounted config refs":
		return true
	case "init containers":
		return true
	default:
		return false
	}
}
