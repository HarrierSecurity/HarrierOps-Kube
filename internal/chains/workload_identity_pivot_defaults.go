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
	Kind                    WorkloadIdentityRowKind
	RuntimeInspectionProven bool
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
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Keep out of default output until the family can prove the exact patchable field honestly.",
		}
	case WorkloadIdentityRowSwitchServiceAccount:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Keep out of default output until the family can prove service-account switching as a real operator-complete path.",
		}
	case WorkloadIdentityRowAddSidecar:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Keep out of default output until the family can prove sidecar insertion without overstating workload behavior.",
		}
	default:
		return WorkloadIdentityDefaultRowDecision{
			AllowedDefault:  false,
			SuppressDefault: true,
			Reason:          "Not part of the minimum honest first row set yet.",
		}
	}
}
