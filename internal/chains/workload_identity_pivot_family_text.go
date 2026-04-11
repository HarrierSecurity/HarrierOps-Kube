package chains

const workloadIdentityPivotCurrentGap = "Not covered by this family yet: rows that only reach visible token or identity clues still stop before the exact workload-side action is named; broader service-account repointing rows still stop before one exact stronger replacement can be selected honestly; sidecar-specific rows stay suppressed until current evidence proves insertion, not just change surface."

var workloadIdentityPivotHelpNotes = []string{
	"Use `harrierops-kube chains` for the overview and `harrierops-kube chains workload-identity-pivot` to run the first live family from current scope.",
	"Default row wording stays evidence-bounded: it should show what is visible, what the current foothold may already be able to do, and the exact missing step when the path still stops short.",
	"Coverage limits in the family overview are current implementation limits, not operator steps to go do manually.",
	"Exact patch rows stay limited to safe visible workload fields the family can tie to the same workload honestly; sidecar wording stays suppressed.",
	"Service-account repointing rows name one exact replacement only when current scope makes that target specific; otherwise the family keeps the lead broader.",
	"Sidecar-specific rows stay suppressed until the family can prove honest insertion of a new sidecar, not just changeable sidecar-related workload surfaces.",
}

func WorkloadIdentityPivotCurrentGap() string {
	return workloadIdentityPivotCurrentGap
}

func WorkloadIdentityPivotHelpNotes() []string {
	return append([]string(nil), workloadIdentityPivotHelpNotes...)
}
