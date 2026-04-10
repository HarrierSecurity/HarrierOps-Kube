package app

import (
	"fmt"
	"strings"

	"harrierops-kube/internal/chains"
)

type commandHelpTopic struct {
	Name             string
	Section          string
	Status           string
	Summary          string
	OperatorValue    string
	SecurityValue    string
	WhyCare          string
	OutputHighlights []string
	Notes            []string
	Example          string
}

var commandHelpTopics = map[string]commandHelpTopic{
	"whoami": {
		Name:          "whoami",
		Section:       "identity",
		Status:        "implemented",
		Summary:       "First truth check for the current cluster, namespace, identity, and foothold shape.",
		OperatorValue: "Confirm where you landed before deeper workload, RBAC, or secret review.",
		SecurityValue: "Wrong cluster, wrong namespace, or wrong identity can invalidate every later conclusion.",
		WhyCare:       "This is the command that keeps a narrow or mistaken foothold from looking like a quiet environment.",
		OutputHighlights: []string{
			"cluster, API server, context, and namespace",
			"best known identity and identity confidence",
			"foothold family, auth material, and execution origin",
			"environment hint, identity evidence, and visibility blockers",
		},
		Example: "harrierops-kube whoami --output table",
	},
	"chains": {
		Name:          "chains",
		Section:       "orchestration",
		Status:        "implemented",
		Summary:       "Grouped family overview plus the first runnable defended path family from current scope.",
		OperatorValue: "Review which family answers the next operator question, then run that family against the current foothold instead of stitching five separate tables by hand.",
		SecurityValue: "This is where workload, service-account, permission, secret, and escalation evidence becomes one bounded path story instead of five separate triage views.",
		WhyCare:       "The operator should be able to move from visible foothold evidence to a defended next review without translating internal proof-state jargon.",
		OutputHighlights: []string{
			"grouped command name, command state, and current behavior",
			"family state, meaning, summary, and allowed claim",
			"family rows such as workload, subversion point, path type, and kubernetes control",
			"visibility, next review, and evidence-bounded note text",
			"path type guide separated from the internal proof ladder",
			"backing source commands and current family gap",
		},
		Notes:   chains.WorkloadIdentityPivotHelpNotes(),
		Example: "harrierops-kube chains workload-identity-pivot --output table",
	},
	"inventory": {
		Name:          "inventory",
		Section:       "core",
		Status:        "implemented",
		Summary:       "Fast cluster-shape summary that points to the next command worth opening.",
		OperatorValue: "Shorten time to the right next command instead of forcing a blind census pass.",
		SecurityValue: "Cluster breadth, exposure, risky workloads, and identity sprawl change the attack story early.",
		WhyCare:       "A broad, exposed, identity-heavy cluster should immediately feel different from a small namespace-scoped app view.",
		OutputHighlights: []string{
			"visibility and environment summary",
			"exposure footprint and risky workload footprint",
			"identity footprint and next-command routing",
			"supporting Kubernetes and Docker counts",
		},
		Example: "harrierops-kube inventory --output table",
	},
	"rbac": {
		Name:          "rbac",
		Section:       "identity",
		Status:        "implemented",
		Summary:       "Binding-and-grant evidence that shows who is bound to what and at what scope.",
		OperatorValue: "Ground later capability and identity-path claims in exact binding evidence.",
		SecurityValue: "Cluster-wide, impersonation-related, or unusual bindings often explain why an identity path matters.",
		WhyCare:       "This is where a suspicious summary row turns into inspectable grant truth.",
		OutputHighlights: []string{
			"priority, scope, subject, role, binding, and signal",
			"built-in role marker `*` for known role names",
			"attached why care block under each row",
			"credential-scope issues when bindings are visible but role detail is not",
		},
		Notes: []string{
			"`*` is a name-based built-in role marker, not a trust guarantee.",
			"`rbac` shows assignment evidence, not effective current-session capability or escalation proof.",
		},
		Example: "harrierops-kube rbac --output table",
	},
	"service-accounts": {
		Name:          "service-accounts",
		Section:       "identity",
		Status:        "implemented",
		Summary:       "Workload-to-service-account triage that shows which identity paths matter first.",
		OperatorValue: "See which workloads sit behind a service account before diving into raw RBAC detail.",
		SecurityValue: "A reused or exposed service account with stronger-than-expected power can shorten the path to control.",
		WhyCare:       "This command should make an app-account path look important for a concrete reason, not just because it exists.",
		OutputHighlights: []string{
			"service account, workload linkage, and token posture",
			"concrete power summary such as secret read or workload change",
			"exposed or risky workload context",
			"attached why care block under each row",
		},
		Example: "harrierops-kube service-accounts --output table",
	},
	"workloads": {
		Name:          "workloads",
		Section:       "workload",
		Status:        "implemented",
		Summary:       "Workload-first triage that joins exposure, identity, and risky execution context.",
		OperatorValue: "Lift the running thing that most changes the next move before opening deeper command surfaces.",
		SecurityValue: "Public-facing, identity-bearing, or privileged workloads often matter faster than quieter internal rows.",
		WhyCare:       "This command should make the most attack-shaping workload obvious on the first screen.",
		OutputHighlights: []string{
			"workload, identity summary, exposure path, and execution signals",
			"service-account power folded into workload context",
			"attached why care block under each row",
		},
		Example: "harrierops-kube workloads --output table",
	},
	"exposure": {
		Name:          "exposure",
		Section:       "exposure",
		Status:        "implemented",
		Summary:       "Outside-facing path triage for ingress, load balancer, node port, and related workload attribution.",
		OperatorValue: "Review the visible cluster edges first without pretending to solve full reachability proof.",
		SecurityValue: "An outside-facing path with a strong workload consequence can change urgency immediately.",
		WhyCare:       "A public-looking hostname, load balancer, or management-facing path should jump ahead of background posture.",
		OutputHighlights: []string{
			"exposure path, targets, attribution, and backend signal",
			"honest visibility language when attribution is heuristic or blocked",
			"attached why care block under each row",
		},
		Example: "harrierops-kube exposure --output table",
	},
	"permissions": {
		Name:          "permissions",
		Section:       "identity",
		Status:        "implemented",
		Summary:       "Current-foothold capability triage that answers what this session can do next.",
		OperatorValue: "Collapse raw RBAC into practical capability rows for the current session.",
		SecurityValue: "Secret read, workload change, exec, impersonation, bind, or escalate rights can justify immediate follow-up.",
		WhyCare:       "This is where a visible foothold stops looking theoretical and starts looking action-capable.",
		OutputHighlights: []string{
			"best known current identity plus `(current session)`",
			"subject confidence, action summary, scope, and next review",
			"boxed empty state when no visible grants match the current session",
			"attached why care block under each row",
		},
		Notes: []string{
			"An empty result means no visible grant matched the current session identity from current scope.",
		},
		Example: "harrierops-kube permissions --output table",
	},
	"secrets": {
		Name:          "secrets",
		Section:       "secrets",
		Status:        "implemented",
		Summary:       "Secret-bearing trust paths and secret dependencies worth follow-up without dumping values.",
		OperatorValue: "Distinguish direct-use, weakly hidden, stored, and external-secret stories quickly.",
		SecurityValue: "Secret paths often widen access well beyond the current session even when the value is not dumped.",
		WhyCare:       "A service-account token, registry credential, or external-secret dependency should read like a real trust path, not background metadata.",
		OutputHighlights: []string{
			"story, path, linkage, likely target family, and direct-use confidence",
			"safe labels only; normal output does not dump secret values",
			"attached why care block under each row",
		},
		Example: "harrierops-kube secrets --output table",
	},
	"privesc": {
		Name:          "privesc",
		Section:       "identity",
		Status:        "implemented",
		Summary:       "Fast escalation triage that shows what visible path could turn this foothold into more power.",
		OperatorValue: "Keep the starting foothold, usable action, and stronger outcome on one screen.",
		SecurityValue: "A short realistic path matters more than a generic privileged-looking posture row.",
		WhyCare:       "This command should surface the next escalation drill-down path, not a broad scary-objects list.",
		OutputHighlights: []string{
			"class, starting foothold, action, and stronger outcome",
			"posture-only rows stay visible without being oversold as ready paths",
			"attached why care block under each row",
		},
		Notes: []string{
			"`privesc` shows likely expansion paths; later chains should own the deeper defended proof story.",
		},
		Example: "harrierops-kube privesc --output table",
	},
	"images": {
		Name:          "images",
		Section:       "supply-chain",
		Status:        "later-depth",
		Summary:       "Workload-linked image triage for pull source, reference stability, and downstream workload importance.",
		OperatorValue: "See which image paths matter because of where they run and how stable the reference looks.",
		SecurityValue: "A central or weakly pinned image path can matter even before deeper registry review exists.",
		WhyCare:       "This stays later-depth until the core Kubernetes foothold and path surfaces are fully settled.",
		OutputHighlights: []string{
			"registry, repository, tag or digest, and workload linkage",
			"reuse breadth and stability cues when visible",
		},
		Example: "harrierops-kube images --output table",
	},
}

func rootHelpText() string {
	var builder strings.Builder
	builder.WriteString("harrierops-kube help\n\n")
	builder.WriteString("Use HarrierOps Kube to ground the current foothold, orient the cluster, and pull the next identity, workload, exposure, or secret path into view.\n\n")
	builder.WriteString("usage:\n")
	builder.WriteString("  harrierops-kube <command> [global options]\n")
	builder.WriteString("  harrierops-kube <command> help\n\n")
	builder.WriteString("global options:\n")
	builder.WriteString("  --context <name>    Kubernetes context name\n")
	builder.WriteString("  --namespace <ns>    Kubernetes namespace override\n")
	builder.WriteString("  --output <mode>     Output format: table, json, csv\n")
	builder.WriteString("  --outdir <dir>      Emit loot/json/table/csv artifacts for runnable commands\n")
	builder.WriteString("  --debug             Show verbose errors\n\n")
	builder.WriteString("implemented commands:\n")
	for _, spec := range commandSpecs {
		if spec.Status != "implemented" {
			continue
		}
		topic := commandHelpTopics[spec.Name]
		builder.WriteString(fmt.Sprintf("  %-16s [%s] %s\n", spec.Name, spec.Section, topic.Summary))
	}
	builder.WriteString("\n")
	builder.WriteString("later depth surfaces:\n")
	for _, spec := range commandSpecs {
		if spec.Status != "later-depth" {
			continue
		}
		topic := commandHelpTopics[spec.Name]
		builder.WriteString(fmt.Sprintf("  %-16s [%s] %s\n", spec.Name, spec.Section, topic.Summary))
	}
	builder.WriteString("\n")
	builder.WriteString("help notes:\n")
	builder.WriteString("  `chains` now has a family overview plus a runnable `workload-identity-pivot` family.\n")
	builder.WriteString("  `rbac` marks known built-in roles with `*`; that marker is name-based and heuristic.\n")
	builder.WriteString("  Partial or blocked reads should stay visible with issues instead of disappearing quietly.\n")
	builder.WriteString("  Run `harrierops-kube <command> help` for command meaning, why care, output highlights, and example usage.\n")
	return builder.String()
}

func commandHelpText(topic commandHelpTopic) string {
	var builder strings.Builder
	builder.WriteString("harrierops-kube ")
	builder.WriteString(topic.Name)
	builder.WriteString(" help")
	builder.WriteString("\n\n")
	builder.WriteString("section: ")
	builder.WriteString(topic.Section)
	builder.WriteString("\n")
	builder.WriteString("status: ")
	builder.WriteString(topic.Status)
	builder.WriteString("\n")
	builder.WriteString("meaning: ")
	builder.WriteString(topic.Summary)
	builder.WriteString("\n\n")
	builder.WriteString("operator value:\n")
	builder.WriteString("  ")
	builder.WriteString(topic.OperatorValue)
	builder.WriteString("\n\n")
	builder.WriteString("security value:\n")
	builder.WriteString("  ")
	builder.WriteString(topic.SecurityValue)
	builder.WriteString("\n\n")
	builder.WriteString("why care:\n")
	builder.WriteString("  ")
	builder.WriteString(topic.WhyCare)
	builder.WriteString("\n\n")
	builder.WriteString("output highlights:\n")
	for _, highlight := range topic.OutputHighlights {
		builder.WriteString("  - ")
		builder.WriteString(highlight)
		builder.WriteString("\n")
	}
	if len(topic.Notes) > 0 {
		builder.WriteString("\nnotes:\n")
		for _, note := range topic.Notes {
			builder.WriteString("  - ")
			builder.WriteString(note)
			builder.WriteString("\n")
		}
	}
	builder.WriteString("\nexample command:\n")
	builder.WriteString("  ")
	builder.WriteString(topic.Example)
	builder.WriteString("\n")
	return builder.String()
}

func helpTopic(name string) (commandHelpTopic, bool) {
	topic, ok := commandHelpTopics[name]
	return topic, ok
}
