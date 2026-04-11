package app

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"harrierops-kube/internal/chains"
)

type commandHelpTopic struct {
	Name              string
	Section           string
	Status            string
	Summary           string
	OffensiveQuestion string
	OperatorValue     string
	SecurityValue     string
	WhyCare           string
	OutputHighlights  []string
	Notes             []string
	Example           string
}

var sectionHelpSummaries = map[string]string{
	"core":          "Fast orientation surfaces that choose the next command.",
	"exposure":      "Outside-facing paths and workload attribution surfaces.",
	"identity":      "Identity, grant, and capability surfaces for the current foothold.",
	"orchestration": "Grouped path surfaces that join multiple commands into bounded stories.",
	"secrets":       "Secret-bearing paths and dependency surfaces worth follow-up.",
	"supply-chain":  "Later-depth image and supply-chain review surfaces.",
	"workload":      "Running workload surfaces that change exposure, identity, and execution risk.",
}

var commandHelpTopics = map[string]commandHelpTopic{
	"whoami": {
		Name:              "whoami",
		Section:           "identity",
		Status:            "implemented",
		Summary:           "First truth check for the current cluster, namespace, identity, and foothold shape.",
		OffensiveQuestion: "Where am I actually standing before I trust any deeper row?",
		OperatorValue:     "Confirm where you landed before deeper workload, RBAC, or secret review.",
		SecurityValue:     "Wrong cluster, wrong namespace, or wrong identity can invalidate every later conclusion.",
		WhyCare:           "This is the command that keeps a narrow or mistaken foothold from looking like a quiet environment.",
		OutputHighlights: []string{
			"cluster, API server, context, and namespace",
			"best known identity and identity confidence",
			"foothold family, auth material, and execution origin",
			"environment hint, identity evidence, and visibility blockers",
		},
		Example: "harrierops-kube whoami --output table",
	},
	"chains": {
		Name:              "chains",
		Section:           "orchestration",
		Status:            "implemented",
		Summary:           chains.GroupedOverviewSummary(),
		OffensiveQuestion: chains.GroupedOverviewOffensiveQuestion(),
		OperatorValue:     chains.GroupedOverviewOperatorValue(),
		SecurityValue:     "This is where workload, service-account, permission, secret, and escalation evidence becomes one bounded path story instead of five separate triage views.",
		WhyCare:           chains.GroupedOverviewWhyCare(),
		OutputHighlights:  chains.GroupedOverviewOutputHighlights(),
		Notes:   chains.WorkloadIdentityPivotHelpNotes(),
		Example: "harrierops-kube chains workload-identity-pivot --output table",
	},
	"inventory": {
		Name:              "inventory",
		Section:           "core",
		Status:            "implemented",
		Summary:           "Fast cluster-shape summary that points to the next command worth opening.",
		OffensiveQuestion: "What kind of cluster view is this, and which command should I open next?",
		OperatorValue:     "Shorten time to the right next command instead of forcing a blind census pass.",
		SecurityValue:     "Cluster breadth, exposure, risky workloads, and identity sprawl change the attack story early.",
		WhyCare:           "A broad, exposed, identity-heavy cluster should immediately feel different from a small namespace-scoped app view.",
		OutputHighlights: []string{
			"visibility and environment summary",
			"exposure footprint and risky workload footprint",
			"identity footprint and next-command routing",
			"supporting Kubernetes and Docker counts",
		},
		Example: "harrierops-kube inventory --output table",
	},
	"rbac": {
		Name:              "rbac",
		Section:           "identity",
		Status:            "implemented",
		Summary:           "Binding-and-grant evidence that shows who is bound to what and at what scope.",
		OffensiveQuestion: "Who got what access here, and at what scope?",
		OperatorValue:     "Ground later capability and identity-path claims in exact binding evidence.",
		SecurityValue:     "Cluster-wide, impersonation-related, or unusual bindings often explain why an identity path matters.",
		WhyCare:           "This is where a suspicious summary row turns into inspectable grant truth.",
		OutputHighlights: []string{
			"priority, scope, subject, role, binding, and signal",
			"built-in role marker `*` for known role names",
			"attached why care block under each row",
			"issues section when bindings are visible but role detail is not",
		},
		Notes: []string{
			"`*` is a name-based built-in role marker, not a trust guarantee.",
			"`rbac` shows assignment evidence, not effective current-session capability or escalation proof.",
		},
		Example: "harrierops-kube rbac --output table",
	},
	"service-accounts": {
		Name:              "service-accounts",
		Section:           "identity",
		Status:            "implemented",
		Summary:           "Workload-to-service-account triage that shows which identity paths matter first.",
		OffensiveQuestion: "Which workload-to-service-account paths matter first from this foothold?",
		OperatorValue:     "See which workloads sit behind a service account before diving into raw RBAC detail.",
		SecurityValue:     "A reused or exposed service account with stronger-than-expected power can shorten the path to control.",
		WhyCare:           "This command should make an app-account path look important for a concrete reason, not just because it exists.",
		OutputHighlights: []string{
			"service account, workload linkage, and token posture",
			"concrete power summary such as secret read or workload change",
			"exposed or risky workload context",
			"attached why care block under each row",
		},
		Example: "harrierops-kube service-accounts --output table",
	},
	"workloads": {
		Name:              "workloads",
		Section:           "workload",
		Status:            "implemented",
		Summary:           "Workload-first triage that joins exposure, identity, and risky execution context.",
		OffensiveQuestion: "Which running workload most changes the next move right now?",
		OperatorValue:     "Lift the running thing that most changes the next move before opening deeper command surfaces.",
		SecurityValue:     "Public-facing, identity-bearing, or privileged workloads often matter faster than quieter internal rows.",
		WhyCare:           "This command should make the most attack-shaping workload obvious on the first screen.",
		OutputHighlights: []string{
			"workload, identity summary, exposure path, and execution signals",
			"service-account power folded into workload context",
			"attached why care block under each row",
		},
		Example: "harrierops-kube workloads --output table",
	},
	"exposure": {
		Name:              "exposure",
		Section:           "exposure",
		Status:            "implemented",
		Summary:           "Outside-facing path triage for ingress, load balancer, node port, and related workload attribution.",
		OffensiveQuestion: "What outside-facing path deserves review first, and what does it appear to touch?",
		OperatorValue:     "Review the visible cluster edges first without pretending to solve full reachability proof.",
		SecurityValue:     "An outside-facing path with a strong workload consequence can change urgency immediately.",
		WhyCare:           "A public-looking hostname, load balancer, or management-facing path should jump ahead of background posture.",
		OutputHighlights: []string{
			"exposure path, targets, attribution, and backend signal",
			"honest visibility language when attribution is heuristic or blocked",
			"attached why care block under each row",
		},
		Example: "harrierops-kube exposure --output table",
	},
	"permissions": {
		Name:              "permissions",
		Section:           "identity",
		Status:            "implemented",
		Summary:           "Current-foothold capability triage that answers what this session can do next.",
		OffensiveQuestion: "What can this current foothold do next from visible scope?",
		OperatorValue:     "Collapse raw RBAC into practical capability rows for the current session.",
		SecurityValue:     "Secret read, workload change, exec, impersonation, bind, or escalate rights can justify immediate follow-up.",
		WhyCare:           "This is where a visible foothold stops looking theoretical and starts looking action-capable.",
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
		Name:              "secrets",
		Section:           "secrets",
		Status:            "implemented",
		Summary:           "Secret-bearing trust paths and secret dependencies worth follow-up without dumping values.",
		OffensiveQuestion: "Which visible secret-bearing path is worth following next without exposing the value?",
		OperatorValue:     "Distinguish direct-use, weakly hidden, stored, and external-secret stories quickly.",
		SecurityValue:     "Secret paths often widen access well beyond the current session even when the value is not dumped.",
		WhyCare:           "A service-account token, registry credential, or external-secret dependency should read like a real trust path, not background metadata.",
		OutputHighlights: []string{
			"story, path, linkage, likely target family, and direct-use confidence",
			"safe labels only; normal output does not dump secret values",
			"attached why care block under each row",
		},
		Example: "harrierops-kube secrets --output table",
	},
	"privesc": {
		Name:              "privesc",
		Section:           "identity",
		Status:            "implemented",
		Summary:           "Fast escalation triage that shows what visible path could turn this foothold into more power.",
		OffensiveQuestion: "What visible path could turn this foothold into more power?",
		OperatorValue:     "Keep the starting foothold, usable action, and stronger outcome on one screen.",
		SecurityValue:     "A short realistic path matters more than a generic privileged-looking posture row.",
		WhyCare:           "This command should surface the next escalation drill-down path, not a broad scary-objects list.",
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
		Name:              "images",
		Section:           "supply-chain",
		Status:            "later-depth",
		Summary:           "Workload-linked image triage for pull source, reference stability, and downstream workload importance.",
		OffensiveQuestion: "Which image path matters because of where it runs and how stable the reference looks?",
		OperatorValue:     "See which image paths matter because of where they run and how stable the reference looks.",
		SecurityValue:     "A central or weakly pinned image path can matter even before deeper registry review exists.",
		WhyCare:           "This stays later-depth until the core Kubernetes foothold and path surfaces are fully settled.",
		OutputHighlights: []string{
			"registry, repository, tag or digest, and workload linkage",
			"reuse breadth and stability cues when visible",
		},
		Example: "harrierops-kube images --output table",
	},
}

const (
	helpPanelMaxWidth = 132
	helpPanelMinWidth = 56
)

func rootHelpText() string {
	usageLines := []string{
		"harrierops-kube",
		"harrierops-kube help",
		"harrierops-kube help <command>",
		"harrierops-kube <command> help",
		"harrierops-kube <command> [global options]",
	}

	sectionLines := make([]string, 0, len(implementedSectionNames()))
	for _, section := range implementedSectionNames() {
		sectionLines = append(sectionLines, fmt.Sprintf("%s: %s", section, sectionHelpSummaries[section]))
	}

	commandLines := []string{}
	for _, spec := range commandSpecs {
		if spec.Status != "implemented" {
			continue
		}
		topic := commandHelpTopics[spec.Name]
		commandLines = append(commandLines, fmt.Sprintf("%s: %s", spec.Name, topic.Summary))
	}

	laterDepthLines := []string{}
	for _, spec := range commandSpecs {
		if spec.Status != "later-depth" {
			continue
		}
		topic := commandHelpTopics[spec.Name]
		laterDepthLines = append(laterDepthLines, fmt.Sprintf("%s: %s", spec.Name, topic.Summary))
	}

	notesLines := []string{
		"Shared flags such as --context, --namespace, --output, --outdir, and --debug work after the command.",
		"`chains` now has a family overview plus a runnable `workload-identity-pivot` family.",
		"`rbac` marks known built-in roles with `*`; that marker is name-based and heuristic.",
		"Partial or blocked reads should stay visible with issues instead of disappearing quietly.",
		"Honest bounded weaker claims should stay in default output when they still change the next operator decision.",
		"Use `harrierops-kube help <command>` or `harrierops-kube <command> help` for command detail.",
	}

	sections := []string{
		renderHelpPanel(
			"HarrierOps Kube Help",
			[]string{"Attack-path-focused Kubernetes recon with flat commands and scoped help."},
		),
		renderHelpPanel("Usage:", usageLines),
		renderHelpPanel("Sections:", sectionLines),
		renderHelpPanel("Commands:", commandLines),
		renderHelpPanel("Later depth surfaces:", laterDepthLines),
		renderHelpPanel("Notes:", bulletLines(notesLines)),
	}
	return strings.Join(sections, "\n\n")
}

func commandHelpText(topic commandHelpTopic) string {
	frameLines := []string{}
	if topic.Status == "implemented" {
		frameLines = append(frameLines, "Status: implemented command.")
	} else {
		frameLines = append(frameLines, "Status: later-depth surface.")
	}
	frameLines = append(frameLines,
		"Section: "+topic.Section,
		"Offensive question: "+topic.OffensiveQuestion,
		"Kube frame: "+topic.OperatorValue,
	)
	notes := make([]string, 0, len(topic.Notes)+3)
	if topic.SecurityValue != "" {
		notes = append(notes, "Security value: "+topic.SecurityValue)
	}
	if topic.WhyCare != "" {
		notes = append(notes, "Why care: "+topic.WhyCare)
	}
	notes = append(notes, topic.Notes...)
	notes = append(notes, "Current-scope visibility limits are investigative context, not proof the cluster is quiet.")

	sections := []string{
		renderHelpPanel("HarrierOps Kube Help :: "+topic.Name, []string{topic.Summary}),
		renderHelpPanel("Command frame:", frameLines),
		renderHelpPanel("Output highlights:", bulletLines(topic.OutputHighlights)),
	}
	if len(notes) > 0 {
		sections = append(sections, renderHelpPanel("Notes:", bulletLines(notes)))
	}
	sections = append(sections, renderHelpPanel("Example:", []string{topic.Example}))
	return strings.Join(sections, "\n\n")
}

func helpTopic(name string) (commandHelpTopic, bool) {
	topic, ok := commandHelpTopics[name]
	return topic, ok
}

func renderHelpPanel(title string, lines []string) string {
	content := []string{title}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		content = append(content, trimmed)
	}
	return helpPanelStyle(currentHelpPanelWidth()).Render(strings.Join(content, "\n"))
}

func bulletLines(lines []string) []string {
	bullets := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		bullets = append(bullets, "- "+trimmed)
	}
	return bullets
}

func helpPanelStyle(width int) lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.ASCIIBorder()).
		Padding(0, 1).
		Width(width)
}

func currentHelpPanelWidth() int {
	columns, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS")))
	if err != nil || columns <= 0 {
		return helpPanelMaxWidth
	}

	width := columns - 2
	if width <= 0 {
		return helpPanelMinWidth
	}
	if width < helpPanelMinWidth {
		return width
	}
	if width > helpPanelMaxWidth {
		return helpPanelMaxWidth
	}
	return width
}
