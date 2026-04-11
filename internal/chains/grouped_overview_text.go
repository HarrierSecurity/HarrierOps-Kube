package chains

const groupedOverviewCurrentBehavior = "Family overview and grouped runner. Use `harrierops-kube chains` to see which grouped path is worth reviewing next, then `harrierops-kube chains <family>` to run one family from current scope."

const groupedOverviewSummary = "Grouped family overview plus the first runnable path family from current scope."

const groupedOverviewOffensiveQuestion = "Which grouped attack path is already visible from where I stand?"

const groupedOverviewOperatorValue = "See which family is worth opening next, then run that family instead of stitching several command outputs together by hand."

const groupedOverviewWhyCare = "The operator should be able to see why a grouped path matters next without needing deep Kubernetes expertise first."

var groupedOverviewOutputHighlights = []string{
	"grouped command name, command state, and current behavior",
	"family summary, offensive value, and what it can show now",
	"family rows such as workload, action point, path type, and stronger control clue",
	"visibility, missing step, and evidence-bounded note text",
	"backing source commands, row types you may see, and current family coverage limits",
}

func GroupedOverviewCurrentBehavior() string {
	return groupedOverviewCurrentBehavior
}

func GroupedOverviewSummary() string {
	return groupedOverviewSummary
}

func GroupedOverviewOffensiveQuestion() string {
	return groupedOverviewOffensiveQuestion
}

func GroupedOverviewOperatorValue() string {
	return groupedOverviewOperatorValue
}

func GroupedOverviewWhyCare() string {
	return groupedOverviewWhyCare
}

func GroupedOverviewOutputHighlights() []string {
	return append([]string(nil), groupedOverviewOutputHighlights...)
}
