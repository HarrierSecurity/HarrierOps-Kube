package model

type workloadRiskText struct {
	signal      string
	whyCare     string
	attackAngle string
	matches     func(Workload) bool
}

var workloadRiskTexts = []workloadRiskText{
	{
		signal:      "workload can reach the container runtime socket on the host",
		whyCare:     "can reach the container runtime socket on the host",
		attackAngle: "this workload may be able to control other containers on the same machine.",
		matches: func(workload Workload) bool {
			return workload.DockerSocketMount
		},
	},
	{
		signal:      "workload mounts host directories",
		whyCare:     "mounts host directories",
		attackAngle: "this workload can touch files from the underlying machine.",
		matches: func(workload Workload) bool {
			return len(workload.HostPathMounts) > 0
		},
	},
	{
		signal:      "workload shares host network, process, or IPC access",
		whyCare:     "shares host network, process, or IPC access",
		attackAngle: "this workload can see more of the underlying machine than a normal workload.",
		matches: func(workload Workload) bool {
			return workload.HostNetwork || workload.HostPID || workload.HostIPC
		},
	},
	{
		signal:      "privileged container",
		whyCare:     "runs a privileged container",
		attackAngle: "this workload is running with unusually high container privileges.",
		matches: func(workload Workload) bool {
			return workload.Privileged
		},
	},
	{
		signal:      "workload allows privilege escalation",
		whyCare:     "allows privilege escalation",
		attackAngle: "this workload can raise process privileges more easily than a normal workload.",
		matches: func(workload Workload) bool {
			return workload.AllowPrivilegeEscalation
		},
	},
	{
		signal:      "workload runs as root",
		whyCare:     "runs as root",
		attackAngle: "this workload is already running as root inside the container.",
		matches: func(workload Workload) bool {
			return workload.RunsAsRoot
		},
	},
	{
		signal:      "workload adds Linux capabilities",
		whyCare:     "adds Linux capabilities",
		attackAngle: "this workload has extra low-level privileges beyond a normal container.",
		matches: func(workload Workload) bool {
			return len(workload.AddedCapabilities) > 0
		},
	},
}

func WorkloadRiskSignals(workload Workload) []string {
	signals := []string{}
	for _, risk := range workloadRiskTexts {
		if risk.matches != nil && risk.matches(workload) {
			signals = append(signals, risk.signal)
		}
	}
	return signals
}

func IsRiskyWorkload(workload Workload) bool {
	return len(WorkloadRiskSignals(workload)) > 0
}

func WorkloadWhyCareRiskPhrase(signal string) string {
	for _, risk := range workloadRiskTexts {
		if risk.signal == signal {
			return risk.whyCare
		}
	}
	return signal
}

func WorkloadRiskAttackAngle(signals []string) string {
	visibleSignals := map[string]bool{}
	for _, signal := range signals {
		visibleSignals[signal] = true
	}
	for _, risk := range workloadRiskTexts {
		if visibleSignals[risk.signal] {
			return risk.attackAngle
		}
	}
	return ""
}
