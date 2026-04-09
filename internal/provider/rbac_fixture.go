package provider

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"harrierops-kube/internal/model"
)

type rawRBACFixture struct {
	RoleGrants          []model.RBACGrant `json:"role_grants"`
	RoleBindings        []rawRoleBinding  `json:"role_bindings"`
	ClusterRoleBindings []rawRoleBinding  `json:"cluster_role_bindings"`
	Roles               []rawRole         `json:"roles"`
	ClusterRoles        []rawRole         `json:"cluster_roles"`
	Issues              []model.Issue     `json:"issues"`
}

type rawRoleBinding struct {
	Name      string       `json:"name"`
	Namespace string       `json:"namespace,omitempty"`
	RoleRef   rawRoleRef   `json:"role_ref"`
	Subjects  []rawSubject `json:"subjects"`
}

type rawRoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type rawSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type rawRole struct {
	Name         string          `json:"name"`
	Namespace    string          `json:"namespace,omitempty"`
	RulesVisible *bool           `json:"rules_visible,omitempty"`
	Rules        []rawPolicyRule `json:"rules"`
}

type rawPolicyRule struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources"`
	APIGroups []string `json:"api_groups,omitempty"`
}

func normalizeRBACFixture(raw rawRBACFixture) model.RBACData {
	if len(raw.RoleBindings) == 0 && len(raw.ClusterRoleBindings) == 0 {
		return model.RBACData{
			RoleGrants: raw.RoleGrants,
			Issues:     raw.Issues,
		}
	}

	roleIndex := map[string]rawRole{}
	for _, role := range raw.Roles {
		roleIndex[roleIndexKey("Role", role.Namespace, role.Name)] = role
	}
	for _, role := range raw.ClusterRoles {
		roleIndex[roleIndexKey("ClusterRole", "", role.Name)] = role
	}

	grants := []model.RBACGrant{}
	issues := append([]model.Issue{}, raw.Issues...)

	for _, binding := range raw.ClusterRoleBindings {
		rows, rowIssues := normalizeRBACBinding(binding, "ClusterRoleBinding", roleIndex)
		grants = append(grants, rows...)
		issues = append(issues, rowIssues...)
	}
	for _, binding := range raw.RoleBindings {
		rows, rowIssues := normalizeRBACBinding(binding, "RoleBinding", roleIndex)
		grants = append(grants, rows...)
		issues = append(issues, rowIssues...)
	}

	sort.SliceStable(grants, func(i, j int) bool {
		left := grants[i]
		right := grants[j]
		if left.Scope != right.Scope {
			return left.Scope == "cluster-wide"
		}
		leftDanger := len(left.DangerousRights)
		rightDanger := len(right.DangerousRights)
		if leftDanger != rightDanger {
			return leftDanger > rightDanger
		}
		if left.WorkloadCount != right.WorkloadCount {
			return left.WorkloadCount > right.WorkloadCount
		}
		if left.BindingName != right.BindingName {
			return left.BindingName < right.BindingName
		}
		return left.SubjectDisplay < right.SubjectDisplay
	})

	return model.RBACData{
		RoleGrants: grants,
		Issues:     issues,
	}
}

func normalizeRBACBinding(binding rawRoleBinding, bindingKind string, roleIndex map[string]rawRole) ([]model.RBACGrant, []model.Issue) {
	roleKey := roleIndexKey(binding.RoleRef.Kind, binding.Namespace, binding.RoleRef.Name)
	role, roleFound := roleIndex[roleKey]
	roleRulesVisible := roleFound && (role.RulesVisible == nil || *role.RulesVisible)

	dangerousRights := []string{}
	if roleRulesVisible {
		dangerousRights = summarizeDangerousRights(role.Rules)
	}

	rows := make([]model.RBACGrant, 0, len(binding.Subjects))
	issues := []model.Issue{}
	if !roleRulesVisible {
		scope := binding.Namespace
		if bindingKind == "ClusterRoleBinding" {
			scope = "_cluster"
		}
		issues = append(issues, model.Issue{
			Kind:    "collection",
			Scope:   fmt.Sprintf("rbac.%s.%s", scope, binding.Name),
			Message: fmt.Sprintf("Binding %q is visible, but the referenced %s %q could not be fully read.", binding.Name, binding.RoleRef.Kind, binding.RoleRef.Name),
		})
	}

	for _, subject := range binding.Subjects {
		subjectNamespace := optionalString(subject.Namespace)
		namespace := optionalString(binding.Namespace)
		if bindingKind == "ClusterRoleBinding" {
			namespace = nil
		}

		rows = append(rows, model.RBACGrant{
			ID:               rbacGrantID(bindingKind, binding.Namespace, binding.Name, subject),
			BindingKind:      bindingKind,
			BindingName:      binding.Name,
			Namespace:        namespace,
			Scope:            grantScope(bindingKind, binding.Namespace),
			RoleKind:         binding.RoleRef.Kind,
			RoleName:         binding.RoleRef.Name,
			RoleDisplayName:  roleDisplayName(binding.RoleRef.Name),
			BuiltIn:          isBuiltInRoleName(binding.RoleRef.Name),
			SubjectKind:      subject.Kind,
			SubjectName:      subject.Name,
			SubjectNamespace: subjectNamespace,
			SubjectDisplay:   grantSubjectDisplay(subject),
			DangerousRights:  dangerousRights,
			RelatedWorkloads: []string{},
			WorkloadCount:    0,
			EvidenceStatus:   grantEvidenceStatus(roleRulesVisible),
			Priority:         "low",
			WhyCare:          baseGrantWhyCare(bindingKind, binding.Namespace, binding.RoleRef.Name, dangerousRights, roleRulesVisible),
		})
	}

	return rows, issues
}

func summarizeDangerousRights(rules []rawPolicyRule) []string {
	signals := []string{}
	add := func(signal string) {
		if signal == "" || slices.Contains(signals, signal) {
			return
		}
		signals = append(signals, signal)
	}

	for _, rule := range rules {
		if hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) {
			add("admin-like wildcard access")
			continue
		}
		if hasVerb(rule.Verbs, "impersonate") {
			for _, resource := range rule.Resources {
				switch resource {
				case "serviceaccounts":
					add("impersonate serviceaccounts")
				case "users":
					add("impersonate users")
				case "groups":
					add("impersonate groups")
				default:
					add("impersonate identities")
				}
			}
		}
		if touchesResource(rule.Verbs, rule.Resources, []string{"bind"}, []string{"roles", "clusterroles"}) {
			add("bind roles")
		}
		if touchesResource(rule.Verbs, rule.Resources, []string{"escalate"}, []string{"roles", "clusterroles"}) {
			add("escalate roles")
		}
		if touchesResource(rule.Verbs, rule.Resources, []string{"get", "list", "watch"}, []string{"secrets"}) {
			add("read secrets")
		}
		if touchesResource(rule.Verbs, rule.Resources, []string{"create", "update", "patch", "delete", "*"}, []string{"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) {
			add("change workloads")
		}
		if touchesResource(rule.Verbs, rule.Resources, []string{"create", "*"}, []string{"pods/exec"}) {
			add("exec into pods")
		}
		if touchesResource(
			rule.Verbs,
			rule.Resources,
			[]string{"create", "update", "patch", "delete", "*"},
			[]string{
				"mutatingwebhookconfigurations",
				"validatingwebhookconfigurations",
				"validatingadmissionpolicies",
				"validatingadmissionpolicybindings",
				"podsecuritypolicies",
			},
		) {
			add("change admission or policy")
		}
		if touchesResource(
			rule.Verbs,
			rule.Resources,
			[]string{"get", "list", "watch", "create", "update", "patch", "delete", "*"},
			[]string{"nodes", "nodes/proxy", "nodes/status", "nodes/metrics"},
		) {
			add("touch nodes")
		}
	}

	sort.SliceStable(signals, func(i, j int) bool {
		return dangerousRightScore(signals[i]) > dangerousRightScore(signals[j])
	})
	return signals
}

func dangerousRightScore(signal string) int {
	switch signal {
	case "admin-like wildcard access":
		return 60
	case "impersonate serviceaccounts", "impersonate users", "impersonate groups", "impersonate identities":
		return 50
	case "bind roles", "escalate roles":
		return 45
	case "touch nodes":
		return 40
	case "change workloads", "exec into pods":
		return 35
	case "change admission or policy":
		return 30
	case "read secrets":
		return 25
	default:
		return 10
	}
}

func touchesResource(verbs []string, resources []string, wantedVerbs []string, wantedResources []string) bool {
	if !(hasWildcard(verbs) || containsAny(verbs, wantedVerbs)) {
		return false
	}
	if hasWildcard(resources) {
		return true
	}
	return containsAny(resources, wantedResources)
}

func containsAny(values []string, wanted []string) bool {
	for _, value := range values {
		for _, candidate := range wanted {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func hasVerb(verbs []string, wanted string) bool {
	for _, verb := range verbs {
		if verb == wanted || verb == "*" {
			return true
		}
	}
	return false
}

func hasWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func grantScope(bindingKind string, namespace string) string {
	if bindingKind == "ClusterRoleBinding" || namespace == "" {
		return "cluster-wide"
	}
	return "namespace/" + namespace
}

func grantSubjectDisplay(subject rawSubject) string {
	switch subject.Kind {
	case "ServiceAccount":
		if subject.Namespace != "" {
			return fmt.Sprintf("ServiceAccount %s/%s", subject.Namespace, subject.Name)
		}
		return "ServiceAccount " + subject.Name
	case "User":
		return "User " + subject.Name
	case "Group":
		return "Group " + subject.Name
	default:
		return subject.Kind + " " + subject.Name
	}
}

func roleDisplayName(roleName string) string {
	if isBuiltInRoleName(roleName) {
		return roleName + "*"
	}
	return roleName
}

func isBuiltInRoleName(roleName string) bool {
	switch {
	case roleName == "cluster-admin", roleName == "admin", roleName == "edit", roleName == "view":
		return true
	case strings.HasPrefix(roleName, "system:"):
		return true
	default:
		return false
	}
}

func grantEvidenceStatus(roleRulesVisible bool) string {
	if roleRulesVisible {
		return "direct"
	}
	return "visibility blocked"
}

func baseGrantWhyCare(bindingKind string, namespace string, roleName string, dangerousRights []string, roleRulesVisible bool) string {
	scope := "namespace-scoped"
	if bindingKind == "ClusterRoleBinding" || namespace == "" {
		scope = "cluster-wide"
	}

	if !roleRulesVisible {
		return fmt.Sprintf("%s binding is visible, but the referenced role rules are not visible from current credentials, so keep the grant in view without overstating what it allows.", scope)
	}
	if len(dangerousRights) > 0 {
		return fmt.Sprintf("%s grant carries %s, so the binding deserves a closer look.", scope, dangerousRights[0])
	}
	if isBuiltInRoleName(roleName) {
		return fmt.Sprintf("%s binding points at a known Kubernetes role name, so it is worth grounding even if the rights look quieter.", scope)
	}
	return fmt.Sprintf("%s grant looks narrower, but it still grounds who is bound to what access.", scope)
}

func roleIndexKey(kind string, namespace string, name string) string {
	if kind == "ClusterRole" {
		return kind + ":_cluster:" + name
	}
	return kind + ":" + namespace + ":" + name
}

func rbacGrantID(bindingKind string, namespace string, bindingName string, subject rawSubject) string {
	scope := namespace
	if bindingKind == "ClusterRoleBinding" {
		scope = "_cluster"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s", bindingKind, scope, bindingName, subject.Kind, subject.Name)
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
