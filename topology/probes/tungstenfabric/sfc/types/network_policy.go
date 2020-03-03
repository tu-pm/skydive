package types

type NetworkPolicy struct {
	CommonAttribute
	PolicyRules        `json:"network_policy_entries"`
	VirtualNetworkRefs []Reference `json:"virtual_network_back_refs"`
	ProjectRef         string      `json:"parent_uuid"`
}

type PolicyRules struct {
	Rules []NetworkPolicyRule `json:"policy_rule"`
}

func (np NetworkPolicy) ListVirtualNetworkIDs() (uuids []string) {
	for _, ref := range np.VirtualNetworkRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

// NOTE: Filter out all rules without an UUID
func (np NetworkPolicy) ListRules() (rules []NetworkPolicyRule) {
	for _, rule := range np.Rules {
		if uuid := rule.UUID; len(uuid) > 0 {
			rules = append(rules, rule)
		}
	}
	return
}

func (np NetworkPolicy) ListProjectIDs() (uuids []string) {
	return []string{np.ProjectRef}
}
