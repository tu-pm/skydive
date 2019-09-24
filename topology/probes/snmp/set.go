package snmp

// Set stores non repetitive items
type Set map[string]struct{}

var presented struct{}

// Push pushes new items to Set, return newly inserted ones
func (set *Set) Push(items []string) []string {
	newItems := []string{}
	for _, item := range items {
		_, ok := (*set)[item]
		if !ok {
			newItems = append(newItems, item)
			(*set)[item] = presented
		}
	}
	return newItems
}
