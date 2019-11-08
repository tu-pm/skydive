package types

type Domain struct {
	CommonAttribute
	ServiceTemplateRefs []Reference `json:"service_templates"`
	ProjectRefs         []Reference `json:"projects"`
}

func (d Domain) ListProjectIDs() (uuids []string) {
	for _, ref := range d.ProjectRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (d Domain) ListServiceTemplateIDs() (uuids []string) {
	for _, ref := range d.ServiceTemplateRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}
