package util

var inSet = struct{}{}

type StringSet map[string]struct{}

func NewStringSet() StringSet {
	return make(map[string]struct{})
}

func (s StringSet) Add(item string) {
	if _, ok := s[item]; ok {
		return
	}

	s[item] = inSet
}

func (s StringSet) Items() []string {
	members := []string{}

	for k, _ := range s {
		members = append(members, k)
	}

	return members
}
