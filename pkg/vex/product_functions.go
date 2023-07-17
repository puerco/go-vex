package vex

import (
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
)

func (p *Product) Matches(identifier, subIdentifier string) bool {
	if !p.Component.Matches(identifier) {
		return false
	}

	if subIdentifier == "" {
		return true
	}

	for _, s := range p.Subcomponents {
		if s.Component.Matches(subIdentifier) {
			return true
		}
	}

	return false
}

func (c *Component) Matches(identifier string) bool {
	if c.ID == identifier {
		return true
	}

	for t, id := range c.Identifiers {
		if id == identifier {
			return true
		}

		if t == PURL && strings.HasPrefix(identifier, "pkg:") {
			if PurlMatches(id, identifier) {
				return true
			}
		}
	}

	for _, hashVal := range c.Hashes {
		if hashVal == Hash(identifier) {
			return true
		}
	}

	return false
}

func (v *Vulnerability) Matches(identifier string) bool {
	if string(v.Name) == identifier {
		return true
	}
	for _, id := range v.Aliases {
		if id == VulnerabilityID(identifier) {
			return true
		}
	}
	return false
}

// Matches returns true if the statement matches the passed vulnerability,
// the VEX productg and any of the identifiers on the received list.
func (s *Statement) Matches(vuln, product string, subcomponents []string) bool {
	if !s.Vulnerability.Matches(vuln) {
		return false
	}

	for i := range s.Products {
		if len(subcomponents) == 0 {
			if s.Products[i].Matches(product, "") {
				return true
			}
		}

		for _, sc := range subcomponents {
			if s.Products[i].Matches(product, sc) {
				return true
			}
		}
	}
	return false
}

// PurlMatches returns true if purl1 matches the more specific purl2. It takes into
// account all segments of the pURL, including qualifiers. purl1 is considered to
// be more general and purl2 more specific and thus, the following considerations
// are made when matching:
//
//   - If purl1 does not have a version, it will match any version in purl2
//   - If purl1 has qualifers, purl2 must have the same set of qualifiers to match.
//   - Inversely, purl2 can have any number of qualifiers not found on purl1 and
//     still match.
//   - If any of the purls is invalid, the function returns false.
//
// Purl version ranges are not supported yet but they will be in a future version
// of this matching function.
func PurlMatches(purl1, purl2 string) bool {
	p1, err := packageurl.FromString(purl1)
	if err != nil {
		return false
	}
	p2, err := packageurl.FromString(purl2)
	if err != nil {
		return false
	}

	if p1.Type != p2.Type {
		return false
	}

	if p1.Namespace != p2.Namespace {
		return false
	}

	if p1.Name != p2.Name {
		return false
	}

	if p1.Version != "" && p2.Version == "" {
		return false
	}

	if p1.Version != p2.Version && p1.Version != "" && p2.Version != "" {
		return false
	}

	p1q := p1.Qualifiers.Map()
	p2q := p2.Qualifiers.Map()

	// All qualifiers in p1 must be in p2 to match
	for k, v1 := range p1q {
		if v2, ok := p2q[k]; !ok || v1 != v2 {
			return false
		}
	}
	return true
}

// LatestStatement returns the latest VEX statement for a given product and
// vulnerability, that is the statement that contains the latest data about
// impact to a given product.
func (vexDoc *VEX) LatestStatement(vulnID, product string, subcomponents []string) (s *Statement) {
	statements := vexDoc.Statements
	var t time.Time
	if vexDoc.Timestamp != nil {
		t = *vexDoc.Timestamp
	}

	SortStatements(statements, t)

	for i := len(statements) - 1; i >= 0; i-- {
		if statements[i].Matches(vulnID, product, subcomponents) {
			return &statements[i]
		}
	}
	return nil
}
