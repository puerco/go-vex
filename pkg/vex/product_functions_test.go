package vex

import (
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestPurlMatches(t *testing.T) {
	for caseName, tc := range map[string]struct {
		p1        string
		p2        string
		mustMatch bool
	}{
		"same purl":         {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", true},
		"different type":    {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:rpm/wolfi/curl@8.1.2-r0?arch=x86_64", false},
		"different ns":      {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/alpine/curl@8.1.2-r0?arch=x86_64", false},
		"different package": {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/bash@8.1.2-r0?arch=x86_64", false},
		"different version": {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/bash@8.1.3-r0?arch=x86_64", false},
		"p1 no qualifiers":  {"pkg:apk/wolfi/curl@8.1.2-r0", "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", true},
		"p2 no qualifiers":  {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/curl@8.1.2-r0", false},
		"versionless": {
			"pkg:oci/curl",
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			true,
		},
		"different qualifier": {
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?arch=amd64&os=linux",
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?arch=arm64&os=linux",
			false,
		},
		"p2 more qualifiers": {
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64",
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64&os=linux",
			true,
		},
	} {
		require.Equal(t, tc.mustMatch, PurlMatches(tc.p1, tc.p2), fmt.Sprintf("failed testcase: %s", caseName))
	}
}

func TestComponentMatches(t *testing.T) {
	for testCase, tc := range map[string]struct {
		identifier string
		component  *Component
		mustMatch  bool
	}{
		"iri": {
			"https://example.com/document.spdx.json#node",
			&Component{ID: "https://example.com/document.spdx.json#node"},
			true,
		},
		"misc identifier": {
			"madeup-2023-12345",
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": "madeup-2023-12345"},
			},
			true,
		},
		"wrong misc identifier": {
			"madeup-2023-12345",
			&Component{
				Identifiers: map[IdentifierType]string{"customIdentifier": "another-string"},
			},
			false,
		},
		"same purl": {
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64",
			&Component{
				Identifiers: map[IdentifierType]string{PURL: "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64"},
			},
			true,
		},
		"globing purl": {
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			&Component{
				Identifiers: map[IdentifierType]string{PURL: "pkg:oci/curl"},
			},
			true,
		},
		"globing purl (inverse)": {
			"pkg:oci/curl",
			&Component{
				Identifiers: map[IdentifierType]string{
					PURL: "pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
				},
			},
			false,
		},
		"hash": {
			"77d86e9752cb933569dfa1f693ee4338e65b28b4",
			&Component{
				Hashes: map[Algorithm]Hash{
					SHA1: "77d86e9752cb933569dfa1f693ee4338e65b28b4",
				},
			},
			true,
		},
		"wrong hash": {
			"77d86e9752cb933569dfa1f693ee4338e65b28b4",
			&Component{
				Hashes: map[Algorithm]Hash{
					SHA1: "b5cc41d90d7ccc195c4a24ceb32656942c9854ea",
				},
			},
			false,
		},
	} {
		require.Equal(t, tc.mustMatch, tc.component.Matches(tc.identifier), fmt.Sprintf("failed: %s", testCase))
	}
}

func TestProductMatches(t *testing.T) {
	for testCase, tc := range map[string]struct {
		sut          *Product
		product      string
		subcomponent string
		mustMach     bool
	}{
		"identifier only": {
			sut: &Product{
				Component: Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
				}},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"generic purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: "pkg:apk/alpine/libcrypto3",
				}},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"identifier and components in doc and statement": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{
						Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
					},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			mustMach:     true,
		},
		"identifier and no components in query": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{
						Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
					},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "",
			mustMach:     false,
		},
		"identifier and no components in document": {
			sut: &Product{
				Component:     Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			mustMach:     true,
		},
		"identifier + multicomponent doc": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"}},
					{Component{ID: "pkg:apk/alpine/libssl@3.0.8-r3"}},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libssl@3.0.8-r3",
			mustMach:     true,
		},
	} {
		require.Equal(t, tc.mustMach, tc.sut.Matches(tc.product, tc.subcomponent), fmt.Sprintf("failed: %s", testCase))
	}
}

func TestDocumentMatches(t *testing.T) {
	now := time.Now()
	for testCase, tc := range map[string]struct {
		sut           *VEX
		product       string
		vulnerability string
		subcomponents []string
		mustMach      bool
		numMatches    int
	}{
		"regular match": {
			sut: &VEX{
				Metadata: Metadata{Timestamp: &now},
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{ID: "CVE-2023-1255"},
						Products: []Product{
							{
								Component: Component{
									ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
								},
								Subcomponents: []Subcomponent{
									//{Component: Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"}},
								},
							},
						},
					},
				},
			},
			product:       "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			vulnerability: "CVE-2023-1255",
			//subcomponents: []string{"pkg:apk/alpine/libcrypto3@3.0.8-r3"},
			mustMach:   true,
			numMatches: 1,
		},
	} {
		matches := tc.sut.Matches(
			tc.vulnerability, tc.product, tc.subcomponents,
		)
		logrus.Infof("%+v", matches)
		require.Equal(t, tc.numMatches, len(matches), fmt.Sprintf("failed: %s", testCase))
	}
}
