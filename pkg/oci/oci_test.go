/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package oci

import (
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"
)

func TestGenerateReferenceIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected IdentifiersBundle
		mustErr  bool
	}{
		{
			name:  "multi arch index",
			input: "alpine@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/alpine@sha256%3Aeece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
						"pkg:oci/alpine@sha256%3Aeece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978?arch=amd64&os=linux&repository_url=index.docker.io%2Flibrary",
						"pkg:oci/alpine@sha256%3A48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86",
						"pkg:oci/alpine@sha256%3A48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86?arch=amd64&os=linux&repository_url=index.docker.io%2Flibrary",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
						"48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86",
					},
				},
			},
			mustErr: false,
		},
		{
			name:  "single arch image",
			input: "cgr.dev/chainguard/curl@sha256:3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/curl@sha256%3A3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8",
						"pkg:oci/curl@sha256%3A3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8?arch=amd64&os=linux&repository_url=cgr.dev%2Fchainguard",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8",
					},
				},
			},
			mustErr: false,
		},
		{
			name:    "invalid reference",
			input:   "invalid reference",
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := GenerateReferenceIdentifiers(tc.input, "linux", "amd64")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, res)
		})
	}
}
