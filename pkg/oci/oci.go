/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package oci

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// IdentifiersBundle is a struct that collects different software identifiers
// and hashes in a structured way
type IdentifiersBundle struct {
	Identifiers map[vex.IdentifierType][]string
	Hashes      map[vex.Algorithm][]vex.Hash
}

// ToStringSlice returns all the identifiers and hashes contained in the bundle
// in a flat string slice
func (bundle *IdentifiersBundle) ToStringSlice() []string {
	ret := []string{}
	if bundle.Identifiers != nil {
		for _, sl := range bundle.Identifiers {
			for _, id := range sl {
				ret = append(ret, id)
			}
		}
	}

	if bundle.Hashes != nil {
		for _, sl := range bundle.Hashes {
			for _, h := range sl {
				ret = append(ret, string(h))
			}
		}
	}

	// Sort the slice to make the return value deterministic
	sort.Strings(ret)

	return ret
}

// GenerateReferenceIdentifiers reads an image reference string and
// generates a list of identifiers that can be used to match an entry
// in VEX a  document.
//
// This function returns the hashes and package urls to match the
// container image specified by the reference string. If the image
// is an index and os and arch are specified, the bundle will include
// purls and hashes for both the arch image and the index fronting it.
//
// For each image, the returned bundle will include a SHA256 hash with
// the image digest and two purls, with and without qualifiers. The
// variant with qualifiers will contain all the data known from the
// registry to match VEX documents with more specific purls.
//
// This function performs calls to the registry to retrieve data such
// as the image digests when needed.
func GenerateReferenceIdentifiers(refString, os, arch string) (IdentifiersBundle, error) {
	var dString, tag string
	bundle := IdentifiersBundle{
		Identifiers: map[vex.IdentifierType][]string{vex.PURL: {}},
		Hashes:      map[vex.Algorithm][]vex.Hash{vex.SHA256: {}},
	}

	ref, err := name.ParseReference(refString)
	if err != nil {
		return bundle, fmt.Errorf("parsing image reference: %w", err)
	}

	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha") {
		dString = identifier
	} else {
		tag = identifier
	}

	// If we dont have the digest in the reference, fetch it
	if dString == "" {
		dString, err = crane.Digest(refString)
		if err != nil {
			return bundle, fmt.Errorf("getting image digest: %w", err)
		}
	}

	bundle.Hashes[vex.SHA256] = append(
		bundle.Hashes[vex.SHA256], vex.Hash(strings.TrimPrefix(dString, "sha256:")),
	)

	pts := strings.Split(ref.Context().RepositoryStr(), "/")
	imageName := pts[len(pts)-1]
	registryPath := ref.Context().RegistryStr() + "/" + strings.ReplaceAll(ref.Context().RepositoryStr(), imageName, "")

	// Generate the variants for the input reference
	identifiers := generateImagePurlVariants(registryPath, imageName, dString, tag, os, arch)
	bundle.Identifiers[vex.PURL] = append(bundle.Identifiers[vex.PURL], identifiers...)

	if os == "" || arch == "" {
		return bundle, nil
	}

	// Now compute the identifiers for the platform specific image
	platform, err := v1.ParsePlatform(os + "/" + arch)
	if err != nil {
		return bundle, fmt.Errorf("parsing platform: %w", err)
	}

	archDString, err := crane.Digest(refString, crane.WithPlatform(platform))
	if err != nil {
		// If there is no arch-specific variant, we simply don't
		// include it. Return what we know.
		if strings.Contains(err.Error(), "no child with platform") {
			return bundle, nil
		}
		return bundle, fmt.Errorf("getting image digest: %w", err)
	}

	// If the single-arch image digest is different, we generate purls for
	// it as we want to match the index and the arch image:
	if archDString != dString && archDString != "" {
		bundle.Identifiers[vex.PURL] = append(
			bundle.Identifiers[vex.PURL], generateImagePurlVariants(registryPath, imageName, archDString, tag, os, arch)...,
		)
		bundle.Hashes[vex.SHA256] = append(
			bundle.Hashes[vex.SHA256], vex.Hash(strings.TrimPrefix(archDString, "sha256:")),
		)
	}

	return bundle, nil
}

// generatePurlVariants
func generateImagePurlVariants(registryString, imageName, digestString, tag, os, arch string) []string {
	purls := []string{}

	// Purl with full qualifiers
	qMap := map[string]string{}
	if registryString != "" {
		qMap["repository_url"] = strings.TrimSuffix(registryString, "/")
	}
	if tag != "" {
		qMap["tag"] = tag
	}
	if os != "" {
		qMap["os"] = os
	}
	if arch != "" {
		qMap["arch"] = arch
	}

	purls = append(purls,
		// Simple purl, no qualifiers
		packageurl.NewPackageURL(
			packageurl.TypeOCI, "", imageName, digestString, nil, "",
		).String(),

		// Specific version with full qualifiers
		packageurl.NewPackageURL(
			packageurl.TypeOCI, "", imageName, digestString,
			packageurl.QualifiersFromMap(qMap), "",
		).String(),
	)

	return purls
}
