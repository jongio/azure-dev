// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package kustomize

import "github.com/azure/azure-dev/cli/azd/pkg/osutil"

type Config struct {
	Env       osutil.ExpandableMap      `yaml:"env"`
	Directory osutil.ExpandableString   `yaml:"dir"`
	Edits     []osutil.ExpandableString `yaml:"edits"`
}
