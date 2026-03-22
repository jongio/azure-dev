// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package state

// Config is the state configuration for an azd project
type Config struct {
	Remote *RemoteConfig `json:"remote" yaml:"remote"`
}

// RemoteConfig is the state configuration for a remote backend
type RemoteConfig struct {
	Config  map[string]any `json:"config"  yaml:"config"`
	Backend string         `json:"backend" yaml:"backend"`
}
