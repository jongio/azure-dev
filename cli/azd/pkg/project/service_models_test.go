// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package project

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ServiceResults_Json_Marshal(t *testing.T) {
	deployResult := &ServiceDeployResult{
		Artifacts: ArtifactCollection{
			{
				Kind:         ArtifactKindDeployment,
				Location:     "https://myapp.azurewebsites.net",
				LocationKind: LocationKindRemote,
				Metadata:     nil,
			},
		},
	}

	jsonBytes, err := json.Marshal(deployResult)
	require.NoError(t, err)
	require.NotEmpty(t, string(jsonBytes))
}

func TestArtifactCollection(t *testing.T) {
	// Create a new service context
	ctx := NewServiceContext()

	// Add some artifacts using the available Add method
	err := ctx.Build.Add(&Artifact{
		Kind:         ArtifactKindDirectory,
		Location:     "/path/to/app.exe",
		LocationKind: LocationKindLocal,
		Metadata:     nil,
	})
	require.NoError(t, err)

	err = ctx.Package.Add(&Artifact{
		Kind:         ArtifactKindArchive,
		Location:     "/path/to/package.zip",
		LocationKind: LocationKindLocal,
		Metadata:     nil,
	})
	require.NoError(t, err)

	err = ctx.Package.Add(&Artifact{
		Kind:         ArtifactKindContainer,
		Location:     "registry.io/myapp:latest",
		LocationKind: LocationKindRemote,
		Metadata:     map[string]string{"digest": "sha256:abc123"},
	})
	require.NoError(t, err)

	// Test finding artifacts using available Find method
	buildArtifacts := ctx.Build.Find()
	require.Len(t, buildArtifacts, 1, "Expected 1 build artifact")
	require.Equal(t, "/path/to/app.exe", buildArtifacts[0].Location)

	// Test package artifacts
	packageArtifacts := ctx.Package.Find()
	require.Len(t, packageArtifacts, 2, "Expected 2 package artifacts")

	// Test that deploy collection is empty
	deployArtifacts := ctx.Deploy.Find()
	require.Len(t, deployArtifacts, 0, "Expected deploy to be empty")
}

func TestArtifactKindEnums(t *testing.T) {
	// Test that all well-known kinds are strings
	kinds := []ArtifactKind{
		ArtifactKindDirectory,
		ArtifactKindArchive,
		ArtifactKindContainer,
		ArtifactKindDeployment,
		ArtifactKindConfig,
		ArtifactKindEndpoint,
		ArtifactKindResource,
	}

	for _, kind := range kinds {
		require.NotEmpty(t, string(kind), "ArtifactKind should not be empty string")
	}

	// Test that string conversion works
	require.Equal(t, "container", string(ArtifactKindContainer))
}

func TestServicePackageResultTimingJSON(t *testing.T) {
	result := ServicePackageResult{
		PackageDurationMs: 1234,
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	require.Equal(t, float64(1234), parsed["packageDurationMs"])
}

func TestServicePackageResultTimingOmitEmpty(t *testing.T) {
	result := ServicePackageResult{}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	// packageDurationMs has omitempty so it should be absent when zero
	_, has := parsed["packageDurationMs"]
	require.False(t, has, "packageDurationMs should be omitted when zero")
}

func TestServicePublishResultTimingJSON(t *testing.T) {
	result := ServicePublishResult{
		PublishDurationMs: 5678,
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	require.Equal(t, float64(5678), parsed["publishDurationMs"])
}

func TestServicePublishResultTimingOmitEmpty(t *testing.T) {
	result := ServicePublishResult{}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	_, has := parsed["publishDurationMs"]
	require.False(t, has, "publishDurationMs should be omitted when zero")
}

func TestServiceDeployResultTimingJSON(t *testing.T) {
	result := ServiceDeployResult{
		DeployDurationMs: 9012,
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	require.Equal(t, float64(9012), parsed["deployDurationMs"])
}

func TestServiceDeployResultTimingOmitEmpty(t *testing.T) {
	result := ServiceDeployResult{}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	_, has := parsed["deployDurationMs"]
	require.False(t, has, "deployDurationMs should be omitted when zero")
}
