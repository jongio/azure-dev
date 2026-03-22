// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package project

import (
	"encoding/json"
	"fmt"
	"testing"
)

// newRealisticDeployResult builds a ServiceDeployResult with a realistic number of artifacts.
func newRealisticDeployResult() *ServiceDeployResult {
	artifacts := make(ArtifactCollection, 0, 10)
	for i := 0; i < 10; i++ {
		artifacts = append(artifacts, &Artifact{
			Kind:         ArtifactKindEndpoint,
			Location:     fmt.Sprintf("https://svc%d.azurewebsites.net", i),
			LocationKind: LocationKindRemote,
			Metadata: map[string]string{
				"resourceGroup": fmt.Sprintf("rg-bench-%d", i),
				"subscriptionId": "00000000-0000-0000-0000-000000000000",
			},
		})
	}

	return &ServiceDeployResult{
		Artifacts:        artifacts,
		DeployDurationMs: 42350,
	}
}

// BenchmarkServiceDeployResultJSON measures the cost of JSON round-tripping a ServiceDeployResult
// with 10 artifacts, each carrying metadata. This exercises both marshal and unmarshal paths.
func BenchmarkServiceDeployResultJSON(b *testing.B) {
	b.ReportAllocs()

	result := newRealisticDeployResult()

	// Pre-marshal once to get a realistic payload for unmarshal.
	data, err := json.Marshal(result)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for range b.N {
		// Marshal
		encoded, err := json.Marshal(result)
		if err != nil {
			b.Fatal(err)
		}

		// Unmarshal
		var decoded ServiceDeployResult
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			b.Fatal(err)
		}
	}

	// Prevent the compiler from optimizing away the pre-marshal.
	_ = data
}
