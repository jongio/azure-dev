// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package cmd

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/contracts"
)

// newRealisticProvisionResult builds a ProvisionResult with realistic outputs and resources
// matching a typical azd provision run.
func newRealisticProvisionResult() *ProvisionResult {
	outputs := make(map[string]contracts.EnvRefreshOutputParameter, 20)
	for i := 0; i < 20; i++ {
		outputs[fmt.Sprintf("SERVICE_%d_ENDPOINT", i)] = contracts.EnvRefreshOutputParameter{
			Type:  contracts.EnvRefreshOutputTypeString,
			Value: fmt.Sprintf("https://svc%d.azurewebsites.net", i),
		}
	}

	resources := make([]contracts.EnvRefreshResource, 30)
	for i := range resources {
		resources[i] = contracts.EnvRefreshResource{
			Id: fmt.Sprintf(
				"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-bench/providers/Microsoft.Web/sites/svc%d",
				i,
			),
		}
	}

	return &ProvisionResult{
		State: contracts.EnvRefreshResult{
			Outputs:   outputs,
			Resources: resources,
		},
		DurationMs: 185000,
	}
}

// BenchmarkProvisionResultJSON measures JSON marshal+unmarshal of a ProvisionResult
// with 20 outputs and 30 resources, representative of a medium-sized azd provision.
func BenchmarkProvisionResultJSON(b *testing.B) {
	b.ReportAllocs()

	result := newRealisticProvisionResult()

	// Pre-marshal once to verify correctness.
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
		var decoded ProvisionResult
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			b.Fatal(err)
		}
	}

	// Prevent the compiler from optimizing away the pre-marshal.
	_ = data
}
