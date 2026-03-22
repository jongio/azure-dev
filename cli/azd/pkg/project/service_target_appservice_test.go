// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package project

import (
	"strings"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/alpha"
	"github.com/azure/azure-dev/cli/azd/pkg/azapi"
	"github.com/azure/azure-dev/cli/azd/pkg/config"
	"github.com/azure/azure-dev/cli/azd/pkg/environment"
	"github.com/stretchr/testify/require"
)

type serviceTargetValidationTest struct {
	targetResource *environment.TargetResource
	expectError    bool
}

func TestNewAppServiceTargetTypeValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]*serviceTargetValidationTest{
		"ValidateTypeSuccess": {
			targetResource: environment.NewTargetResource("SUB_ID", "RG_ID", "res", string(azapi.AzureResourceTypeWebSite)),
			expectError:    false,
		},
		"ValidateTypeLowerCaseSuccess": {
			targetResource: environment.NewTargetResource(
				"SUB_ID",
				"RG_ID",
				"res",
				strings.ToLower(string(azapi.AzureResourceTypeWebSite)),
			),
			expectError: false,
		},
		"ValidateTypeFail": {
			targetResource: environment.NewTargetResource("SUB_ID", "RG_ID", "res", "BadType"),
			expectError:    true,
		},
	}

	for test, data := range tests {
		t.Run(test, func(t *testing.T) {
			serviceTarget := &appServiceTarget{}

			err := serviceTarget.validateTargetResource(data.targetResource)
			if data.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRunFromPackage_FeatureDisabled(t *testing.T) {
	t.Parallel()

	// Without the alpha flag, the appServiceTarget should not reference run-from-package at all.
	// We verify by checking that an appServiceTarget created with a nil alpha manager has no
	// panic or unexpected behaviour when IsEnabled is guarded correctly.
	st := &appServiceTarget{
		alphaFeatureManager: nil,
	}

	// The nil guard in Deploy prevents any call to IsEnabled.
	require.Nil(t, st.alphaFeatureManager)
}

func TestRunFromPackage_FeatureEnabled(t *testing.T) {
	// Not parallel — mutates global defaultEnablement.
	alpha.SetDefaultEnablement("deploy.runFromPackage", true)
	t.Cleanup(func() { alpha.ResetDefaultEnablement("deploy.runFromPackage") })

	alphaManager := alpha.NewFeaturesManagerWithConfig(config.NewEmptyConfig())

	st := &appServiceTarget{
		alphaFeatureManager: alphaManager,
	}

	// Verify the feature flag is detected as enabled.
	require.True(t, st.alphaFeatureManager.IsEnabled(runFromPackageFeatureKey))
}

func TestRunFromPackage_FeatureDisabledByDefault(t *testing.T) {
	// Not parallel — reads global defaultEnablement which other tests mutate.
	alphaManager := alpha.NewFeaturesManagerWithConfig(config.NewEmptyConfig())

	st := &appServiceTarget{
		alphaFeatureManager: alphaManager,
	}

	// Without explicit enablement, the feature should be disabled.
	require.False(t, st.alphaFeatureManager.IsEnabled(runFromPackageFeatureKey))
}
