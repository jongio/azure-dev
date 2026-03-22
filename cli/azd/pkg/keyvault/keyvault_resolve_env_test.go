// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package keyvault

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockKeyVaultService struct {
	resolveReference func(ctx context.Context, ref string, defaultSubscriptionId string) (string, error)
}

func (m *mockKeyVaultService) GetKeyVault(
	ctx context.Context, subscriptionId string, resourceGroupName string, vaultName string,
) (*KeyVault, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) GetKeyVaultSecret(
	ctx context.Context, subscriptionId string, vaultName string, secretName string,
) (*Secret, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) PurgeKeyVault(
	ctx context.Context, subscriptionId string, vaultName string, location string,
) error {
	panic("unexpected call")
}

func (m *mockKeyVaultService) ListSubscriptionVaults(ctx context.Context, subscriptionId string) ([]Vault, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) CreateVault(
	ctx context.Context,
	tenantId string,
	subscriptionId string,
	resourceGroupName string,
	location string,
	vaultName string,
) (Vault, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) ListKeyVaultSecrets(
	ctx context.Context, subscriptionId string, vaultName string,
) ([]string, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) CreateKeyVaultSecret(
	ctx context.Context, subscriptionId string, vaultName string, secretName string, secretValue string,
) error {
	panic("unexpected call")
}

func (m *mockKeyVaultService) SecretFromAkvs(ctx context.Context, akvs string) (string, error) {
	panic("unexpected call")
}

func (m *mockKeyVaultService) SecretFromKeyVaultReference(
	ctx context.Context, ref string, defaultSubscriptionId string,
) (string, error) {
	if m.resolveReference == nil {
		return "", errors.New("unexpected call")
	}

	return m.resolveReference(ctx, ref, defaultSubscriptionId)
}

func TestParseKeyVaultAppReference_Valid(t *testing.T) {
	t.Parallel()

	ref := "@Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/my-secret/123)"
	parsed, err := ParseKeyVaultAppReference(ref)
	require.NoError(t, err)
	require.Equal(t, "https://my-vault.vault.azure.net", parsed.VaultURL)
	require.Equal(t, "my-vault", parsed.VaultName)
	require.Equal(t, "my-secret", parsed.SecretName)
	require.Equal(t, "123", parsed.SecretVersion)
}

func TestParseKeyVaultAppReference_InvalidHost(t *testing.T) {
	t.Parallel()

	ref := "@Microsoft.KeyVault(SecretUri=https://evil.example.com/secrets/my-secret)"
	_, err := ParseKeyVaultAppReference(ref)
	require.Error(t, err)
	require.ErrorContains(t, err, "not a known Azure Key Vault endpoint")
}

func TestResolveSecretEnvironment_ReplacesReferences(t *testing.T) {
	t.Parallel()

	envVars := []string{
		"PLAIN=value",
		"KV_AKVS=akvs://sub/vault/secret",
		"KV_APP=@Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/my-secret)",
	}

	service := &mockKeyVaultService{
		resolveReference: func(ctx context.Context, ref string, defaultSubscriptionId string) (string, error) {
			require.Equal(t, "sub-default", defaultSubscriptionId)
			return "resolved-" + ref, nil
		},
	}

	resolved, err := ResolveSecretEnvironment(context.Background(), service, envVars, "sub-default")
	require.NoError(t, err)
	require.Equal(t, []string{
		"PLAIN=value",
		"KV_AKVS=resolved-akvs://sub/vault/secret",
		"KV_APP=resolved-@Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/my-secret)",
	}, resolved)
}

func TestResolveSecretEnvironment_ReturnsError(t *testing.T) {
	t.Parallel()

	envVars := []string{"KV_AKVS=akvs://sub/vault/secret"}

	service := &mockKeyVaultService{
		resolveReference: func(ctx context.Context, ref string, defaultSubscriptionId string) (string, error) {
			return "", errors.New("boom")
		},
	}

	resolved, err := ResolveSecretEnvironment(context.Background(), service, envVars, "sub-default")
	require.Nil(t, resolved)
	require.ErrorContains(t, err, "resolving Key Vault reference for environment variable")
}
