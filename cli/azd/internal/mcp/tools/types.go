// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package tools

// ErrorResponse represents a JSON error response structure that can be reused across all tools
type ErrorResponse struct {
	Message string `json:"message"`
	Error   bool   `json:"error"`
}
