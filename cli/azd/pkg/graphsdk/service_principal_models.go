// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package graphsdk

// A Microsoft Graph Service Principal entity.
type ServicePrincipal struct {
	Id                     *string `json:"id"`
	AppOwnerOrganizationId *string `json:"appOwnerOrganizationId"`
	AppDisplayName         *string `json:"appDisplayName"`
	Description            *string `json:"appDescription"`
	Type                   *string `json:"servicePrincipalType"`
	DisplayName            string  `json:"displayName"`
	AppId                  string  `json:"appId"`
}

type ServicePrincipalCreateRequest struct {
	AppId string `json:"appId"`
}

// A list of service principals returned from the Microsoft Graph.
type ServicePrincipalListResponse struct {
	Value []ServicePrincipal `json:"value"`
}
