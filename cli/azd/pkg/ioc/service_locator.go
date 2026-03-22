// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package ioc

// ServiceLocator abstracts the IoC container for service resolution.
//
// Thread-safety: After the container is fully initialized (all registrations complete),
// Resolve, ResolveNamed, and Invoke perform read-only map lookups on the underlying
// golobby/container. Concurrent reads without concurrent writes are safe in Go.
// This means ServiceLocator is safe for concurrent use from multiple goroutines
// in production code (e.g. parallel provisioning), provided no new registrations
// are made after initialization.
type ServiceLocator interface {
	Resolve(instance any) error
	ResolveNamed(name string, instance any) error
	Invoke(resolver any) error
}
