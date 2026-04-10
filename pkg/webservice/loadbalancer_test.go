// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webservice

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoundRobinBalancer(t *testing.T) {
	t.Run("round robin distribution", func(t *testing.T) {
		backends := []string{"backend1", "backend2", "backend3"}
		balancer := RoundRobinBalancer()

		// Test multiple rounds to ensure proper cycling
		expected := []string{
			"backend1", "backend2", "backend3", // First round
			"backend1", "backend2", "backend3", // Second round
			"backend1", // Start of third round
		}

		for i, exp := range expected {
			result := balancer(backends)
			assert.Equal(t, exp, result, "iteration %d", i)
		}
	})

	t.Run("single backend", func(t *testing.T) {
		backends := []string{"single-backend"}
		balancer := RoundRobinBalancer()

		// Should always return the same backend
		for i := 0; i < 5; i++ {
			result := balancer(backends)
			assert.Equal(t, "single-backend", result, "iteration %d", i)
		}
	})

	t.Run("two backends", func(t *testing.T) {
		backends := []string{"backend1", "backend2"}
		balancer := RoundRobinBalancer()

		expected := []string{
			"backend1", "backend2",
			"backend1", "backend2",
			"backend1", "backend2",
		}

		for i, exp := range expected {
			result := balancer(backends)
			assert.Equal(t, exp, result, "iteration %d", i)
		}
	})

	t.Run("thread safety", func(t *testing.T) {
		backends := []string{"backend1", "backend2", "backend3"}
		balancer := RoundRobinBalancer()

		var wg sync.WaitGroup
		results := make([]string, 100)
		mu := sync.Mutex{}

		// Run concurrent requests
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				backend := balancer(backends)
				mu.Lock()
				results[idx] = backend
				mu.Unlock()
			}(i)
		}

		wg.Wait()

		// Verify all results are valid backends
		backendMap := make(map[string]bool)
		for _, b := range backends {
			backendMap[b] = true
		}

		for i, result := range results {
			assert.True(t, backendMap[result], "iteration %d returned invalid backend: %s", i, result)
		}

		// Count distribution - should be relatively even
		counts := make(map[string]int)
		for _, result := range results {
			counts[result]++
		}

		// Each backend should get approximately 33 requests (100/3)
		// We allow some variance due to thread scheduling
		for backend, count := range counts {
			assert.True(t, count >= 25 && count <= 42,
				"backend %s got %d requests, expected between 25 and 42", backend, count)
		}
	})

	t.Run("independent balancer instances", func(t *testing.T) {
		backends := []string{"backend1", "backend2", "backend3"}

		// Create two independent balancer instances
		balancer1 := RoundRobinBalancer()
		balancer2 := RoundRobinBalancer()

		// Advance balancer1
		balancer1(backends)
		balancer1(backends)

		// balancer2 should start from the beginning
		result := balancer2(backends)
		assert.Equal(t, "backend1", result, "balancer2 should start from beginning")

		// balancer1 should be at position 3
		result = balancer1(backends)
		assert.Equal(t, "backend3", result, "balancer1 should be at position 3")
	})

	t.Run("large number of backends", func(t *testing.T) {
		// Create a large list of backends
		backends := make([]string, 100)
		for i := 0; i < 100; i++ {
			backends[i] = string(rune('a'+(i%26))) + string(rune('0'+(i/26)))
		}

		balancer := RoundRobinBalancer()

		// Verify all backends are visited in order
		for i := 0; i < 200; i++ {
			expected := backends[i%100]
			result := balancer(backends)
			assert.Equal(t, expected, result, "iteration %d", i)
		}
	})
}
