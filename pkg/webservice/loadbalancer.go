package webservice

import "sync"

type LoadBalancerFunc func(backends []string) string

func RoundRobinBalancer() LoadBalancerFunc {
	var mu sync.Mutex
	var idx int
	return func(backends []string) string {
		mu.Lock()
		defer mu.Unlock()
		selected := backends[idx]
		idx = (idx + 1) % len(backends)
		return selected
	}
}
