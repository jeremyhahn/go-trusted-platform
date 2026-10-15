package gateway

// NewTestRuntime returns the fake datapath runtime the in-package tests use,
// with the load balancer's group client, for the external tests that run a
// gateway as a supervised child.
func NewTestRuntime() *GatewayRuntime {
	runtime := newTestRuntime()
	runtime.Groups = newFakeGroupClient()
	return runtime
}
