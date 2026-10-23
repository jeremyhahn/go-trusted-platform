package gateway

// NewTestRuntime returns the fake datapath runtime the in-package tests use,
// with the load balancer's group client, for the external tests that run a
// gateway as a supervised child.
func NewTestRuntime() *GatewayRuntime {
	runtime := newTestRuntime()
	runtime.Groups = newFakeGroupClient()
	return runtime
}

// TestBridge is a fake OVS bridge several runtimes share (bridge_test.go).
type TestBridge = testBridge

// NewTestBridge returns an empty shared fake bridge.
func NewTestBridge() *TestBridge { return newTestBridge() }

// NewTestRuntimeOn returns a fresh runtime that programs bridge, so each
// supervised child in a test starts over the bridge its predecessor left.
func NewTestRuntimeOn(bridge *TestBridge) *GatewayRuntime {
	runtime := newTestRuntime()
	runtime.Controller = &testController{b: bridge}
	runtime.OVS = bridge
	runtime.Groups = bridge
	return runtime
}
