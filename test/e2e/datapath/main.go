// Command datapath serves an in-memory gateway datapath on a gatewayd IPC
// socket for the web real-server harness. platformd reaches it through
// sdn.gateway.datapath-socket, so the load balancer, NAT64 and perf verbs
// answer without Open vSwitch or a kernel translator, the way the harness
// runs a TPM simulator and an in-memory quicbaas. It is test tooling: it
// programs no flows and keeps nothing across restarts.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
)

// serve listens on path (mode 0600, the caller's uid may drive it) and
// serves the in-memory datapath until stop is called.
func serve(path string) (stop func(), err error) {
	srv := ipc.NewServer(node{}, ipc.Policy{ControlUIDs: []uint32{uint32(os.Getuid())}})
	srv.SetServices(services())
	if err := srv.Listen(path, 0o600, -1); err != nil {
		return nil, err
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	return func() {
		srv.Stop()
		<-served
	}, nil
}

func main() {
	socket := flag.String("socket", "", "path of the IPC socket to serve")
	flag.Parse()
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "datapath: -socket is required")
		os.Exit(2)
	}
	if err := run(*socket); err != nil {
		fmt.Fprintln(os.Stderr, "datapath:", err)
		os.Exit(1)
	}
}

func run(socket string) error {
	if socket == "" {
		return errors.New("empty socket path")
	}
	stop, err := serve(socket)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "datapath: serving on", socket)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	stop()
	_ = os.Remove(socket)
	return nil
}
