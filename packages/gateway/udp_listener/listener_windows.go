//go:build windows
// +build windows

package udplistener

import (
	"fmt"
	"net"
	"syscall"
)

func SetupListenerConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return fmt.Errorf("Hanzo KMS relay not supported for windows.")
		},
	}
}
