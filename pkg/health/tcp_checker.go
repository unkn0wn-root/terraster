package health

import (
	"net"
	"time"
)

type TCPChecker struct {
	timeout time.Duration
}

func NewTCPChecker(timeout time.Duration) *TCPChecker {
	return &TCPChecker{
		timeout: timeout,
	}
}

func (c *TCPChecker) Check(address string) error {
	conn, err := net.DialTimeout("tcp", address, c.timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}
