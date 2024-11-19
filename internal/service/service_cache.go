package service

import "fmt"

type ServiceKey struct {
	Host     string
	Port     int
	Protocol ServiceType
}

func (k ServiceKey) String() string {
	return fmt.Sprintf("%s|%d|%s", k.Host, k.Port, k.Protocol)
}
