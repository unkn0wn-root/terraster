package service

import "fmt"

type ServiceKey struct {
	Host     string
	Path     string
	Port     int
	Protocol ServiceType
}

func (k ServiceKey) String() string {
	return fmt.Sprintf("%s|%s|%d|%s", k.Host, k.Path, k.Port, k.Protocol)
}
