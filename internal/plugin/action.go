package plugin

// Action represents what the proxy should do with the request/response
type Action int

const (
	// Continue indicates that the request/response should proceed normally
	Continue Action = iota
	// Stop indicates that the request/response should be stopped
	Stop
	// Modify indicates that the request/response has been modified and should proceed
	Modify
)
