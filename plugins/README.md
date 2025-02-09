# Terraster Plugin Development Guide

This guide explains how to develop custom plugins for the Terraster. Plugins allow you to extend the load balancer's functionality by intercepting and modifying requests and responses.

## Plugin Interface

To create a plugin, you need to implement the `Handler` interface:

```go
type Handler interface {
    ProcessRequest(ctx context.Context, req *http.Request) *Result
    ProcessResponse(ctx context.Context, resp *http.Response) *Result
    Name() string
    Priority() int
    Cleanup() error
}
```

### Required Methods

- `ProcessRequest`: Processes incoming requests before they reach the backend
- `ProcessResponse`: Processes responses before they're sent back to the client
- `Name`: Returns the plugin's unique identifier
- `Priority`: Determines the plugin's execution order (lower numbers execute first)
- `Cleanup`: Handles plugin cleanup when shutting down

## Creating a Plugin

### 1. Basic Structure

Start by creating a new Go package for your plugin:

```go
package myplugin

import (
    "context"
    "net/http"
    "github.com/unkn0wn-root/terraster/pkg/plugin"
)

type MyPlugin struct {
    // Plugin configuration and state
}

func New() plugin.Handler {
    return &MyPlugin{}
}
```

### 2. Configuration

It's recommended to use a configuration structure to make your plugin configurable:

```go
type Config struct {
    // Define your configuration fields
    Enabled     bool     `json:"enabled"`
    SomeOption  string   `json:"some_option"`
}
```

### 3. Implementing the Interface

Each method in the interface serves a specific purpose:

#### ProcessRequest

```go
func (p *MyPlugin) ProcessRequest(ctx context.Context, req *http.Request) *plugin.Result {
    // Modify or validate the request
    // Return plugin.ResultModify to continue processing
    // Return a custom result with plugin.NewResult to stop processing
    return plugin.ResultModify
}
```

#### ProcessResponse

```go
func (p *MyPlugin) ProcessResponse(ctx context.Context, resp *http.Response) *plugin.Result {
    // Modify or transform the response
    return plugin.ResultModify
}
```

#### Additional Required Methods

```go
func (p *MyPlugin) Name() string {
    return "my_plugin"
}

func (p *MyPlugin) Priority() int {
    return 50 // Middle priority
}

func (p *MyPlugin) Cleanup() error {
    // Clean up resources
    return nil
}
```

## Result Types

The plugin system uses `Result` objects to control request/response flow:

```go
// Continue processing
plugin.ResultModify

// Stop processing and return custom response
plugin.NewResult(
    plugin.Stop,
    plugin.WithStatus(http.StatusBadRequest),
    plugin.WithJSONResponse(map[string]string{
        "error": "Invalid request",
    }),
)
```

## Best Practices

1. **Error Handling**
   - Always handle errors gracefully
   - Use appropriate HTTP status codes
   - Log errors with context for debugging

2. **Performance**
   - Minimize memory allocations
   - Avoid blocking operations

3. **Context Usage**
   - Respect context cancellation
   - Use context for request-scoped values
   - Don't store context values across requests

4. **Configuration**
   - Make your plugin configurable
   - Provide sensible defaults
   - Validate configuration on startup

5. **Resource Management**
   - Clean up resources in the Cleanup method
   - Use sync.Pool for frequently allocated objects
   - Implement proper connection pooling if needed

## Example Plugin

See the [example plugin](https://github.com/unkn0wn-root/terraster/blob/main/example/main.go) for a complete implementation demonstrating:

- Request/Response processing
- Rate limiting
- CORS handling
- Authentication
- Error handling
- Configuration management

## Integration

To integrate your plugin with the Terraster, you have two options:

### 1. Default Plugins Directory

Place your plugin file in the `plugins` directory in the Terraster root:

```
terraster/
├── plugins/
│   └── your_plugin.go
```

### 2. Custom Plugin Directory

Specify a custom plugin directory in your Terraster configuration:

```yaml
plugin_directory: "/path/to/plugins" # Will default to `./plugins` if not specified
```

The load balancer will automatically discover and load plugins from the configured directory during startup. Make sure your plugin implements the required Handler interface and is properly structured as a Go package.

## Testing

It's recommended to thoroughly test your plugins:

```go
func TestMyPlugin(t *testing.T) {
    plugin := New()

    // Test request processing
    req := httptest.NewRequest("GET", "/test", nil)
    result := plugin.ProcessRequest(context.Background(), req)

    // Assert expected behavior
    // ...
}
```
