package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

type WebSocketProxy struct {
	upgrader  websocket.Upgrader
	backend   *url.URL
	onConnect func(string)
	onClose   func(string)
}

func NewWebSocketProxy(backend *url.URL) *WebSocketProxy {
	return &WebSocketProxy{
		backend: backend,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Override this in production
			},
		},
	}
}

func (wp *WebSocketProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	backendURL := *wp.backend
	backendURL.Scheme = strings.Replace(backendURL.Scheme, "http", "ws", 1)
	backendConn, _, err := websocket.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		http.Error(w, "Could not connect to backend", http.StatusServiceUnavailable)
		return
	}
	defer backendConn.Close()

	clientConn, err := wp.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer clientConn.Close()

	if wp.onConnect != nil {
		wp.onConnect(r.RemoteAddr)
	}
	defer func() {
		if wp.onClose != nil {
			wp.onClose(r.RemoteAddr)
		}
	}()

	errChan := make(chan error, 2)
	go wp.proxy(clientConn, backendConn, errChan)
	go wp.proxy(backendConn, clientConn, errChan)

	// Wait for error or completion
	<-errChan
}

func (wp *WebSocketProxy) proxy(dst, src *websocket.Conn, errChan chan error) {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			errChan <- err
			return
		}

		err = dst.WriteMessage(messageType, message)
		if err != nil {
			errChan <- err
			return
		}
	}
}
