package algorithm

import (
	"hash/fnv"
	"net/http"
	"strconv"
)

const (
	stickySessionCookie = "PX_SESSION_ID"
)

type StickySession struct {
	fallback Algorithm // Fallback algorithm when no cookie exists
}

func NewStickySession() *StickySession {
	return &StickySession{
		fallback: &RoundRobin{},
	}
}

func (ss *StickySession) Name() string {
	return "sticky-session"
}

func (ss *StickySession) NextServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	// Try to get existing cookie
	cookie, err := r.Cookie(stickySessionCookie)
	if err == http.ErrNoCookie {
		// No cookie found, use fallback algorithm to choose server
		server := ss.fallback.NextServer(pool, r, w)
		if server == nil {
			return nil
		}

		// Generate new session ID based on server URL
		h := fnv.New32a()
		h.Write([]byte(server.URL))
		sessionID := h.Sum32()

		// Add cookie to response
		http.SetCookie(*w, &http.Cookie{
			Name:     stickySessionCookie,
			Value:    strconv.FormatUint(uint64(sessionID), 10),
			Path:     "/",
			HttpOnly: true,
		})

		return server
	}

	// Cookie exists, try to find the corresponding server
	sessionID, err := strconv.ParseUint(cookie.Value, 10, 32)
	if err != nil {
		// Invalid cookie value, use fallback
		return ss.fallback.NextServer(pool, r, w)
	}

	idx := uint32(sessionID) % uint32(len(servers))
	server := servers[idx]

	// Check if the sticky server is still healthy
	if server.Alive.Load() && server.CanAcceptConnection() {
		return server
	}

	// Sticky server is down, use fallback and update cookie
	newServer := ss.fallback.NextServer(pool, r, w)
	if newServer != nil {
		// Generate new session ID
		h := fnv.New32a()
		h.Write([]byte(newServer.URL))
		newSessionID := h.Sum32()

		// Update cookie with new server
		http.SetCookie(*w, &http.Cookie{
			Name:     stickySessionCookie,
			Value:    strconv.FormatUint(uint64(newSessionID), 10),
			Path:     "/",
			HttpOnly: true,
		})
	}

	return newServer
}
