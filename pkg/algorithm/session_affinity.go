package algorithm

import (
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"net/http"
	"strconv"
	"time"
)

const (
	// sessionCookie is the cookie identifier for client session tracking
	sessionCookie = "t_px__SESSION_ID"
	// defaultSessionTTL defines the default cookie lifetime
	defaultSessionTTL = 24 * time.Hour
)

type SessionAffinity struct {
	fallbackAlgo Algorithm     // alternative algorithm when sticky session fails
	sessionTTL   time.Duration // session cookie lifetime
	useSecure    bool          // secure cookie settings
}

// NewSessionAffinity creates a new sticky session manager with default settings
func NewSessionAffinity() *SessionAffinity {
	return &SessionAffinity{
		fallbackAlgo: &RoundRobin{},
		sessionTTL:   defaultSessionTTL,
		useSecure:    true,
	}
}

// Name returns the identifier of the session affinity
func (ss *SessionAffinity) Name() string {
	return "sticky-session"
}

// NextServer selects the appropriate backend server based on session stickiness
func (ss *SessionAffinity) NextServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	servers := pool.GetBackends()
	if len(servers) == 0 {
		return nil
	}

	cookie, err := r.Cookie(sessionCookie)
	if err == http.ErrNoCookie {
		return ss.selectNewServer(pool, r, w)
	}

	return ss.selectServerFromSession(cookie, servers, pool, r, w)
}

// selectNewServer handles new client connections without existing session
func (ss *SessionAffinity) selectNewServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	server := ss.fallbackAlgo.NextServer(pool, r, w)
	if server == nil {
		return nil
	}

	sessionID := ss.newSessionID(server.URL)
	http.SetCookie(*w, ss.newSessionCookie(sessionID))
	return server
}

// selectServerFromSession handles clients with existing session cookies
func (ss *SessionAffinity) selectServerFromSession(
	cookie *http.Cookie,
	servers []*Server,
	pool ServerPool,
	r *http.Request,
	w *http.ResponseWriter,
) *Server {
	sessionID, err := strconv.ParseUint(cookie.Value, 10, 64)
	if err != nil {
		return ss.selectNewServer(pool, r, w)
	}

	serverHash := uint32(sessionID >> 32)
	for _, s := range servers {
		if computeURLHash(s.URL) == serverHash {
			if s.Alive.Load() && s.CanAcceptConnection() {
				return s
			}
			break
		}
	}

	return ss.selectFallbackServer(pool, r, w)
}

// selectFallbackServer manages failover when the original server is unavailable
func (ss *SessionAffinity) selectFallbackServer(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	newServer := ss.fallbackAlgo.NextServer(pool, r, w)
	if newServer != nil {
		newSessionID := ss.newSessionID(newServer.URL)
		http.SetCookie(*w, ss.newSessionCookie(newSessionID))
	}
	return newServer
}

// newSessionCookie creates an HTTP cookie with the session information
func (ss *SessionAffinity) newSessionCookie(sessionID uint64) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    strconv.FormatUint(sessionID, 10),
		Path:     "/",
		HttpOnly: true,
		Secure:   ss.useSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ss.sessionTTL.Seconds()),
	}
}

// newSessionID generates a unique session identifier for a server
func (ss *SessionAffinity) newSessionID(serverURL string) uint64 {
	serverHash := computeURLHash(serverURL)
	nonce := generateNonce()
	return (uint64(serverHash) << 32) | uint64(nonce)
}

// computeURLHash creates a hash of the server URL for consistent mapping
func computeURLHash(url string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(url))
	return h.Sum32()
}

// generateNonce creates a random 32-bit value for session uniqueness
func generateNonce() uint32 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint32(b)
}
