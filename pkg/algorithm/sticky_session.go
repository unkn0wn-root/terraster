package algorithm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"strconv"
	"time"
)

const (
	stickySessionCookie = "t_px_SESSION_ID"
	defaultCookieTTL    = 24 * time.Hour
)

type StickySession struct {
	fallback  Algorithm // Fallback algorithm when no cookie exists
	cookieTTL time.Duration
	secure    bool
}

func NewStickySession() *StickySession {
	return &StickySession{
		fallback:  &RoundRobin{},
		cookieTTL: defaultCookieTTL,
		secure:    true,
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

	cookie, err := r.Cookie(stickySessionCookie)
	if err == http.ErrNoCookie {
		return ss.handleNewSession(pool, r, w)
	}

	return ss.handleExistingSession(cookie, servers, pool, r, w)
}

func (ss *StickySession) handleNewSession(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	server := ss.fallback.NextServer(pool, r, w)
	if server == nil {
		return nil
	}

	sessionID := ss.generateSessionID(server.URL)
	http.SetCookie(*w, ss.createSessionCookie(sessionID))

	return server
}

func (ss *StickySession) handleExistingSession(
	cookie *http.Cookie,
	servers []*Server,
	pool ServerPool,
	r *http.Request,
	w *http.ResponseWriter,
) *Server {
	sessionID, err := strconv.ParseUint(cookie.Value, 10, 64)
	if err != nil {
		return ss.handleNewSession(pool, r, w)
	}

	idx := ss.consistentHash(sessionID, len(servers))
	server := servers[idx]

	if server.Alive.Load() && server.CanAcceptConnection() {
		return server
	}

	return ss.handleFailover(pool, r, w)
}

func (ss *StickySession) handleFailover(pool ServerPool, r *http.Request, w *http.ResponseWriter) *Server {
	newServer := ss.fallback.NextServer(pool, r, w)
	if newServer != nil {
		newSessionID := ss.generateSessionID(newServer.URL)
		http.SetCookie(*w, ss.createSessionCookie(newSessionID))
	}
	return newServer
}

func (ss *StickySession) createSessionCookie(sessionID uint64) *http.Cookie {
	return &http.Cookie{
		Name:     stickySessionCookie,
		Value:    strconv.FormatUint(sessionID, 10),
		Path:     "/",
		HttpOnly: true,
		Secure:   ss.secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ss.cookieTTL.Seconds()),
	}
}

func (ss *StickySession) generateSessionID(serverURL string) uint64 {
	hash := sha256.New()
	random := make([]byte, 16)
	rand.Read(random)

	hash.Write(random)
	hash.Write([]byte(serverURL))
	hash.Write([]byte(time.Now().UTC().Format(time.RFC3339Nano)))

	sum := hash.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

func (ss *StickySession) consistentHash(sessionID uint64, numServers int) int {
	return int(sessionID % uint64(numServers))
}
