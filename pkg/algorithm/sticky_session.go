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
	stickySessionCookie = "t_px__SESSION_ID" // client cookie session name
	defaultCookieTTL    = 24 * time.Hour     // cookie expiration time
)

type StickySession struct {
	fallback  Algorithm // if current server is not active or alive - use fallback to pick server
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

	serverHash := uint32(sessionID >> 32)
	for _, s := range servers {
		if hashServerURL(s.URL) == serverHash {
			if s.Alive.Load() && s.CanAcceptConnection() {
				return s
			}
			break
		}
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
	serverHash := hashServerURL(serverURL)
	nonce := generateRandomNonce()
	return (uint64(serverHash) << 32) | uint64(nonce)
}

func hashServerURL(url string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(url))
	return h.Sum32()
}

func generateRandomNonce() uint32 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint32(b)
}
