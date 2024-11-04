package admin

import (
	"encoding/json"
	"net/http"

	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
)

type BackendStatus struct {
	URL         string `json:"url"`
	Alive       bool   `json:"alive"`
	Connections int32  `json:"connections"`
}

func (a *AdminAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := a.serverPool.GetConfig()
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var update pool.ConfigUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.serverPool.UpdateConfig(update); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
