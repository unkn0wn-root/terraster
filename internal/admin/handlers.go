package admin

import (
	"encoding/json"
	"net/http"
)

type BackendStatus struct {
	URL         string `json:"url"`
	Alive       bool   `json:"alive"`
	Connections int32  `json:"connections"`
}

type ConfigUpdate struct {
	Algorithm string `json:"algorithm"`
	MaxConns  int    `json:"max_connections"`
}

func (a *AdminAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := a.serverPool.GetConfig()
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var update ConfigUpdate
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
