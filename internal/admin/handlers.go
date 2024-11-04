package admin

import (
	"encoding/json"
	"net/http"

	"github.com/unkn0wn-root/go-load-balancer/internal/pool"
	"github.com/unkn0wn-root/go-load-balancer/internal/service"
)

type BackendStatus struct {
	URL         string `json:"url"`
	Alive       bool   `json:"alive"`
	Connections int32  `json:"connections"`
}

func (a *AdminAPI) handleConfig(w http.ResponseWriter, r *http.Request) {
	servicePath := r.URL.Query().Get("service")
	var service *service.ServiceInfo

	if servicePath == "" {
		// Get default service
		services := a.serviceManager.GetServices()
		switch len(services) {
		case 1:
			service = services[0]
		case 0:
			http.Error(w, "No services configured", http.StatusNotFound)
			return
		default:
			http.Error(w, "Multiple services exist, please specify service path", http.StatusBadRequest)
			return
		}
	} else {
		service = a.serviceManager.GetServiceForPath(servicePath)
		if service == nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		cfg := service.ServerPool.GetConfig()
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		var update pool.ConfigUpdate
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := service.ServerPool.UpdateConfig(update); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
