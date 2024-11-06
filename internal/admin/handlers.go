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
	serviceName := r.URL.Query().Get("service_name")
	pathName := r.URL.Query().Get("path")

	var srvc *service.ServiceInfo
	if serviceName == "" {
		services := a.serviceManager.GetServices()
		switch len(services) {
		case 1:
			srvc = services[0]
		case 0:
			http.Error(w, "No services configured", http.StatusNotFound)
			return
		default:
			http.Error(w, "Multiple services exist, please specify service name", http.StatusBadRequest)
			return
		}
	} else {
		srvc = a.serviceManager.GetServiceByName(serviceName)
		if srvc == nil {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
	}

	if pathName == "" {
		http.Error(w, "Path cannot be empty", http.StatusNotFound)
		return
	}

	var location *service.LocationInfo
	for _, loc := range srvc.Locations {
		if loc.Path == pathName {
			location = loc
			break
		}
	}

	if location == nil {
		http.Error(w, "Location not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg := location.ServerPool.GetConfig()
		json.NewEncoder(w).Encode(cfg)
	case http.MethodPut:
		var update pool.PoolConfig
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		location.ServerPool.UpdateConfig(update)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
