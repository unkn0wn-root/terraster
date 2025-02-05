package admin

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/unkn0wn-root/terraster/internal/config"
)

type ValidationError struct {
	Field string
	Error string
}

func (e ValidationError) String() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Error)
}

type Validator interface {
	Validate() []ValidationError
}

type BackendRequest struct {
	URL            string              `json:"url"`
	Weight         int                 `json:"weight"`
	MaxConnections int32               `json:"maxConnections"`
	SkipTLSVerify  bool                `json:"skipTLSVerify"`
	HealthCheck    *config.HealthCheck `json:"healthCheck"`
}

func (r BackendRequest) Validate() []ValidationError {
	var errors []ValidationError

	if r.URL == "" {
		errors = append(errors, ValidationError{"url", "required"})
	}
	if r.Weight <= 0 {
		errors = append(errors, ValidationError{"weight", "must be positive"})
	}
	if r.MaxConnections <= 0 {
		errors = append(errors, ValidationError{"maxConnections", "must be positive"})
	}

	if r.HealthCheck != nil {
		if errs := validateHealthCheck(r.HealthCheck); len(errs) > 0 {
			errors = append(errors, errs...)
		}
	}

	return errors
}

func validateHealthCheck(hc *config.HealthCheck) []ValidationError {
	var errors []ValidationError

	if hc.Type != "http" && hc.Type != "tcp" {
		errors = append(errors, ValidationError{"healthCheck.type", "must be 'http' or 'tcp'"})
	}
	if hc.Interval <= 0 {
		errors = append(errors, ValidationError{"healthCheck.interval", "must be positive"})
	}
	if hc.Timeout <= 0 {
		errors = append(errors, ValidationError{"healthCheck.timeout", "must be positive"})
	}
	if hc.Thresholds.Healthy <= 0 {
		errors = append(errors, ValidationError{"healthCheck.thresholds.healthy", "must be positive"})
	}
	if hc.Thresholds.Unhealthy <= 0 {
		errors = append(errors, ValidationError{"healthCheck.thresholds.unhealthy", "must be positive"})
	}

	return errors
}

// HTTP handler helper
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, v Validator) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "Invalid request payload: "+err.Error(), http.StatusBadRequest)
		return err
	}

	if errors := v.Validate(); len(errors) > 0 {
		msg := "Validation failed:"
		for _, err := range errors {
			msg += "\n" + err.String()
		}
		http.Error(w, msg, http.StatusBadRequest)
		return fmt.Errorf(msg)
	}

	return nil
}
