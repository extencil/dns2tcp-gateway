package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// tunnelResponse is the JSON response for tunnel creation.
type tunnelResponse struct {
	ID        string `json:"id"`
	Subdomain string `json:"subdomain"`
	Domain    string `json:"domain"`
	Mode      string `json:"mode"`
	Target    string `json:"target,omitempty"`
	RTCPPort  int    `json:"rtcp_port,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
}

// errorResponse is the JSON response for errors.
type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) handleCreateTCP(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	portStr := r.PathValue("port")

	if net.ParseIP(ip) == nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.writeError(w, http.StatusBadRequest, "invalid port number")
		return
	}

	sess, err := s.createSession(r, session.ModeTCP, ip, port)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.Domain)
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("DNS tunnel to %s will forward to %s", fqdn, sess.Target()),
	})
}

func (s *Server) handleCreateNS(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	portStr := r.PathValue("port")

	if net.ParseIP(ip) == nil {
		s.writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		s.writeError(w, http.StatusBadRequest, "invalid port number")
		return
	}

	sess, err := s.createSession(r, session.ModeNS, ip, port)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.Domain)
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("%s NS will point to %s:%d", fqdn, ip, port),
	})
}

func (s *Server) handleCreateRTCP(w http.ResponseWriter, r *http.Request) {
	sess, err := s.createSession(r, session.ModeRTCP, "", 0)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.Domain)
	s.writeJSON(w, http.StatusCreated, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Mode:      sess.Mode.String(),
		RTCPPort:  sess.RTCPPort,
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		Message:   fmt.Sprintf("use 'nc %s %d'. DNS tunnel to %s will terminate here.", s.cfg.GatewayIP, sess.RTCPPort, fqdn),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	subdomain := r.PathValue("subdomain")

	sess, ok := s.store.Get(r.Context(), subdomain)
	if !ok {
		s.writeError(w, http.StatusNotFound, "tunnel not found or expired")
		return
	}

	fqdn := fmt.Sprintf("%s.%s", sess.Subdomain, s.cfg.Domain)
	s.writeJSON(w, http.StatusOK, tunnelResponse{
		ID:        sess.ID,
		Subdomain: sess.Subdomain,
		Domain:    fqdn,
		Mode:      sess.Mode.String(),
		Target:    sess.Target(),
		RTCPPort:  sess.RTCPPort,
		CreatedAt: sess.CreatedAt.Format(time.RFC3339),
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	subdomain := r.PathValue("subdomain")

	if !s.store.Delete(r.Context(), subdomain) {
		s.writeError(w, http.StatusNotFound, "tunnel not found")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("tunnel %s deleted", subdomain),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"sessions": s.store.Count(),
	})
}

func (s *Server) createSession(r *http.Request, mode session.Mode, ip string, port int) (*session.Session, error) {
	// Check per-IP tunnel limit.
	ownerIP := extractClientIP(r)
	existing := s.store.ListByOwner(r.Context(), ownerIP)
	if len(existing) >= s.cfg.MaxTunnelsPerIP {
		return nil, fmt.Errorf("max tunnels per ip reached (%d)", s.cfg.MaxTunnelsPerIP)
	}

	id, err := session.GenerateID()
	if err != nil {
		return nil, fmt.Errorf("generating session id: %w", err)
	}

	subdomain, err := session.GenerateSubdomain()
	if err != nil {
		return nil, fmt.Errorf("generating subdomain: %w", err)
	}

	now := time.Now()
	sess := &session.Session{
		ID:         id,
		Subdomain:  subdomain,
		Mode:       mode,
		TargetIP:   ip,
		TargetPort: port,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.cfg.SessionTTL),
		OwnerIP:    ownerIP,
	}

	if err := s.store.Put(r.Context(), sess); err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return sess, nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Error("failed to encode json response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, errorResponse{Error: msg})
}

// extractClientIP gets the client IP from X-Forwarded-For or RemoteAddr.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (client IP).
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
