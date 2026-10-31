package ui

import (
	"encoding/json"
	"net/http"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
)

type requestLogView struct {
	Enabled bool                  `json:"enabled"`
	Entries []client.RequestEntry `json:"entries"`
}

func (s *Server) getRequestLog(w http.ResponseWriter, r *http.Request) {
	view := requestLogView{Enabled: s.ctl.Settings().RequestLog, Entries: []client.RequestEntry{}}
	if c := s.ctl.Client(); c != nil {
		view.Entries = c.Requests().Snapshot()
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) putRequestLog(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request log setting")
		return
	}
	if err := s.ctl.SetRequestLogging(body.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.getRequestLog(w, r)
}

func (s *Server) clearRequestLog(w http.ResponseWriter, r *http.Request) {
	if c := s.ctl.Client(); c != nil {
		c.Requests().Clear()
	}
	s.getRequestLog(w, r)
}
