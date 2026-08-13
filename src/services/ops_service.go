package services

import (
	"encoding/json"
	"fmt"
	oslib "os"
	"path/filepath"
	"time"

	"github.com/user/wisp/internal/db"
	"github.com/user/wisp/internal/mitre"
)

// OpsService manages the operational data (targets, credentials, loot) and
// report generation.
type OpsService struct {
	serverSvc *ServerService
}

// NewOpsService creates a new OpsService.
func NewOpsService(serverSvc *ServerService) *OpsService {
	return &OpsService{serverSvc: serverSvc}
}

// ---- Targets ----

// AddTarget adds or updates a target by IP.
func (os *OpsService) AddTarget(ip, hostname, note string) (*db.TargetRow, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	if hostname == "" {
		hostname = ip
	}
	return os.serverSvc.GetDB().AddTarget(ip, hostname, "", note)
}

// ListTargets returns all targets.
func (os *OpsService) ListTargets() ([]db.TargetRow, error) {
	return os.serverSvc.GetDB().ListTargets()
}

// DeleteTarget removes a target.
func (os *OpsService) DeleteTarget(id string) error {
	return os.serverSvc.GetDB().DeleteTarget(id)
}

// ---- Credentials ----

// AddCredential stores a credential.
func (os *OpsService) AddCredential(target, username, password, secret, kind, note string) (*db.CredRow, error) {
	if username == "" && password == "" && secret == "" {
		return nil, fmt.Errorf("nothing to store (username/password/secret all empty)")
	}
	return os.serverSvc.GetDB().AddCredential(target, username, password, secret, kind, note)
}

// ListCredentials returns all credentials (secrets decrypted).
func (os *OpsService) ListCredentials() ([]db.CredRow, error) {
	return os.serverSvc.GetDB().ListCredentials()
}

// DeleteCredential removes a credential.
func (os *OpsService) DeleteCredential(id string) error {
	return os.serverSvc.GetDB().DeleteCredential(id)
}

// ---- Loot ----

// AddLoot stores a loot item (e.g. "save this output as loot").
func (os *OpsService) AddLoot(sessionID, name, kind, data string) (*db.LootRow, error) {
	if name == "" {
		name = fmt.Sprintf("loot-%d", time.Now().Unix())
	}
	return os.serverSvc.GetDB().AddLoot(sessionID, name, kind, data)
}

// ListLoot returns loot items.
func (os *OpsService) ListLoot(limit int) ([]db.LootRow, error) {
	return os.serverSvc.GetDB().ListLoot(limit)
}

// DeleteLoot removes a loot item.
func (os *OpsService) DeleteLoot(id string) error {
	return os.serverSvc.GetDB().DeleteLoot(id)
}

// ---- Reports ----

// MitreReport returns the JSON MITRE ATT&CK coverage report.
func (os *OpsService) MitreReport() (string, error) {
	return mitre.BuildReport().JSON()
}

// MitreNavigator returns the MITRE ATT&CK Navigator layer JSON.
func (os *OpsService) MitreNavigator() (string, error) {
	return mitre.BuildReport().NavigatorLayer()
}

// MitreHTML renders a standalone HTML coverage report.
func (os *OpsService) MitreHTML() (string, error) {
	r := mitre.BuildReport()
	nav, err := r.NavigatorLayer()
	if err != nil {
		return "", err
	}
	navJSON, _ := json.Marshal(nav)
	// Simple self-contained HTML page.
	html := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>RAT-WISP MITRE Report</title>
<style>body{font-family:monospace;background:#111;color:#ddd;padding:20px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:6px;text-align:left}
th{background:#222}tr:hover{background:#1a1a1a}</style></head><body>
<h1>RAT-WISP MITRE ATT&amp;CK Coverage</h1>
<p>Tactics: ` + fmt.Sprintf("%d", r.Tactics) + ` &middot; Techniques: ` + fmt.Sprintf("%d", r.Techniques) + `</p>
<table><tr><th>Tactic</th><th>Technique</th><th>Name</th><th>Command</th></tr>`
	for _, t := range r.SortedTactics() {
		for _, e := range r.ByTactic[t] {
			html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", t, e.Technique, e.Name, e.Command)
		}
	}
	html += `</table></body></html>`
	_ = navJSON
	return html, nil
}

// ExportReport writes a report to disk and returns the path.
func (os *OpsService) ExportReport(format string) (string, error) {
	var content string
	switch format {
	case "json":
		c, err := os.MitreReport()
		if err != nil {
			return "", err
		}
		content = c
	case "navigator":
		c, err := os.MitreNavigator()
		if err != nil {
			return "", err
		}
		content = c
	case "html", "":
		c, err := os.MitreHTML()
		if err != nil {
			return "", err
		}
		content = c
		format = "html"
	default:
		return "", fmt.Errorf("unsupported report format: %s", format)
	}
	dir := filepath.Join(exeDir(), "reports")
	if err := oslib.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("mitre_%s.%s", time.Now().Format("20060102_150405"), format))
	if err := oslib.WriteFile(path, []byte(content), 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ---- Canaries (burn detection) ----

// ListCanaries returns all registered burn-detection tokens.
func (os *OpsService) ListCanaries() ([]db.CanaryRow, error) {
	if os.serverSvc.GetDB() == nil {
		return nil, fmt.Errorf("no database")
	}
	return os.serverSvc.GetDB().ListCanaries(500)
}

// GetCanary returns a single canary by token.
func (os *OpsService) GetCanary(token string) (*db.CanaryRow, error) {
	if os.serverSvc.GetDB() == nil {
		return nil, fmt.Errorf("no database")
	}
	return os.serverSvc.GetDB().GetCanary(token)
}
