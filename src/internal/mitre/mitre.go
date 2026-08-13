// Package mitre maps WISP commands to MITRE ATT&CK techniques and renders
// reports (JSON inventory + MITRE Navigator layer).
package mitre

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Entry maps one command to a technique.
type Entry struct {
	Command   string `json:"command"`
	Technique string `json:"technique"` // ATT&CK ID, e.g. T1059
	Name      string `json:"name"`
	Tactic    string `json:"tactic"`
}

// Catalog is the command → technique mapping for the agent command surface.
var Catalog = []Entry{
	{"shell", "T1059", "Command and Scripting Interpreter", "Execution"},
	{"ishell", "T1059", "Command and Scripting Interpreter", "Execution"},
	{"upload", "T1105", "Ingress Tool Transfer", "Command and Control"},
	{"download", "T1005", "Data from Local System", "Collection"},
	{"exec-file", "T1204", "User Execution", "Execution"},
	{"ps", "T1057", "Process Discovery", "Discovery"},
	{"kill", "T1489", "Service Stop", "Impact"},
	{"sysinfo", "T1082", "System Information Discovery", "Discovery"},
	{"screenshot", "T1113", "Screen Capture", "Collection"},
	{"keylog", "T1056.001", "Input Capture: Keylogging", "Collection"},
	{"clipboard", "T1115", "Clipboard Data", "Collection"},
	{"portscan", "T1046", "Network Service Discovery", "Discovery"},
	{"netenum", "T1018", "Remote System Discovery", "Discovery"},
	{"socks", "T1090.001", "Proxy: Internal Proxy", "Command and Control"},
	{"portfwd", "T1090.001", "Proxy: Internal Proxy", "Command and Control"},
	{"shellcode", "T1055.001", "Process Injection: Dynamic-link Library Injection", "Defense Evasion"},
	{"spawn", "T1055.001", "Process Injection: Dynamic-link Library Injection", "Defense Evasion"},
	{"bof", "T1106", "Native API", "Execution"},
	{"token-steal", "T1134.001", "Access Token Manipulation: Token Impersonation/Theft", "Privilege Escalation"},
	{"getsystem", "T1134.001", "Access Token Manipulation: Token Impersonation/Theft", "Privilege Escalation"},
	{"persist", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"},
	{"hashdump", "T1003.002", "OS Credential Dumping: Security Account Manager", "Credential Access"},
	{"browser-creds", "T1555.003", "Credentials from Web Browsers", "Credential Access"},
	{"srdi", "T1055.012", "Process Injection: Process Hollowing", "Defense Evasion"},
	{"stager", "T1105", "Ingress Tool Transfer", "Command and Control"},
}

// ByCommand returns the entry for a command, if any.
func ByCommand(cmd string) (Entry, bool) {
	for _, e := range Catalog {
		if e.Command == cmd {
			return e, true
		}
	}
	return Entry{}, false
}

// Report is the full attack-coverage report.
type Report struct {
	Tool       string             `json:"tool"`
	Tactics    int                `json:"tactics"`
	Techniques int                `json:"techniques"`
	Commands   []Entry            `json:"commands"`
	ByTactic   map[string][]Entry `json:"by_tactic"`
}

// BuildReport assembles a report from the catalog.
func BuildReport() *Report {
	r := &Report{Tool: "RAT-WISP", ByTactic: map[string][]Entry{}}
	for _, e := range Catalog {
		r.Commands = append(r.Commands, e)
		r.ByTactic[e.Tactic] = append(r.ByTactic[e.Tactic], e)
	}
	r.Techniques = len(r.Commands)
	r.Tactics = len(r.ByTactic)
	return r
}

// JSON renders the report as JSON.
func (r *Report) JSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	return string(b), err
}

// NavigatorLayer renders the report as a MITRE ATT&CK Navigator layer (v4).
func (r *Report) NavigatorLayer() (string, error) {
	type navTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Tactic      string `json:"tactic"`
		Score       int    `json:"score"`
		Comment     string `json:"comment"`
		Enabled     bool   `json:"enabled"`
	}
	layer := map[string]any{
		"version":     "4.5",
		"name":        "RAT-WISP Coverage",
		"description": "Techniques exercised by RAT-WISP commands.",
		"domain":      "enterprise-attack",
		"techniques":  []navTechnique{},
		"gradient": map[string]any{
			"colors":   []string{"#ffffff", "#ff6666"},
			"minValue": 0,
			"maxValue": 1,
		},
	}
	var techniques []navTechnique
	for _, e := range Catalog {
		techniques = append(techniques, navTechnique{
			TechniqueID: e.Technique,
			Tactic:      tacticID(e.Tactic),
			Score:       1,
			Comment:     fmt.Sprintf("%s via %s", e.Name, e.Command),
			Enabled:     true,
		})
	}
	layer["techniques"] = techniques
	b, err := json.MarshalIndent(layer, "", "  ")
	return string(b), err
}

// tacticID maps a tactic display name to its ATT&CK short id.
func tacticID(name string) string {
	m := map[string]string{
		"Reconnaissance":       "reconnaissance",
		"Resource Development": "resource-development",
		"Initial Access":       "initial-access",
		"Execution":            "execution",
		"Persistence":          "persistence",
		"Privilege Escalation": "privilege-escalation",
		"Defense Evasion":      "defense-evasion",
		"Credential Access":    "credential-access",
		"Discovery":            "discovery",
		"Lateral Movement":     "lateral-movement",
		"Collection":           "collection",
		"Command and Control":  "command-and-control",
		"Exfiltration":         "exfiltration",
		"Impact":               "impact",
	}
	if v, ok := m[name]; ok {
		return v
	}
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

// SortedTactics returns tactic names in a stable order for HTML output.
func (r *Report) SortedTactics() []string {
	var out []string
	for t := range r.ByTactic {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
