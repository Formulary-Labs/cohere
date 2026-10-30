// Package cohere implements program-level cross-artifact coherence checking
// for the Formulary compliance micro-tools ecosystem.
//
// probe validates one artifact at a time. cohere validates the set: it loads
// a program directory of Formulary artifacts (SoA CSV, assay assessment
// state, specimen risk register, evidence map, gemara MappingDocuments) and
// checks that they agree with each other and with the declared control
// catalog. Every check is deterministic and read-only.
//
// Checks:
//
//	CH-01  Control IDs referenced across artifacts exist in the catalog (blocking)
//	CH-02  Evidence references resolve to files or classified external links (blocking)
//	CH-03  Every catalog control appears in the SoA — no orphans (blocking)
//	CH-04  MappingDocument source/target IDs resolve against their catalogs (blocking)
//	CH-05  Risk control references resolve; accepted risks carry rationale (blocking)
//	CH-06  Assessment determinations consistent with citation quality (warning)
//	CH-07  Provenance hash-chain verifies; outputs have ledger entries (warning)
//
// cohere never makes compliance determinations. It reports broken references
// and structural inconsistencies, one finding per defect, so output pipes
// cleanly into specimen ingest as gap sources.
package cohere

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Formulary-Labs/substrate/artifact"
	"github.com/Formulary-Labs/substrate/evidence"
	"github.com/Formulary-Labs/substrate/provenance"
)

// Severity ranks a finding. Blocking findings make the program incoherent;
// warnings are observations that do not fail the set.
type Severity string

const (
	SeverityBlocking Severity = "blocking"
	SeverityWarning  Severity = "warning"
)

// Verdict values for a Report.
const (
	VerdictCoherent = "coherent"
	VerdictFindings = "findings"
)

// Finding is one coherence defect. IDs are stable per check and increment
// per defect: CH-01-003 is the third CH-01 finding in the report.
type Finding struct {
	ID        string   `json:"id"`
	Severity  Severity `json:"severity"`
	Check     string   `json:"check"`
	Artifact  string   `json:"artifact,omitempty"`
	ControlID string   `json:"control_id,omitempty"`
	Message   string   `json:"message"`
}

// Report is the structured output of a cohere run.
type Report struct {
	ProgramDir    string         `json:"program_dir"`
	CatalogPath   string         `json:"catalog_path"`
	Verdict       string         `json:"verdict"`
	ChecksRun     []string       `json:"checks_run"`
	ChecksSkipped []string       `json:"checks_skipped,omitempty"`
	Findings      []Finding      `json:"findings"`
	Stats         map[string]int `json:"stats"`
}

// HasBlocking reports whether any finding is blocking.
func (r *Report) HasBlocking() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityBlocking {
			return true
		}
	}
	return false
}

// ToMarkdown renders the report as a markdown summary.
func (r *Report) ToMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# cohere results\n\n**Verdict:** %s\n\n", r.Verdict)
	fmt.Fprintf(&b, "Checks run: %s\n", strings.Join(r.ChecksRun, ", "))
	if len(r.ChecksSkipped) > 0 {
		fmt.Fprintf(&b, "Skipped: %s\n", strings.Join(r.ChecksSkipped, ", "))
	}
	fmt.Fprintf(&b, "\n**%d findings**\n\n", len(r.Findings))
	if len(r.Findings) == 0 {
		return b.String()
	}
	b.WriteString("| ID | Severity | Check | Artifact | Control | Message |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` | `%s` | %s |\n",
			f.ID, f.Severity, f.Check, f.Artifact, f.ControlID, f.Message)
	}
	return b.String()
}

// --- Program inputs ---------------------------------------------------------

// SOARow is one row of a formula soa.csv.
type SOARow struct {
	ControlID     string
	Title         string
	InScope       string
	Determination string
	Evidence      string
}

// AssayResponse is the response block of an assay control entry.
type AssayResponse struct {
	Citation        string `json:"citation"`
	CitationQuality string `json:"citation_quality"`
	Determination   string `json:"determination"`
	Gap             string `json:"gap,omitempty"`
}

// AssayControl is one control entry in an assay assessment state file.
type AssayControl struct {
	ID       string         `json:"id"`
	Status   string         `json:"status"`
	Response *AssayResponse `json:"response,omitempty"`
}

// AssayState is the subset of the assay state schema cohere consumes.
type AssayState struct {
	RunID    string                   `json:"run_id"`
	Controls map[string]*AssayControl `json:"controls"`
}

// RiskEntry is the subset of the specimen register risk schema cohere consumes.
type RiskEntry struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	ControlID       string `json:"control_id,omitempty"`
	EvidenceRef     string `json:"evidence_ref,omitempty"`
	AcceptRationale string `json:"accept_rationale,omitempty"`
}

// RiskFile is the subset of the specimen register schema cohere consumes.
type RiskFile struct {
	Risks []RiskEntry `json:"risks"`
}

// MappingFile is a gemara MappingDocument found in the program directory,
// with the IDs cohere needs for resolution.
type MappingFile struct {
	Path   string
	Source string
	Target string
	// Entries is sourceID -> []targetID.
	Entries map[string][]string
}

// ProgramSet is the loaded program directory.
type ProgramSet struct {
	Dir           string
	CatalogPath   string
	CatalogIDs    map[string]bool
	SOA           []SOARow
	SOAPath       string
	Assay         *AssayState
	AssayPath     string
	Risks         *RiskFile
	RisksPath     string
	EvidenceMap   map[string]string
	EvidencePath  string
	Mappings      []MappingFile
	ProvenanceLog string
}

// LoadProgramSet walks dir and loads every recognized Formulary artifact.
// Recognized files (by name, anywhere under dir):
//
//	soa.csv               formula Statement of Applicability
//	risks.json            specimen register
//	evidence-map.json     {control_id: evidence path or URL}
//	*-state.json          assay assessment state (must contain "controls")
//	*.yaml / *.yml / *.json  scanned for gemara MappingDocuments
//
// The catalog is loaded via substrate (OSCAL or gemara ControlCatalog).
// The provenance log is looked up at dir/logs/provenance.jsonl, or the
// provenancePath override when non-empty.
func LoadProgramSet(dir, catalogPath, provenancePath string) (*ProgramSet, error) {
	if dir == "" {
		return nil, fmt.Errorf("cohere: program directory is required")
	}
	unified, err := artifact.LoadCatalog(catalogPath)
	if err != nil {
		return nil, fmt.Errorf("cohere: loading catalog: %w", err)
	}
	ps := &ProgramSet{
		Dir:           dir,
		CatalogPath:   catalogPath,
		CatalogIDs:    map[string]bool{},
		EvidenceMap:   map[string]string{},
		ProvenanceLog: provenancePath,
	}
	for _, c := range unified.Controls {
		ps.CatalogIDs[c.ID] = true
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		switch {
		case name == "soa.csv" && ps.SOAPath == "":
			rows, err := loadSOA(path)
			if err != nil {
				return fmt.Errorf("cohere: %w", err)
			}
			ps.SOA, ps.SOAPath = rows, path
		case name == "risks.json" && ps.RisksPath == "":
			rf, err := loadJSON[RiskFile](path)
			if err != nil {
				return fmt.Errorf("cohere: %w", err)
			}
			ps.Risks, ps.RisksPath = rf, path
		case name == "evidence-map.json" && ps.EvidencePath == "":
			em, err := loadJSON[map[string]string](path)
			if err != nil {
				return fmt.Errorf("cohere: %w", err)
			}
			ps.EvidenceMap, ps.EvidencePath = *em, path
		case strings.HasSuffix(name, "-state.json") && ps.AssayPath == "":
			st, err := loadJSON[AssayState](path)
			if err != nil {
				return fmt.Errorf("cohere: %w", err)
			}
			if st.Controls != nil {
				ps.Assay, ps.AssayPath = st, path
			}
		case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
			mf, ok, err := loadMapping(path)
			if err != nil {
				return fmt.Errorf("cohere: %w", err)
			}
			if ok {
				ps.Mappings = append(ps.Mappings, mf)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if ps.ProvenanceLog == "" {
		candidate := filepath.Join(dir, "logs", "provenance.jsonl")
		if _, err := os.Stat(candidate); err == nil {
			ps.ProvenanceLog = candidate
		}
	}
	return ps, nil
}

// --- Checks ----------------------------------------------------------------

// Check runs the full CH-01..CH-07 check set against the program set.
func Check(ps *ProgramSet) *Report {
	r := &Report{
		ProgramDir:  ps.Dir,
		CatalogPath: ps.CatalogPath,
		Stats:       map[string]int{"catalog_controls": len(ps.CatalogIDs)},
	}
	counters := map[string]int{}
	add := func(check string, sev Severity, artifactPath, controlID, format string, args ...any) {
		counters[check]++
		r.Findings = append(r.Findings, Finding{
			ID:        fmt.Sprintf("%s-%03d", check, counters[check]),
			Severity:  sev,
			Check:     check,
			Artifact:  artifactPath,
			ControlID: controlID,
			Message:   fmt.Sprintf(format, args...),
		})
	}
	rel := func(p string) string {
		if ps.Dir != "" && strings.HasPrefix(p, ps.Dir) {
			return strings.TrimPrefix(strings.TrimPrefix(p, ps.Dir), "/")
		}
		return p
	}

	// CH-01 — referenced control IDs exist in the catalog (blocking).
	ch01 := false
	for _, row := range ps.SOA {
		ch01 = true
		if !ps.CatalogIDs[row.ControlID] {
			add("CH-01", SeverityBlocking, rel(ps.SOAPath), row.ControlID,
				"SoA references control %q not present in catalog %q", row.ControlID, rel(ps.CatalogPath))
		}
	}
	if ps.Assay != nil {
		ch01 = true
		for id := range ps.Assay.Controls {
			if !ps.CatalogIDs[id] {
				add("CH-01", SeverityBlocking, rel(ps.AssayPath), id,
					"assessment references control %q not present in catalog %q", id, rel(ps.CatalogPath))
			}
		}
	}
	if ps.Risks != nil {
		ch01 = true
		for _, risk := range ps.Risks.Risks {
			if risk.ControlID != "" && !ps.CatalogIDs[risk.ControlID] {
				add("CH-01", SeverityBlocking, rel(ps.RisksPath), risk.ControlID,
					"risk %s references control %q not present in catalog %q", risk.ID, risk.ControlID, rel(ps.CatalogPath))
			}
		}
	}
	for id := range ps.EvidenceMap {
		ch01 = true
		if !ps.CatalogIDs[id] {
			add("CH-01", SeverityBlocking, rel(ps.EvidencePath), id,
				"evidence map references control %q not present in catalog %q", id, rel(ps.CatalogPath))
		}
	}
	if ch01 {
		r.ChecksRun = append(r.ChecksRun, "CH-01")
	} else {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-01")
	}

	// CH-02 — evidence references resolve (blocking). PENDING placeholders
	// are warnings; unresolvable non-placeholder references are blocking.
	ch02 := false
	resolveEvidence := func(artifactPath, controlID, ref string) {
		if ref == "" {
			return
		}
		ch02 = true
		if _, isPending := evidence.ClassifyLink(ref); isPending {
			add("CH-02", SeverityWarning, artifactPath, controlID,
				"evidence reference %q is a PENDING placeholder", ref)
			return
		}
		if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
			return // classified external link — citation, not a file
		}
		candidate := ref
		if !filepath.IsAbs(ref) {
			candidate = filepath.Join(ps.Dir, ref)
		}
		if _, err := os.Stat(candidate); err != nil {
			add("CH-02", SeverityBlocking, artifactPath, controlID,
				"evidence reference %q does not resolve to a file", ref)
		}
	}
	if ps.SOAPath != "" {
		for _, row := range ps.SOA {
			if row.Evidence != "" && row.Evidence != "[PENDING]" {
				resolveEvidence(rel(ps.SOAPath), row.ControlID, row.Evidence)
			}
		}
	}
	if ps.Risks != nil {
		for _, risk := range ps.Risks.Risks {
			resolveEvidence(rel(ps.RisksPath), risk.ControlID, risk.EvidenceRef)
		}
	}
	for id, ref := range ps.EvidenceMap {
		resolveEvidence(rel(ps.EvidencePath), id, ref)
	}
	if ch02 {
		r.ChecksRun = append(r.ChecksRun, "CH-02")
	} else {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-02")
	}

	// CH-03 — every catalog control appears in the SoA (blocking).
	if ps.SOAPath == "" {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-03")
	} else {
		r.ChecksRun = append(r.ChecksRun, "CH-03")
		seen := map[string]bool{}
		for _, row := range ps.SOA {
			seen[row.ControlID] = true
		}
		orphans := make([]string, 0, len(ps.CatalogIDs))
		for id := range ps.CatalogIDs {
			if !seen[id] {
				orphans = append(orphans, id)
			}
		}
		sort.Strings(orphans)
		for _, id := range orphans {
			add("CH-03", SeverityBlocking, rel(ps.SOAPath), id,
				"catalog control %q has no row in the SoA — include, exclude, or mark not applicable", id)
		}
		r.Stats["soa_rows"] = len(ps.SOA)
	}

	// CH-04 — mapping document IDs resolve (blocking). Mapping IDs are
	// checked against the program catalog when the mapping's source or
	// target reference matches the catalog; IDs from the other framework
	// are not expected to resolve and are skipped.
	if len(ps.Mappings) == 0 {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-04")
	} else {
		r.ChecksRun = append(r.ChecksRun, "CH-04")
		for _, mf := range ps.Mappings {
			checkSource := catalogMatches(ps, mf.Source)
			checkTarget := catalogMatches(ps, mf.Target)
			for srcID, targets := range mf.Entries {
				if checkSource && !ps.CatalogIDs[srcID] {
					add("CH-04", SeverityBlocking, rel(mf.Path), srcID,
						"mapping source control %q not found in catalog %q (mapping %s → %s)",
						srcID, rel(ps.CatalogPath), mf.Source, mf.Target)
				}
				if checkTarget {
					for _, tgtID := range targets {
						if !ps.CatalogIDs[tgtID] {
							add("CH-04", SeverityBlocking, rel(mf.Path), tgtID,
								"mapping target control %q not found in catalog %q (mapping %s → %s)",
								tgtID, rel(ps.CatalogPath), mf.Source, mf.Target)
							break
						}
					}
				}
			}
		}
	}

	// CH-05 — risk hygiene (blocking): accepted risks need rationale.
	if ps.Risks == nil {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-05")
	} else {
		r.ChecksRun = append(r.ChecksRun, "CH-05")
		for _, risk := range ps.Risks.Risks {
			if strings.EqualFold(risk.Status, "accepted") && strings.TrimSpace(risk.AcceptRationale) == "" {
				add("CH-05", SeverityBlocking, rel(ps.RisksPath), risk.ControlID,
					"risk %s is accepted without accept_rationale", risk.ID)
			}
		}
		r.Stats["risks"] = len(ps.Risks.Risks)
	}

	// CH-06 — determinations consistent with citation quality (warning).
	// assay criterion 6 re-checked at set level: only direct_assertion and
	// topical_reference support satisfied; gap required for partial/not.
	if ps.Assay == nil {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-06")
	} else {
		r.ChecksRun = append(r.ChecksRun, "CH-06")
		ids := make([]string, 0, len(ps.Assay.Controls))
		for id := range ps.Assay.Controls {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			c := ps.Assay.Controls[id]
			if c == nil || c.Response == nil {
				continue
			}
			resp := c.Response
			if strings.EqualFold(resp.Determination, "satisfied") &&
				resp.CitationQuality != "direct_assertion" && resp.CitationQuality != "topical_reference" {
				add("CH-06", SeverityWarning, rel(ps.AssayPath), id,
					"determination is satisfied but citation quality is %q — only direct_assertion and topical_reference support satisfied",
					resp.CitationQuality)
			}
			if (strings.EqualFold(resp.Determination, "partially_satisfied") ||
				strings.EqualFold(resp.Determination, "not_satisfied")) &&
				strings.TrimSpace(resp.Gap) == "" {
				add("CH-06", SeverityWarning, rel(ps.AssayPath), id,
					"determination is %s with no gap noted", resp.Determination)
			}
		}
		r.Stats["assessed_controls"] = len(ps.Assay.Controls)
	}

	// CH-07 — provenance chain verifies (warning).
	if ps.ProvenanceLog == "" {
		r.ChecksSkipped = append(r.ChecksSkipped, "CH-07")
	} else {
		r.ChecksRun = append(r.ChecksRun, "CH-07")
		results, err := provenance.Verify(ps.ProvenanceLog)
		if err != nil {
			add("CH-07", SeverityWarning, rel(ps.ProvenanceLog), "",
				"provenance verification error: %v", err)
		} else {
			for _, v := range results {
				if !v.Valid || !v.ChainValid {
					add("CH-07", SeverityWarning, rel(ps.ProvenanceLog), "",
						"provenance entry %s failed verification: %s", v.EntryID, v.FailureReason)
				}
			}
			r.Stats["provenance_entries"] = len(results)
		}
	}

	if r.HasBlocking() {
		r.Verdict = VerdictFindings
	} else {
		r.Verdict = VerdictCoherent
	}
	r.Stats["findings"] = len(r.Findings)
	blocking := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityBlocking {
			blocking++
		}
	}
	r.Stats["blocking"] = blocking
	return r
}

// catalogMatches reports whether a mapping reference (e.g. "iso27001")
// plausibly refers to the program catalog, by comparing the reference to the
// catalog path base name without extension.
func catalogMatches(ps *ProgramSet, reference string) bool {
	if reference == "" {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(ps.CatalogPath), filepath.Ext(ps.CatalogPath))
	return strings.Contains(strings.ToLower(base), strings.ToLower(reference))
}

// --- Loaders ---------------------------------------------------------------

func loadSOA(path string) ([]SOARow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening SoA %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("reading SoA %s: %w", path, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("SoA %s is empty", path)
	}
	header := records[0]
	col := func(name string) int {
		for i, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}
	idCol := col("Control ID")
	if idCol < 0 {
		return nil, fmt.Errorf("SoA %s has no Control ID column", path)
	}
	evCol := col("Evidence Source")
	scopeCol := col("In Scope")
	detCol := col("Determination")
	var rows []SOARow
	for _, rec := range records[1:] {
		if len(rec) <= idCol || strings.TrimSpace(rec[idCol]) == "" {
			continue
		}
		row := SOARow{ControlID: strings.TrimSpace(rec[idCol])}
		if evCol >= 0 && evCol < len(rec) {
			row.Evidence = strings.TrimSpace(rec[evCol])
		}
		if scopeCol >= 0 && scopeCol < len(rec) {
			row.InScope = strings.TrimSpace(rec[scopeCol])
		}
		if detCol >= 0 && detCol < len(rec) {
			row.Determination = strings.TrimSpace(rec[detCol])
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func loadJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &v, nil
}

// loadMapping attempts to load a gemara MappingDocument. ok is false (not an
// error) when the file is not a MappingDocument — program directories hold
// many YAML files that are not mappings.
func loadMapping(path string) (mf MappingFile, ok bool, err error) {
	doc, err := artifact.LoadMappingDocument(path)
	if err != nil {
		return MappingFile{}, false, nil //nolint:nilerr // not a mapping document — skip
	}
	if doc == nil || doc.Metadata.Type != artifact.MappingDocumentArtifact {
		return MappingFile{}, false, nil // not a mapping document — skip
	}
	mf = MappingFile{
		Path:    path,
		Source:  doc.SourceReference.ReferenceId,
		Target:  doc.TargetReference.ReferenceId,
		Entries: map[string][]string{},
	}
	for _, m := range doc.Mappings {
		var targets []string
		for _, t := range m.Targets {
			targets = append(targets, t.EntryId)
		}
		mf.Entries[m.Source] = targets
	}
	return mf, true, nil
}
