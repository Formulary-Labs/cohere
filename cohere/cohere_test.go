package cohere

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Formulary-Labs/substrate/provenance"
)

// copyDir copies the fixture program tree into a temp directory so tests can
// mutate it and generate provenance logs without touching testdata.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o640)
	})
	if err != nil {
		t.Fatalf("copying fixture: %v", err)
	}
}

func fixtureProgram(t *testing.T) (*ProgramSet, string) {
	t.Helper()
	dir := t.TempDir()
	copyDir(t, filepath.Join("testdata", "program"), dir)
	ps, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatalf("loading program set: %v", err)
	}
	return ps, dir
}

func findingsByCheck(r *Report) map[string][]Finding {
	by := map[string][]Finding{}
	for _, f := range r.Findings {
		by[f.Check] = append(by[f.Check], f)
	}
	return by
}

func TestCoherentProgram(t *testing.T) {
	ps, dir := fixtureProgram(t)

	// Generate a valid provenance log so CH-07 runs and passes.
	logPath := filepath.Join(dir, "logs", "provenance.jsonl")
	for i := 0; i < 3; i++ {
		if err := provenance.Write(logPath, provenance.Entry{
			Spec:        "test",
			Output:      "out.md",
			OutputType:  "report",
			Program:     "test-program",
			Purpose:     "fixture entry",
			Reusability: provenance.Instance,
			QualityGate: provenance.Pass,
			Tool:        "test",
		}); err != nil {
			t.Fatalf("writing provenance entry: %v", err)
		}
	}

	// Reload: the provenance log did not exist when the set was loaded.
	ps, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}

	report := Check(ps)
	if report.Verdict != VerdictCoherent {
		t.Fatalf("expected coherent verdict, got %q; findings: %+v", report.Verdict, report.Findings)
	}
	if report.HasBlocking() {
		t.Fatalf("expected no blocking findings, got %+v", report.Findings)
	}

	// CH-06 warning is expected: ac-3 is satisfied on architectural_description.
	by := findingsByCheck(report)
	if len(by["CH-06"]) != 1 {
		t.Fatalf("expected exactly one CH-06 warning (ac-3 satisfied on architectural_description), got %+v", by["CH-06"])
	}
	if by["CH-06"][0].ControlID != "ac-3" {
		t.Fatalf("expected CH-06 warning on ac-3, got %q", by["CH-06"][0].ControlID)
	}

	// All checks ran.
	want := map[string]bool{"CH-01": true, "CH-02": true, "CH-03": true, "CH-04": true, "CH-05": true, "CH-06": true, "CH-07": true}
	for _, c := range report.ChecksRun {
		delete(want, c)
	}
	if len(want) > 0 {
		t.Fatalf("checks not run: %v", want)
	}
}

func TestIncoherentProgram(t *testing.T) {
	ps, dir := fixtureProgram(t)

	// Break the SoA: unknown control ID + orphan (drop ac-3's row).
	soaPath := filepath.Join(dir, "soa.csv")
	soa := `Control ID,Title,Family,In Scope,Determination,Implementation Status,Implementation Summary,Owner,Inherited,Inherited From,Evidence Source,Exclusion Justification
ac-1,Policy and Procedures,Access Control,yes,satisfied,implemented,Policy documented.,security-team,,,evidence/policy.md,
ac-99,Ghost Control,Access Control,yes,satisfied,implemented,Does not exist.,security-team,,,evidence/missing.md,
`
	if err := os.WriteFile(soaPath, []byte(soa), 0o640); err != nil {
		t.Fatal(err)
	}

	// Break the risk register: accepted risk without rationale.
	risksPath := filepath.Join(dir, "risks.json")
	risks := `{
  "risks": [
    {"id": "RISK-009", "status": "accepted", "control_id": "ac-99", "evidence_ref": "evidence/nowhere.md"}
  ]
}`
	if err := os.WriteFile(risksPath, []byte(risks), 0o640); err != nil {
		t.Fatal(err)
	}

	// Reload: the program set was loaded before the files were broken.
	ps, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}

	report := Check(ps)
	if report.Verdict != VerdictFindings {
		t.Fatalf("expected findings verdict, got %q", report.Verdict)
	}
	if !report.HasBlocking() {
		t.Fatalf("expected blocking findings, got %+v", report.Findings)
	}

	by := findingsByCheck(report)

	// CH-01: ac-99 in SoA and risks.
	if len(by["CH-01"]) != 2 {
		t.Fatalf("expected 2 CH-01 findings (SoA + risk), got %+v", by["CH-01"])
	}
	// CH-02: two unresolvable evidence files (SoA evidence/missing.md, risk evidence/nowhere.md).
	if len(by["CH-02"]) != 2 {
		t.Fatalf("expected 2 CH-02 findings, got %+v", by["CH-02"])
	}
	for _, f := range by["CH-02"] {
		if f.Severity != SeverityBlocking {
			t.Fatalf("expected blocking CH-02 findings, got %+v", f)
		}
	}
	// CH-03: ac-2 and ac-3 orphaned in the SoA.
	if len(by["CH-03"]) != 2 {
		t.Fatalf("expected 2 CH-03 orphan findings (ac-2, ac-3), got %+v", by["CH-03"])
	}
	// CH-05: accepted risk without rationale.
	if len(by["CH-05"]) != 1 {
		t.Fatalf("expected 1 CH-05 finding, got %+v", by["CH-05"])
	}
}

func TestMappingIDResolution(t *testing.T) {
	_, dir := fixtureProgram(t)

	// Mapping with a source ID that is not in the catalog.
	badMapping := `title: Broken Mapping
metadata:
  id: map-bad-001
  type: MappingDocument
  gemara-version: "1.0"
  description: Fixture with an unknown source control.
source-reference:
  entry-type: Control
  reference-id: test-framework
target-reference:
  entry-type: Control
  reference-id: peer-framework
mappings:
  - id: map-bad
    source: ac-77
    relationship: equivalent
    targets:
      - entry-id: peer-1
        strength: 5
`
	if err := os.WriteFile(filepath.Join(dir, "broken-mapping.yaml"), []byte(badMapping), 0o640); err != nil {
		t.Fatal(err)
	}

	// Reload to pick up the new mapping file.
	ps2, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}

	report := Check(ps2)
	by := findingsByCheck(report)
	var hit bool
	for _, f := range by["CH-04"] {
		if f.ControlID == "ac-77" && f.Severity == SeverityBlocking {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected a blocking CH-04 finding for ac-77, got %+v", by["CH-04"])
	}
}

func TestProvenanceTamperDetection(t *testing.T) {
	_, dir := fixtureProgram(t)

	logPath := filepath.Join(dir, "logs", "provenance.jsonl")
	if err := provenance.Write(logPath, provenance.Entry{
		Spec: "test", Output: "out.md", OutputType: "report", Program: "p",
		Purpose: "entry one", Reusability: provenance.Instance,
		QualityGate: provenance.Pass, Tool: "test",
	}); err != nil {
		t.Fatal(err)
	}

	// Tamper: rewrite the purpose field without recomputing the digest.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), "entry one", "entry TAMPERED", 1)
	if tampered == string(data) {
		t.Fatal("tamper replacement did not apply")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o640); err != nil {
		t.Fatal(err)
	}

	// Reload: the provenance log did not exist when the set was loaded.
	ps2, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}

	report := Check(ps2)
	by := findingsByCheck(report)
	if len(by["CH-07"]) == 0 {
		t.Fatalf("expected CH-07 findings for tampered provenance, got %+v", report.Findings)
	}
	for _, f := range by["CH-07"] {
		if f.Severity != SeverityWarning {
			t.Fatalf("expected CH-07 to be warning severity, got %+v", f)
		}
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	ps, _ := fixtureProgram(t)
	report := Check(ps)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Verdict != report.Verdict || len(back.Findings) != len(report.Findings) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", back, report)
	}
	if !strings.Contains(report.ToMarkdown(), "cohere results") {
		t.Fatal("markdown output missing header")
	}
}

func TestSkippedChecks(t *testing.T) {
	dir := t.TempDir()
	// Empty program directory: everything except CH-01 (catalog-only) skips.
	if err := os.WriteFile(filepath.Join(dir, "placeholder.txt"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadProgramSet(dir, filepath.Join("testdata", "test-framework-catalog.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	report := Check(ps)
	if report.Verdict != VerdictCoherent {
		t.Fatalf("empty program should be coherent, got %q", report.Verdict)
	}
	for _, c := range report.ChecksRun {
		if c == "CH-02" || c == "CH-03" || c == "CH-05" || c == "CH-06" || c == "CH-07" {
			t.Fatalf("expected %s to be skipped on an empty program", c)
		}
	}
}
