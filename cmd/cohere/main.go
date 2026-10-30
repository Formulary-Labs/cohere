// cohere is the program-level coherence checker for the Formulary compliance
// micro-tools ecosystem.
//
// Usage:
//
//	cohere --program-dir data/my-program/ --catalog catalog.yaml
//
// Exit codes follow the Formulary contract:
//
//	0  coherent (warnings allowed)
//	1  blocking findings present
//	2  tool error
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Formulary-Labs/cohere/cohere"
	"github.com/Formulary-Labs/substrate/exit"
	"github.com/Formulary-Labs/substrate/provenance"
)

const version = "0.1.0"

func main() {
	programDir := flag.String("program-dir", "", "Program directory of Formulary artifacts (required)")
	catalog := flag.String("catalog", "", "Path to an OSCAL catalog or gemara ControlCatalog (required)")
	provenancePath := flag.String("provenance", "", "Provenance log path (default: <program-dir>/logs/provenance.jsonl)")
	fmtFlag := flag.String("format", "json", "Output format: json (default), md")
	output := flag.String("output", "", "Output file path (stdout if empty)")
	quiet := flag.Bool("quiet", false, "Suppress progress output")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("cohere version %s\n", version)
		return
	}
	if *programDir == "" || *catalog == "" {
		fmt.Fprintln(os.Stderr, "error: --program-dir and --catalog are required")
		os.Exit(exit.ToolError)
	}

	ps, err := cohere.LoadProgramSet(*programDir, *catalog, *provenancePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exit.ToolError)
	}

	report := cohere.Check(ps)

	var out []byte
	switch strings.ToLower(*fmtFlag) {
	case "json":
		out, err = json.MarshalIndent(report, "", "  ")
	case "md":
		out = []byte(report.ToMarkdown())
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported format %q (json or md)\n", *fmtFlag)
		os.Exit(exit.ToolError)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: rendering report: %v\n", err)
		os.Exit(exit.ToolError)
	}

	if *output != "" {
		if err := os.WriteFile(*output, out, 0o640); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
			os.Exit(exit.ToolError)
		}
	} else {
		fmt.Println(string(out))
	}

	if !*quiet && *output != "" {
		summary := fmt.Sprintf("%s — %d findings (%d blocking), checks: %s",
			report.Verdict, len(report.Findings), report.Stats["blocking"],
			strings.Join(report.ChecksRun, ", "))
		fmt.Fprintln(os.Stderr, summary)
	}

	// Provenance: record that this report was produced.
	_ = provenance.Write("", provenance.Entry{
		Spec:        "cohere/README.md",
		Output:      *output,
		OutputType:  "report",
		Program:     *programDir,
		Purpose:     fmt.Sprintf("coherence check: %d findings (%d blocking)", len(report.Findings), report.Stats["blocking"]),
		Reusability: provenance.Instance,
		QualityGate: gateFor(report),
		Tool:        "cohere",
		ToolVersion: version,
	})

	switch {
	case report.HasBlocking():
		os.Exit(exit.Validation)
	default:
		os.Exit(exit.OK)
	}
}

func gateFor(r *cohere.Report) provenance.QualityGate {
	if r.HasBlocking() {
		return provenance.FailedOnceCorrected
	}
	return provenance.Pass
}
