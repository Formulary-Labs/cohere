# cohere

`probe` says each file is valid. `cohere` says the files agree with each other. Point it at a program directory and a catalog — every control ID, evidence reference, risk linkage, and mapping entry is checked for resolution across the artifact set. Broken references fail with a named reason, one finding per defect.

```bash
go install github.com/Formulary-Labs/cohere/cmd/cohere@latest
```

## In the ecosystem

Formulary is a **pick-and-choose** suite of small, single-purpose CLIs. Install only the tools your workflow needs; each runs standalone. Shared contracts live in [`substrate`](https://github.com/Formulary-Labs/substrate). Optional Make pipelines (or an agent such as `regimen`) compose tools into a run — plug-and-play, not all-or-nothing.

**This tool:** program-level cross-artifact coherence — the set, not the file.
**Works with:** `probe` (file validity) upstream; `specimen` (findings as risk sources) downstream.
**Pipeline stage:** validate (set level).

## What it does

`cohere` loads a program directory of Formulary artifacts and the declared control catalog, then runs deterministic coherence checks:

| ID | Check | Severity |
|---|---|---|
| CH-01 | Control IDs referenced in the SoA, assessment, risk register, and evidence map exist in the catalog | blocking |
| CH-02 | Evidence references resolve to files or classified external links (PENDING placeholders warn) | blocking |
| CH-03 | Every catalog control appears in the SoA — no orphans | blocking |
| CH-04 | MappingDocument source/target IDs resolve against their catalogs | blocking |
| CH-05 | Risk control references resolve; accepted risks carry rationale | blocking |
| CH-06 | Assessment determinations consistent with citation quality | warning |
| CH-07 | Provenance hash-chain verifies | warning |

It is **read-only** and **deterministic**: identical program directory + catalog → identical report. `cohere` never makes compliance determinations — it reports broken references and structural inconsistencies.

## Recognized program files

Found by name, anywhere under `--program-dir`:

| File | Source tool | Consumed as |
|---|---|---|
| `soa.csv` | `formula` | control IDs, evidence references |
| `risks.json` | `specimen` | control linkages, evidence refs, accept rationales |
| `evidence-map.json` | — | `{control_id: evidence path or URL}` |
| `*-state.json` | `assay` | control responses, determinations, citation quality |
| `*.yaml` / `*.yml` | — | scanned for gemara `MappingDocument` (others skipped) |
| `logs/provenance.jsonl` | all tools | hash-chain verification (CH-07) |

Checks whose inputs are absent are skipped and listed in `checks_skipped` — a program with only a catalog is coherent by vacuity, not by accident.

## Usage

```bash
cohere --program-dir data/my-program/ \
       --catalog data/my-program/oscal/control-catalog.yaml \
       --format json \
       --output out/coherence.json
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `--program-dir` | Yes | Program directory of Formulary artifacts |
| `--catalog` | Yes | OSCAL catalog or gemara ControlCatalog (YAML/JSON) |
| `--provenance` | No | Provenance log path (default: `<program-dir>/logs/provenance.jsonl`) |
| `--format` | No | `json` (default) or `md` |
| `--output` | No | File path (stdout if empty) |
| `--quiet` | No | Suppress progress on stderr |
| `--version` | No | Print version and exit |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Coherent — no blocking findings (warnings allowed) |
| `1` | Blocking findings present — the artifact set disagrees |
| `2` | Tool error |

Use it as a CI gate: `cohere --program-dir data/p --catalog c.yaml && proceed`.

## Output

```json
{
  "verdict": "findings",
  "checks_run": ["CH-01", "CH-02", "CH-03", "CH-05", "CH-06"],
  "findings": [
    {
      "id": "CH-01-001",
      "severity": "blocking",
      "check": "CH-01",
      "artifact": "soa.csv",
      "control_id": "ac-99",
      "message": "SoA references control \"ac-99\" not present in catalog \"control-catalog.yaml\""
    }
  ],
  "stats": { "catalog_controls": 93, "soa_rows": 92, "blocking": 1 }
}
```

Findings are one-per-defect with stable IDs (`CH-01-003` = third CH-01 finding), so output pipes cleanly into `specimen ingest` as gap sources.

## Pipeline

```text
probe (each file) → cohere (the set) → challenge (the content) → exhibit
```

Run `probe` first so schema errors don't masquerade as coherence breaks; run `cohere` before packaging — `formula`/`compound` outputs and `assay` state are its primary inputs.

## License

Apache License 2.0
