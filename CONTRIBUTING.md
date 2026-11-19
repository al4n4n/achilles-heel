# Contributing research entries

Each published study has a stable directory with a README and a `meta.json`. Edit the study and its metadata together. The generator uses the metadata to build the [research index](INDEX.md), the [JSON catalog](index.json), the root README tables and links, and a citation at the end of each study.

## Entry metadata

Use the [JSON Schema](schemas/research-entry.schema.json) as the format contract. The [Chrome entry](CVE-2026-125350/meta.json) is a complete example. The [paired PHP entry](CVE-2026-109618-and-CVE-2026-109619/meta.json) shows how one study can cover two CVEs.

| Field | What to record |
|---|---|
| `ids` | Array of identifiers, primary ID first. Supported forms include CVE, GHSA, ZDI-CAN, and a lowercase hyphenated local slug for research awaiting a public identifier. When an ID is assigned later, add it and preserve the directory path so existing citations keep working. |
| `title` | A one-line research title suitable for a citation. |
| `affected_product` | The name of the affected product or component. Put tested versions and configuration details in the README. |
| `impact_achieved` | A short summary of the outcome documented in the study. Include qualifications such as an emulated target or instrumented build. Use `null` when the entry lacks evidence for an observed outcome. Record broader advisory claims separately in the README. |
| `authors` | The researchers who authored this study, in citation order. Use a consistent public name or handle. Credit the original vulnerability reporter separately in the README when applicable. |
| `added` | The calendar date the study was added to this repository, formatted as YYYY-MM-DD. Keep this date when making corrections. |
| `cvss` | The score from 0 to 10 stated in the study, or `null` if unavailable. Cite the score's source in the README. |
| `writeup` | Direct URL of the research article, or `null` until one is published. The directory remains citable in either case. |
| `type` | Optional classification of the affected component, such as `client` or `library`. |

## Generate and review

1. Add or update the entry README and metadata. Keep the human-authored analysis outside the generated citation markers.
2. Install the validator in your Python environment with `python3 -m pip install -r scripts/requirements.txt`.
3. Run the following from the repository root.

   ```sh
   python3 scripts/build_index.py
   python3 scripts/build_index.py --check
   python3 scripts/check_links.py
   ```

4. Review the diff. Check that each citation credits the study authors, links to the right article, and preserves all identifiers. Include the generated files in the same commit. CI runs the checks on pushes and pull requests.

## Catalog and citations

The root `index.json` has a numeric `schema_version` and an `entries` array, ordered by date added, newest first. Each record contains the entry metadata plus the directory name (`dir`) and absolute citation URL (`entry_url`). A paired study appears once and carries both identifiers. Entries awaiting a CVE appear in the catalog under their existing IDs.

To cite one study, copy **Cite this research** from its README. For a citation to the exact files examined, use GitHub's permalink for that revision. For the whole collection, see [CITATION.cff](CITATION.cff).
