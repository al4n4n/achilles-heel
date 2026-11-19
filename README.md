# achilles-heel

Every application has one. This repository documents them, with proof.

Each directory covers one vulnerability, or a pair disclosed together: a local lab that builds the affected software, a proof of concept that reproduces the bug through the real attack surface, and, where the research produced them, network captures, raw evidence and experimental detection rules. The point of all of it is defense: detection rules and captures that the security community can build on.

## Latest critical research

<!-- research-table:start -->
The 10 most recently added critical entries (CVSS 9.0 or higher), newest first. All 19 entries, every severity: [INDEX.md](INDEX.md).

| ID | Vulnerability | CVSS | Included |
|---|---|---|---|
| [CVE-2026-116779](CVE-2026-116779/) | FreeSWITCH SIP MESSAGE command execution | 9.8 | PoC · pcap · Suricata · Sigma · raw evidence |
| [CVE-2026-110186](CVE-2026-110186/) | Langflow code injection via pydoc scanner bypass | 9.8 | PoC · pcap · Suricata · Sigma |
| [CVE-2026-118306](CVE-2026-118306/) | Chromium FileSystemAccessManagerImpl use-after-free | 9.6 | PoC · Suricata · Sigma |
| [CVE-2026-58115](CVE-2026-58115/) | Siemens SIMATIC IoT2050 Node-RED unauthenticated root RCE | 10.0 | PoC · pcap · Suricata · Sigma |
| [CVE-2026-98432](CVE-2026-98432/) | Linux kernel TCP/IPv4 race condition use-after-free | 9.8 | PoC · pcap · Suricata · Sigma |
| [CVE-2026-102785](CVE-2026-102785/) | YOOtheme Pro image handler RCE | 10.0 | PoC · pcap · Suricata · Sigma |
| [CVE-2026-115560](CVE-2026-115560/) | PHP session upload-progress serialize handler mismatch | 9.8 | PoC · Suricata · Sigma |
| [ZDI-CAN-33549](ZDI-CAN-33549/) | Linux kernel ksmbd SMB Direct integer underflow | 9.0 | PoC · Suricata · Sigma |
| [ZDI-CAN-33774](ZDI-CAN-33774/) | Linux kernel ksmbd protocol dispatch race condition | 9.0 | PoC · Suricata · Sigma |
| [CVE-2026-110264](CVE-2026-110264/) | GitLab Onigmo regex integer overflow via org-ruby | 10.0 | PoC |

CVSS is the score stated in each directory's README.

<details>
<summary>Browse all 17 CVE IDs</summary>

**2026**

[CVE-2026-25253](CVE-2026-25253/) ·
[CVE-2026-58115](CVE-2026-58115/) ·
[CVE-2026-98432](CVE-2026-98432/) ·
[CVE-2026-102785](CVE-2026-102785/) ·
[CVE-2026-104007](CVE-2026-104007/) ·
[CVE-2026-109618](CVE-2026-109618-and-CVE-2026-109619/) ·
[CVE-2026-109619](CVE-2026-109618-and-CVE-2026-109619/) ·
[CVE-2026-110186](CVE-2026-110186/) ·
[CVE-2026-110264](CVE-2026-110264/) ·
[CVE-2026-112403](CVE-2026-112403/) ·
[CVE-2026-114938](CVE-2026-114938/) ·
[CVE-2026-115560](CVE-2026-115560/) ·
[CVE-2026-116779](CVE-2026-116779/) ·
[CVE-2026-118306](CVE-2026-118306/) ·
[CVE-2026-123874](CVE-2026-123874/) ·
[CVE-2026-125350](CVE-2026-125350/) ·
[CVE-2026-128067](CVE-2026-128067/)

</details>

<!-- research-table:end -->

Write-ups for each are on [blog.al4n4n.com](https://blog.al4n4n.com).

Browse the [research index](INDEX.md) or download the [machine-readable catalog](index.json). Each entry includes a citation at the end of its README. See the [contributor guide](CONTRIBUTING.md) to add or update an entry.

## Getting started

```bash
git clone https://github.com/al4n4n/achilles-heel.git
cd achilles-heel/<directory>
```

Then follow that directory's README. Most follow the same layout:

- `setup.py` / `setup.sh`: starts the vulnerable and the patched target locally
- `check.py`: tests for the vulnerability without triggering it
- `poc.py` / `poc.sh`: reproduces the vulnerability
- `capture/`: the network capture of the attack
- `detection/`: Suricata, Sigma or YARA rules, for education only
- `evidence/`: the raw output of every run behind each claim (newer directories)
- `meta.json`: research metadata used to generate the catalogs and entry citation

Run the labs and PoCs only against targets you set up yourself, ideally in a disposable virtual machine: several of them crash their target on purpose.

Each directory used to be its own repository. Those repositories are archived and point here.

## How the research is done

Every new entry meets these rules before it is published:

- **Shown working first.** An entry is written up only after the bug has been triggered in the lab and the result recorded.
- **Recorded output.** Any output quoted in a README or blog post is copied from a saved run.
- **The attacker's route.** The PoC reaches the bug through the same entry point an attacker would use, as the advisory describes it.
- **Fixed build as a control.** When a patched version is available, the same PoC is run against it and the impact disappears.
- **Detection scope stated.** Each rule is tested on the research capture and one benign sample, and is published for education only.

## Corrections

Found a mistake in an entry? Open an [issue](https://github.com/al4n4n/achilles-heel/issues). Corrections to a published entry are recorded in a dated Changelog section of that entry's README.

## Disclaimer

This repository is for learning and defense. The PoCs exist to reproduce each vulnerability faithfully, so the attack can be analyzed, the impact assessed honestly, and detection built from real attack traffic. The detection rules are for education only: if you use them, you do so at your own risk. Everything here, code, captures, rules and evidence alike, is provided as is, without warranty, and responsibility for its use lies with whoever runs or deploys it, not with this repository or its author. Read the full [DISCLAIMER](DISCLAIMER.md).

## Attribution

If you share, publish or build on anything from this repository (code, captures, detection rules, evidence or write-ups) in any project or product, commercial or open source, you must credit the author and link back:

> al4n4n (Dadb0d), achilles-heel, https://github.com/al4n4n/achilles-heel

When you use a single directory, link to that directory, for example `https://github.com/al4n4n/achilles-heel/tree/main/CVE-2026-116779`. If you adapt the material, say that you changed it. GitHub's "Cite this repository" button gives the same credit, from [CITATION.cff](CITATION.cff).

## License

[CC BY 4.0](LICENSE). Free to use, share and adapt for any purpose, including commercial, as long as you give credit as described under [Attribution](#attribution).

## Author

[al4n4n](https://github.com/al4n4n) (Dadb0d)
