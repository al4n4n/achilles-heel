#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""Check that every relative link and image in the repository's Markdown files points to a file
that exists, and that every #anchor into a Markdown file matches one of its headings.

Usage: python3 scripts/check_links.py
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)|<(?:img|a)\s[^>]*(?:src|href)=\"([^\"]+)\"")
SKIP = {".git", "node_modules", ".lab"}


def anchors(md):
    """GitHub heading anchors: lower case, punctuation dropped, spaces become hyphens."""
    out = set()
    for heading in re.findall(r"^#+\s+(.*?)\s*#*$", md.read_text(errors="replace"), flags=re.M):
        out.add(re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-"))
    return out


def main():
    problems = []
    for md in sorted(ROOT.rglob("*.md")):
        if SKIP & set(md.relative_to(ROOT).parts):
            continue
        text = re.sub(r"```.*?```", "", md.read_text(errors="replace"), flags=re.S)
        text = re.sub(r"`[^`\n]*`", "", text)
        for m in LINK.finditer(text):
            target = m.group(1) or m.group(2)
            if re.match(r"^[a-zA-Z][a-zA-Z+.-]*:", target) or target.startswith("//"):
                continue
            path, _, frag = target.partition("#")
            dest = (md.parent / path).resolve() if path else md
            where = md.relative_to(ROOT)
            if not dest.exists():
                problems.append(f"{where}: no such file: {target}")
            elif frag and dest.suffix == ".md" and frag.lower() not in anchors(dest):
                problems.append(f"{where}: no such heading: {target}")
    for p in problems:
        print(p)
    if problems:
        sys.exit(f"{len(problems)} broken link(s)")
    print("all relative links resolve")


if __name__ == "__main__":
    main()
