"""Render docs/*.md to PDF (tables, code, mermaid) via headless Edge/Chrome.

    python scripts/build_docs_pdf.py docs/03_architecture.md docs/04_tasks.md

Output: docs/pdf/<name>.pdf. Needs internet once (mermaid.js from jsDelivr).
"""

from __future__ import annotations

import html
import re
import shutil
import subprocess
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "pdf"
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge", "google-chrome", "chromium",
]

CSS = """
img { max-width: 100%; max-height: 228mm; width: auto; height: auto; display: block; margin: 6px auto 4px;
      border: 1px solid #d0d7de; break-inside: avoid; }
h2, h3 { break-after: avoid; }

@page { size: A4; margin: 16mm 14mm 18mm 14mm; }
:root { --ink:#1b1f24; --muted:#57606a; --line:#d0d7de; --accent:#0b5cad; --soft:#f3f6fa; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", system-ui, sans-serif; color: var(--ink); font-size: 10.2pt;
       line-height: 1.5; margin: 0; background: #fff; }
.cover { border-left: 5px solid var(--accent); padding: 4px 0 4px 14px; margin-bottom: 18px; }
.cover .kicker { color: var(--accent); font-weight: 600; font-size: 9pt; letter-spacing: .06em;
                 text-transform: uppercase; }
h1 { font-size: 21pt; margin: 2px 0 0; line-height: 1.2; }
h2 { font-size: 14pt; color: var(--accent); border-bottom: 1px solid var(--line); padding-bottom: 3px;
     margin: 22px 0 8px; break-after: avoid; }
h3 { font-size: 11.5pt; margin: 16px 0 6px; break-after: avoid; }
p, li { orphans: 3; widows: 3; }
a { color: var(--accent); text-decoration: none; }
blockquote { margin: 10px 0; padding: 8px 12px; background: var(--soft); border-left: 3px solid var(--accent); }
blockquote p { margin: 0; }
code { font-family: Consolas, "Cascadia Mono", monospace; font-size: 8.8pt; background: var(--soft);
       padding: 1px 4px; border-radius: 3px; }
pre { background: #f6f8fa; border: 1px solid var(--line); border-radius: 6px; padding: 9px 11px;
      font-size: 8.3pt; line-height: 1.35; white-space: pre; overflow: hidden; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 8.7pt; break-inside: auto; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th { background: var(--soft); text-align: left; font-weight: 600; }
th, td { border: 1px solid var(--line); padding: 4px 6px; vertical-align: top; }
td code, th code { font-size: 8pt; word-break: break-word; }
pre.mermaid { background: #fff; border: 1px solid var(--line); text-align: center; white-space: pre; }
pre.mermaid svg { max-width: 100%; max-height: 188mm; height: auto; width: auto; }
pre.mermaid { padding: 4px; margin: 6px 0; }
ul.tasks { list-style: none; padding-left: 4px; }
ul.tasks li { margin: 5px 0; padding-left: 22px; text-indent: -22px; break-inside: avoid; }
.box { display: inline-block; width: 12px; height: 12px; border: 1.4px solid var(--muted); border-radius: 2px;
       margin-right: 8px; vertical-align: -1px; }
hr { border: 0; border-top: 1px solid var(--line); margin: 18px 0; }
.footer-note { color: var(--muted); font-size: 8pt; margin-top: 24px; border-top: 1px solid var(--line);
               padding-top: 6px; }
"""

TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>{css}</style></head><body>
<div class="cover"><div class="kicker">NetSentinel · Microsoft Innovate 2026 · PS #26</div><h1>{title}</h1></div>
{body}
<div class="footer-note">Source: {src} · github.com/Saroy-ctrl/netsentinel</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>
  if (window.mermaid) {{
    mermaid.initialize({{ startOnLoad: false, theme: "neutral", flowchart: {{ useMaxWidth: true }} }});
    mermaid.run({{ querySelector: "pre.mermaid" }}).then(() => document.body.dataset.ready = "1");
  }}
</script></body></html>"""


def render(md_path: Path) -> Path:
    text = md_path.read_text(encoding="utf-8")
    first, _, rest = text.partition("\n")
    title = re.sub(r"^#\s*(\d+\s*—\s*)?", "", first).strip()

    mermaids: list[str] = []

    def stash(m: re.Match) -> str:
        mermaids.append(m.group(1))
        return f"\n\nMERMAID_{len(mermaids) - 1}\n\n"

    rest = re.sub(r"```mermaid\n(.*?)```", stash, rest, flags=re.S)
    # python-markdown needs a blank line before a list that follows a paragraph line (GitHub doesn't)
    rest = re.sub(r"(?m)^(?![ \t]*(?:[-*]|\d+\.)\s)(\S.*)\n(?=[ \t]*(?:[-*]|\d+\.)\s)", r"\1\n\n", rest)
    # wide LR flowcharts are unreadable on A4 portrait -> stack top-to-bottom
    mermaids[:] = [m.replace("flowchart LR", "flowchart TB", 1) for m in mermaids]
    body = markdown.markdown(rest, extensions=["tables", "fenced_code", "sane_lists", "toc"])
    for i, src in enumerate(mermaids):
        body = body.replace(f"<p>MERMAID_{i}</p>", f'<pre class="mermaid">{html.escape(src)}</pre>')
    # images: links are relative to the .md file (as on GitHub); the HTML is written to docs/pdf, so make them absolute
    body = re.sub(r'<img ([^>]*?)src="(?!https?:|file:|data:)([^"]+)"',
                  lambda m: f'<img {m.group(1)}src="{(md_path.parent / m.group(2)).resolve().as_uri()}"', body)
    # GitHub task lists -> printable checkboxes
    body = re.sub(r"<li>\[ \]\s*", '<li><span class="box"></span>', body)
    body = body.replace("<ul>\n<li><span class=\"box\">", '<ul class="tasks">\n<li><span class="box">')

    OUT.mkdir(parents=True, exist_ok=True)
    html_path = OUT / f"{md_path.stem}.html"
    html_path.write_text(
        TEMPLATE.format(title=html.escape(title), css=CSS, body=body, src=md_path.relative_to(ROOT).as_posix()),
        encoding="utf-8",
    )
    pdf_path = OUT / f"{md_path.stem}.pdf"
    browser = next((b for b in BROWSERS if Path(b).exists() or shutil.which(b)), None)
    if not browser:
        sys.exit("No Edge/Chrome found")
    subprocess.run(
        [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--virtual-time-budget=15000",
         f"--print-to-pdf={pdf_path}", html_path.as_uri()],
        check=True, capture_output=True,
    )
    html_path.unlink()
    return pdf_path


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        print("wrote", render((ROOT / arg).resolve()))
