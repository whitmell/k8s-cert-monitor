"""Writes rules.yml (plain Prometheus rule file) from the Helm chart template."""
import os
import subprocess
here = os.path.dirname(os.path.abspath(__file__))
chart = os.path.abspath(os.path.join(here, "..", "deploy"))
text = subprocess.run(
    ["helm", "template", "cert-inventory", chart, "--set", "monitoring.enabled=true"],
    check=True,
    capture_output=True,
    text=True,
).stdout
doc = next(d for d in text.split("\n---\n") if "kind: PrometheusRule" in d)
spec = doc.split("\nspec:\n", 1)[1]
rules = "\n".join(line[2:] if line.startswith("  ") else line for line in spec.splitlines()) + "\n"
open(os.path.join(here, "rules.yml"), "w", encoding="utf-8", newline="\n").write(rules)
print(rules.splitlines()[0], "...", len(rules.splitlines()), "lines")
