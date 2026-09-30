"""Check resolved Git leaf identity without compiling anything locally."""
import collections
import pathlib
import tomllib

lock = tomllib.loads(pathlib.Path("Cargo.lock").read_text())
leaves = collections.defaultdict(list)
for package in lock["package"]:
    source = package.get("source", "")
    if source.startswith(("git+https://github.com/corbet-foss/", "git+https://github.com/corbet-libs/")):
        leaves[package["name"]].append(source)
for name, sources in sorted(leaves.items()):
    if len(sources) != 1:
        raise SystemExit(f"{name}: expected one resolved revision, got {len(sources)}")
    if "#" not in sources[0] or len(sources[0].rsplit("#", 1)[1]) != 40:
        raise SystemExit(f"{name}: missing full resolved revision")
print(f"One resolved revision for each of {len(leaves)} facade/leaf packages")
