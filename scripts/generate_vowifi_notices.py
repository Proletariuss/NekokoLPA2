#!/usr/bin/env python3
"""Inventory iOS Go dependencies and preserve their module-root notices.

Run from any directory. Requires the same Go toolchain/module cache as the
framework build. --check verifies the committed outputs without writing them.
This inventory is not a legal determination or a file-level license audit.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "mobilecore"
MANIFEST = CORE / "DEPENDENCIES.json"
NOTICES = ROOT / "local_packages/proletarius_vowifi/ios/Resources/MobileCoreNotices.txt"
TARGET = {"GOOS": "ios", "GOARCH": "arm64", "CGO_ENABLED": "1"}
PACKAGES = [".", "golang.org/x/mobile/bind/seq"]
SWU_REVISION = "7cf4b63f44474f1be8b3e9f05c8ddaddc787c6d5"
CARRIER_REVISION = "ca030f836d858e59443e8957a844216c179d8677"
HOST_REVISION = "9717ccfe65f2780b9185937ca2cd45b16621ac83"
AMR_URL = "https://downloads.sourceforge.net/project/opencore-amr/opencore-amr/opencore-amr-0.1.6.tar.gz"
AMR_SHA256 = "483eb4061088e2b34b358e47540b5d495a96cd468e361050fae615b1809dc4a1"


def run_go(*args):
    return subprocess.check_output(
        ["go", *args], cwd=CORE, env={**os.environ, **TARGET}, text=True
    )


def json_stream(raw):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            return
        item, offset = decoder.raw_decode(raw, offset)
        yield item


def module_escape(value):
    # Go module proxy escaping, before ordinary URL path escaping.
    return quote("".join("!" + c.lower() if c.isupper() else c for c in value), safe="/!@.-+")


def root_notices(directory):
    names = sorted(
        p for p in directory.iterdir()
        if p.is_file() and re.match(r"^(LICENSE|COPYING|NOTICE)(?:[._-].*)?$", p.name, re.I)
    )
    if not any(re.match(r"^(LICENSE|COPYING)(?:[._-].*)?$", p.name, re.I) for p in names):
        raise ValueError("No module-root LICENSE or COPYING for " + directory.name)
    return names


def record_notices(paths, label_root):
    records = []
    for path in paths:
        data = path.read_bytes()
        if not data.strip():
            raise ValueError("Empty notice file: " + label_root + "/" + path.name)
        text = data.decode("utf-8")
        records.append({
            "file": label_root + "/" + path.name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "text": text,
        })
    return records


def component(name, source, paths):
    records = []
    for path in paths:
        records.extend(record_notices([path], str(path.relative_to(ROOT).parent)))
    return {"name": name, "source": source, "notices": records}


def render():
    graph = list(json_stream(run_go("list", "-deps", "-json", *PACKAGES)))
    modules = {}
    standard_packages = []
    for package in graph:
        if package.get("Error") or package.get("DepsErrors"):
            raise ValueError("go list returned package errors")
        if package.get("Standard"):
            standard_packages.append(package["ImportPath"])
        module = package.get("Module")
        if module is None:
            if not package.get("Standard") and package["ImportPath"] != "C":
                raise ValueError("Package without a module: " + package["ImportPath"])
            continue
        key = module["Path"]
        if key not in modules:
            effective = module.get("Replace", module)
            replacement = None
            if "Replace" in module:
                replacement = {"path": effective["Path"], "version": effective.get("Version")}
                if Path(replacement["path"]).is_absolute():
                    raise ValueError("Absolute module replacements cannot be published")
            if module.get("Main"):
                directory = CORE
                label = "mobilecore"
                source = {"kind": "local-contribution", "license": "mobilecore/LICENSE"}
            else:
                directory = Path(effective["Dir"])
                label = key + "@" + module["Version"]
                version = effective.get("Version", module["Version"])
                if replacement and effective.get("Version") is None:
                    local_path = str(directory.resolve().relative_to(ROOT))
                    label = local_path
                    source = {"local_path": local_path}
                else:
                    source = {"module_zip": "https://proxy.golang.org/" + module_escape(effective["Path"]) + "/@v/" + module_escape(version) + ".zip"}
                if key == "github.com/1239t/swu-go" and replacement:
                    source = {
                        "upstream_commit": SWU_REVISION,
                        "upstream_url": "https://github.com/1239t/swu-go/tree/" + SWU_REVISION,
                        "local_changes": "mobilecore/third_party/swu-go/PATCHES.md",
                    }
                    label = "mobilecore/third_party/swu-go"
            modules[key] = {
                "path": key,
                "version": module.get("Version"),
                "replace": replacement,
                "sum": effective.get("Sum"),
                "go_mod_sum": effective.get("GoModSum"),
                "source": source,
                "packages": [],
                "notices": record_notices(root_notices(directory), label),
            }
        modules[key]["packages"].append(package["ImportPath"])

    ordered_modules = [modules[key] for key in sorted(modules)]
    for module in ordered_modules:
        module["packages"].sort()
    if "golang.org/x/mobile/bind/seq" not in modules["golang.org/x/mobile"]["packages"]:
        raise ValueError("Missing gomobile runtime dependency")

    go_environment = json.loads(run_go("env", "-json", "GOVERSION", "GOROOT"))
    go_version = go_environment["GOVERSION"]
    if not re.fullmatch(r"go\d+\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?", go_version):
        raise ValueError("A release Go toolchain is required for reproducible provenance")
    go_notice_root = Path(go_environment["GOROOT"])
    # Homebrew places the upstream Go LICENSE beside its libexec/GOROOT.
    if (go_notice_root.name == "libexec"
            and go_notice_root.parent.name == go_version.removeprefix("go")
            and not (go_notice_root / "LICENSE").is_file()):
        go_notice_root = go_notice_root.parent
    toolchain = {
        "version": go_version,
        "source_url": "https://github.com/golang/go/tree/" + go_version,
        "standard_packages": sorted(set(standard_packages)),
        "notices": record_notices(root_notices(go_notice_root), "go@" + go_version),
    }
    components = [
        component("NekokoLPA2 host", {"url": "https://github.com/iebb/NekokoLPA2/blob/" + HOST_REVISION + "/LICENSE", "commit": HOST_REVISION}, [ROOT / "LICENSE"]),
        component("iOS Flutter/native bridge", {"kind": "local-contribution", "license": "local_packages/proletarius_vowifi/LICENSE"}, [ROOT / "local_packages/proletarius_vowifi/LICENSE"]),
        component("Carrier registry", {"url": "https://github.com/iniwex5/ios-carrier-profiles/tree/" + CARRIER_REVISION, "commit": CARRIER_REVISION}, [CORE / "internal/vowifi/carrier/data/LICENSE"]),
        component("opencore-amr 0.1.6", {"archive_url": AMR_URL, "archive_sha256": AMR_SHA256, "local_provenance": "mobilecore/third_party/opencore-amr/UPSTREAM.txt"}, [CORE / "third_party/opencore-amr/LICENSE", CORE / "third_party/opencore-amr/opencore/NOTICE"]),
    ]
    inventory = {
        "schema_version": 1,
        "generator": "scripts/generate_vowifi_notices.py",
        "target": TARGET,
        "go_list_packages": PACKAGES,
        "scope": "Production package graph plus gomobile bind/seq; module-root LICENSE/COPYING/NOTICE, retained local component notices, and Go toolchain notices.",
        "limitations": [
            "This inventory is not a legal determination or a file-level license audit.",
            "Module membership is based on go list, not a link-map or dead-code analysis.",
            "Apple system frameworks, Flutter/Dart packages and their notices are outside this Go/native-source inventory.",
        ],
        "warnings": [],
        "modules": ordered_modules,
        "toolchain": toolchain,
        "components": components,
    }
    sections = [
        "NekokoLPA2 iOS VoWiFi - source and dependency notices\n",
        "Generated by scripts/generate_vowifi_notices.py.\n"
        "Target: GOOS=ios GOARCH=arm64 CGO_ENABLED=1.\n"
        "Graph: mobilecore plus golang.org/x/mobile/bind/seq.\n"
        "Versions, source references and license SHA-256 hashes: mobilecore/DEPENDENCIES.json.\n"
        "Original notice text is retained below; this is not a legal determination.\n"
        "This module-root inventory does not replace a file-level license review or\n"
        "the host application's Flutter, Apple-framework and other notices.\n",
    ]
    for item in [*components, *ordered_modules, toolchain]:
        title = item.get("name", item.get("path", "Go standard library and runtime"))
        if item.get("version"):
            title += " " + item["version"]
        sections.append("=" * 78 + "\n" + title + "\n")
        sections.append("Source: " + json.dumps(item.get("source", {"url": item.get("source_url")}), sort_keys=True) + "\n")
        for notice in item["notices"]:
            sections.append("\n" + notice["file"] + "\nSHA-256: " + notice["sha256"] + "\n\n" + notice["text"])
            if not notice["text"].endswith("\n"):
                sections.append("\n")
            del notice["text"]
    manifest_text = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
    notice_text = "\n".join(sections)
    for text in [manifest_text, notice_text]:
        if str(ROOT) in text or str(Path.home()) in text:
            raise ValueError("Machine-specific paths leaked into generated output")
    return manifest_text, notice_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if generated outputs differ; write nothing")
    args = parser.parse_args()
    manifest_text, notice_text = render()
    outputs = [(MANIFEST, manifest_text), (NOTICES, notice_text)]
    if args.check:
        different = [str(path.relative_to(ROOT)) for path, text in outputs if not path.is_file() or path.read_text() != text]
        if different:
            raise ValueError("Generated notices are stale: " + ", ".join(different))
        print("VoWiFi dependency notices are current.")
    else:
        for path, text in outputs:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        print("Generated mobilecore/DEPENDENCIES.json and MobileCoreNotices.txt.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("Cannot generate VoWiFi notices: " + str(error), file=sys.stderr)
        sys.exit(1)
