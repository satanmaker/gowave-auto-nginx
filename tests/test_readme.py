#!/usr/bin/env python3
"""Offline contracts for the paired operator guides."""
import json
import re
import shlex
import subprocess
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
PAGES = (ROOT / "README.md", ROOT / "README.ru.md")
SECTIONS = (
    "purpose", "features", "architecture", "requirements", "domains",
    "installation", "first-connection", "remote-nodes", "operations",
    "reference", "security", "troubleshooting", "testing", "project",
)


def anchors(text):
    explicit = re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)["\']\s*></a>', text)
    headings = []
    seen = {}
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        headings.append(f"{slug}-{count}" if count else slug)
    return explicit + headings


def check_structure(text):
    actual = re.findall(r'<a\s+id="([a-z-]+)"\s*></a>', text)
    if tuple(section for section in actual if section in SECTIONS) != SECTIONS:
        raise AssertionError("missing or reordered operator-guide section")
    for section in SECTIONS:
        if f"](#{section})" not in text:
            raise AssertionError(f"contents missing {section}")


def check_links(page, text):
    for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^\s)]+)\)", text):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc:
            continue
        destination = (page.parent / unquote(parsed.path)).resolve() if parsed.path else page
        if not destination.exists():
            raise AssertionError(f"missing link target: {target}")
        if parsed.fragment:
            if destination.suffix != ".md":
                raise AssertionError(f"unsupported local fragment: {target}")
            content = text if destination == page else destination.read_text(encoding="utf-8")
            if unquote(parsed.fragment) not in anchors(content):
                raise AssertionError(f"missing fragment: {target}")


def executable_examples(text):
    examples = []
    for block in re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL):
        tokens = shlex.split(block, comments=True)
        if tokens:
            examples.append(tokens)
    return examples


def check_commands(text, source):
    router = source[source.index("# CLI Entrypoint Router"):]
    commands = re.findall(r"^        ([a-z][a-z-]*)\)", router, re.MULTILINE)
    for command in commands:
        if command == "recover":
            continue
        if not re.search(r"gowave-auto\.sh\s+" + re.escape(command) + r"\b", text):
            raise AssertionError(f"undocumented command: {command}")


def check_pinned_core(text, source):
    version = re.search(r'^GOWAVE_PINNED_XRAY_VERSION="([^"]+)"', source, re.MULTILINE).group(1)
    if version not in text:
        raise AssertionError(f"missing pinned Xray version: {version}")


class TestReadme(unittest.TestCase):
    def test_paired_sections_and_language_links(self):
        for page, other in zip(PAGES, reversed(PAGES)):
            with self.subTest(page=page.name):
                text = page.read_text(encoding="utf-8")
                check_structure(text)
                self.assertIn(f"]({other.name})", text)

    def test_local_files_and_fragments_resolve(self):
        for page in PAGES:
            with self.subTest(page=page.name):
                text = page.read_text(encoding="utf-8")
                check_links(page, text)
                ids = re.findall(r'<a\s+id="([a-z-]+)"\s*></a>', text)
                self.assertEqual(len(ids), len(set(ids)), "duplicate explicit anchor")

    def test_contribution_links_and_current_entrypoints(self):
        page = ROOT / "CONTRIBUTING.md"
        text = page.read_text(encoding="utf-8")
        check_links(page, text)
        self.assertIn("`develop`", text)
        self.assertIn("set -Eeuo pipefail", text)
        for topology in ("aio", "multi-node", "panel-only"):
            self.assertIn(f"tools.run_podman_e2e --topology {topology}", text)

    def test_executable_examples_match(self):
        english, russian = (executable_examples(page.read_text(encoding="utf-8")) for page in PAGES)
        self.assertTrue(english)
        self.assertEqual(english, russian)

    def test_shell_examples_have_valid_syntax(self):
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            for index, block in enumerate(re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL)):
                with self.subTest(page=page.name, block=index):
                    result = subprocess.run(
                        ["bash", "-n"], input=block, text=True,
                        capture_output=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_inline_technical_identifiers_match(self):
        identifiers = []
        for page in PAGES:
            text = re.sub(r"```.*?```", "", page.read_text(encoding="utf-8"), flags=re.DOTALL)
            values = set(re.findall(r"`([^`\n]+)`", text))
            identifiers.append({value for value in values if value.isascii()})
        self.assertEqual(identifiers[0], identifiers[1])

    def test_commands_are_backed_by_router(self):
        source = (ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        for page in PAGES:
            with self.subTest(page=page.name):
                check_commands(page.read_text(encoding="utf-8"), source)

    def test_supported_platforms_and_profiles(self):
        os_source = (ROOT / "modules/os.sh").read_text(encoding="utf-8")
        versions = re.findall(r'\[\[ "\$os_version" == "([\d.]+)" \|\| "\$os_version" == "([\d.]+)" \]\]', os_source)
        self.assertTrue(versions)
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            for pair in versions:
                for version in pair:
                    self.assertIn(version, text)
            for value in ("amd64", "arm64", "REALITY", "XHTTP", "WebSocket", "Trojan", "Vision"):
                self.assertIn(value, text)

    def test_client_versions_and_subscription_paths_match_owners(self):
        matrix = yaml.safe_load((ROOT / "tests/cases/matrix.yaml").read_text(encoding="utf-8"))
        product = matrix["product"]
        source = (ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        links = source[source.index("cmd_user_links() {"):source.index("cmd_user_links() {") + 4000]
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            for engine in ("xray_client_version", "mihomo_client_version"):
                self.assertIn(product[engine], text)
            for suffix in ("", "/v2ray-json", "/mihomo", "/clash"):
                self.assertIn(f"/api/sub/<shortUuid>{suffix}", text)
                self.assertIn(f"/api/sub/$short_uuid{suffix}", links)
            for suite in ("nonroot", "root", "integration", "services", "systemd"):
                self.assertIn(f"`{suite}`", text)

    def test_reality_bind_warning_matches_template(self):
        template = json.loads((ROOT / "assets/xray/vless-reality.json").read_text(encoding="utf-8"))
        self.assertNotIn("listen", template)
        phrases = (
            (PAGES[0], "does not restrict the bind address"),
            (PAGES[1], "адрес привязки"),
        )
        for page, phrase in phrases:
            text = page.read_text(encoding="utf-8")
            row = next(line for line in text.splitlines() if line.startswith("| `8443` |"))
            self.assertIn(phrase, row)

    def test_pinned_core_matches_source(self):
        source = (ROOT / "modules/xray_core.sh").read_text(encoding="utf-8")
        for page in PAGES:
            with self.subTest(page=page.name):
                check_pinned_core(page.read_text(encoding="utf-8"), source)

    def test_guard_refuses_changed_pinned_default(self):
        source = (ROOT / "modules/xray_core.sh").read_text(encoding="utf-8")
        version = re.search(r'^GOWAVE_PINNED_XRAY_VERSION="([^"]+)"', source, re.MULTILINE).group(1)
        text = PAGES[0].read_text(encoding="utf-8").replace(version, "0.0.0")
        with self.assertRaisesRegex(AssertionError, "pinned Xray"):
            check_pinned_core(text, source)

    def test_guards_refuse_missing_section(self):
        text = (PAGES[0]).read_text(encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "section"):
            check_structure(text.replace('<a id="domains"></a>', ""))

    def test_guards_refuse_broken_file_and_fragment(self):
        for target in ("no-such-operator-guide.md", "#no-such-readme-section"):
            with self.subTest(target=target), self.assertRaises(AssertionError):
                check_links(PAGES[0], f"[broken]({target})")

    def test_guards_refuse_changed_command(self):
        text = PAGES[0].read_text(encoding="utf-8")
        source = (ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "status"):
            check_commands(text.replace("gowave-auto.sh status", "gowave-auto.sh state"), source)


if __name__ == "__main__":
    unittest.main()
