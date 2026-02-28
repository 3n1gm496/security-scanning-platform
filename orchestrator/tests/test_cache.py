from __future__ import annotations

import time

from orchestrator.cache import build_cache_key, load_cached_output, store_cached_output


def test_build_cache_key_stable():
    context = {"severity": "high", "templates": ["a", "b"]}
    k1 = build_cache_key("nuclei", "local", "/tmp/repo", context)
    k2 = build_cache_key("nuclei", "local", "/tmp/repo", context)
    assert k1 == k2


def test_build_cache_key_changes_with_context():
    k1 = build_cache_key("trivy", "image", "nginx:1.27", {"severity": ["HIGH"]})
    k2 = build_cache_key("trivy", "image", "nginx:1.27", {"severity": ["CRITICAL"]})
    assert k1 != k2


def test_store_and_load_cached_output(tmp_path):
    cache_dir = tmp_path / "cache"
    output = tmp_path / "out.json"
    output.write_text('{"ok": true}', encoding="utf-8")

    key = build_cache_key("semgrep", "local", "/tmp/repo", {"configs": ["p/default"]})
    store_cached_output(cache_dir, key, str(output))

    output.write_text("{}", encoding="utf-8")
    hit = load_cached_output(cache_dir, key, str(output), ttl_seconds=60)

    assert hit is True
    assert output.read_text(encoding="utf-8") == '{"ok": true}'


def test_cache_expired(tmp_path):
    cache_dir = tmp_path / "cache"
    output = tmp_path / "out.json"
    output.write_text('{"ok": true}', encoding="utf-8")

    key = build_cache_key("gitleaks", "git", "https://example/repo.git", {})
    store_cached_output(cache_dir, key, str(output))

    time.sleep(1)
    hit = load_cached_output(cache_dir, key, str(output), ttl_seconds=0)
    assert hit is False
