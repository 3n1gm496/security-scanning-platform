from __future__ import annotations

import time
import threading

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


def test_store_cached_output_is_atomic(tmp_path):
    cache_dir = tmp_path / "cache"
    output = tmp_path / "out.json"
    output.write_text('{"ok": true}', encoding="utf-8")

    key = build_cache_key("semgrep", "local", "/tmp/repo", {})
    store_cached_output(cache_dir, key, str(output))

    cache_file = cache_dir / f"{key}.json"
    assert cache_file.exists()
    assert not list(cache_dir.glob("*.tmp"))


def test_store_cached_output_serializes_same_key_writes(tmp_path):
    cache_dir = tmp_path / "cache"
    key = build_cache_key("nuclei", "url", "https://example.com", {})

    src_a = tmp_path / "a.json"
    src_b = tmp_path / "b.json"
    src_a.write_text('{"value":"a"}', encoding="utf-8")
    src_b.write_text('{"value":"b"}', encoding="utf-8")

    t1 = threading.Thread(target=store_cached_output, args=(cache_dir, key, str(src_a)))
    t2 = threading.Thread(target=store_cached_output, args=(cache_dir, key, str(src_b)))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    cache_file = cache_dir / f"{key}.json"
    assert cache_file.read_text(encoding="utf-8") in {'{"value":"a"}', '{"value":"b"}'}
