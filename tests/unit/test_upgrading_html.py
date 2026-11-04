"""Parser of the official Upgrading Guide HTML (data/breaking-changes/source/upgrading-guide.html)."""
from collections import Counter

import pytest

from app.ingestion.upgrading_html import parse_upgrading_html

URL = "https://www.keycloak.org/docs/latest/upgrading/index.html"


@pytest.fixture(scope="module")
def catalog(settings):
    html = (settings.data_dir / "breaking-changes" / "source" / "upgrading-guide.html").read_text()
    return parse_upgrading_html(html, URL, "2026-11-04T00:00:00Z")


def _entry(catalog, title_part):
    return next(e for e in catalog["entries"] if title_part in e["title"])


def test_index_matches_toc_and_versions_are_chained(catalog):
    assert catalog["warnings"] == []
    assert catalog["stats"]["versions"] == catalog["stats"]["toc_versions"] > 40
    idx = {v["version"]: v for v in catalog["index"]}
    assert idx["26.6.3"]["from_version"] == "26.6.2"
    assert idx["26.0.0"]["from_version"] == "25.0.3"
    assert idx["26.6.3"]["categories"]["breaking"] >= 3


def test_categories_are_normalized(catalog):
    cats = Counter(e["category"] for e in catalog["entries"])
    assert set(cats) <= {"breaking", "notable", "deprecated", "removed", "end-of-life", "uncategorized"}
    assert cats["breaking"] > 0 and cats["notable"] > 0 and cats["deprecated"] > 0


def test_known_entries(catalog):
    e = _entry(catalog, "do not accept wildcards for hostname")
    assert (e["version"], e["from_version"], e["category"]) == ("26.6.3", "26.6.2", "breaking")
    assert "https://example.com*" in e["text"] and e["url"].startswith(URL + "#_valid_redirect")
    e = _entry(catalog, "Accepting only normalized paths")
    assert (e["version"], e["category"]) == ("26.4.3", "breaking")
    e = _entry(catalog, "Accepting HTTP requests with non-normalized paths")
    assert (e["version"], e["category"]) == ("26.4.3", "deprecated")
    # older versions have no category headers
    e = _entry(catalog, "Support for legacy")
    assert (e["version"], e["category"]) == ("26.0.0", "uncategorized")
    assert "redirect_uri" in e["text"]


def test_entry_ids_are_unique_and_stable(catalog, settings):
    ids = [e["entry_id"] for e in catalog["entries"]]
    assert len(ids) == len(set(ids))
    html = (settings.data_dir / "breaking-changes" / "source" / "upgrading-guide.html").read_text()
    again = parse_upgrading_html(html, URL, "later")
    assert [e["entry_id"] for e in again["entries"]] == ids
    assert [e["content_hash"] for e in again["entries"]] == [e["content_hash"] for e in catalog["entries"]]


def test_minimal_non_asciidoctor_markup():
    html = """<h2 id="m">Migration Changes</h2>
    <h3 id="v2">Migrating to 2.0.0</h3><h4 id="b">Breaking changes</h4>
    <h5 id="x">Thing removed</h5><p>The thing was removed.</p>
    <h3 id="v1">Migrating to 1.0.0</h3><h4 id="y">Old item</h4><p>Old text.</p>"""
    c = parse_upgrading_html(html, "u")
    assert [(e["version"], e["category"], e["text"]) for e in c["entries"]] == [
        ("2.0.0", "breaking", "The thing was removed."), ("1.0.0", "uncategorized", "Old text.")]
    assert c["entries"][0]["from_version"] == "1.0.0"


def test_committed_catalog_is_in_sync_with_snapshot(catalog, settings):
    import json

    committed = json.loads((settings.data_dir / "breaking-changes" / "catalog.json").read_text())
    assert [e["content_hash"] for e in committed["entries"]] == [e["content_hash"] for e in catalog["entries"]]
