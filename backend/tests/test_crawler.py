"""Tests unitaires du crawler — utilisent uniquement la logique de parsing,
pas de réseau réel."""
import pytest


def test_parse_form_extracts_fields():
    """Vérifie que _parse_form extrait correctement action, method, fields."""
    from scanner.core.crawler import Crawler
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        pytest.skip("bs4 non installé")

    html = """
    <form action="/login" method="POST">
      <input type="text" name="username">
      <input type="password" name="password" required>
      <input type="hidden" name="csrf" value="xyz">
      <input type="submit" value="Login">
      <textarea name="notes"></textarea>
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    out = Crawler._parse_form(form, "http://test.local/")

    assert out["method"] == "POST"
    assert out["action"] == "http://test.local/login"
    names = [f["name"] for f in out["fields"]]
    assert "username" in names
    assert "password" in names
    assert "csrf" in names
    assert "notes" in names
    assert "Login" not in names  # le submit doit être filtré


def test_extract_endpoints_from_js():
    """Vérifie qu'on trouve les endpoints dans fetch() / axios / XHR."""
    from scanner.core.crawler import Crawler
    js = """
    fetch("/api/users")
    fetch('/api/v2/orders');
    axios.get("/api/products");
    $.ajax({ url: "/api/categories", method: "GET" });
    xhr.open("POST", "/api/login");
    """
    endpoints = Crawler._extract_endpoints(js, "http://test.local/")
    paths = [e.replace("http://test.local", "") for e in endpoints]
    assert "/api/users" in paths
    assert "/api/v2/orders" in paths
    assert "/api/products" in paths
    assert "/api/categories" in paths
    assert "/api/login" in paths


def test_crawler_empty_for_invalid_url():
    """Crawler ne plante pas sur une URL invalide."""
    from scanner.core.crawler import Crawler
    result = Crawler().crawl("not-a-url")
    assert result["stats"]["pages_visited"] == 0
