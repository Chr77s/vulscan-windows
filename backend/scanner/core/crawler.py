"""
Crawler / Spider — phase de découverte avant les modules d'injection.

Visite la page cible (et optionnellement 1 niveau de profondeur) pour extraire :
  - Tous les liens internes (<a href>)
  - Tous les formulaires (<form>) avec leurs champs
  - Tous les endpoints API dans le JS (fetch, XHR, axios)
  - Le sitemap.xml et robots.txt s'ils sont accessibles

Le résultat est mis dans `context` pour que les modules d'injection puissent
fuzzer **toutes les surfaces d'attaque** découvertes, pas seulement l'URL initiale.
"""
from __future__ import annotations
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse, urljoin, urldefrag
import requests
import re
import logging

logger = logging.getLogger("vulnscan.crawler")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class Crawler:
    """
    Crawler minimaliste — pas concurrent (séquentiel pour rester poli avec la cible).

    Limites par défaut :
      - max_depth = 1 (la page seed + ses liens directs)
      - max_pages = 30
      - timeout = 5s par requête
      - only same-origin (pas de crawl externe)
    """

    def __init__(self,
                 max_depth: int = 1,
                 max_pages: int = 30,
                 timeout: int = 5,
                 user_agent: str = "VulnScan/1.3 (security-audit)"):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.user_agent = user_agent
        self._visited: Set[str] = set()

    def crawl(self, seed_url: str, auth: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Lance le crawl et retourne un dict structuré.

        Si `auth` est fourni (cookies/headers), le crawler découvrira aussi
        les pages protégées par auth.
        """
        self._auth = auth or {}
        if not re.match(r"^https?://", seed_url):
            return self._empty_result(seed_url)

        seed_host = urlparse(seed_url).hostname or ""
        urls: Set[str] = set()
        forms: List[Dict[str, Any]] = []
        api_endpoints: Set[str] = set()
        comments: List[str] = []

        queue = [(seed_url, 0)]
        while queue and len(self._visited) < self.max_pages:
            current_url, depth = queue.pop(0)
            current_url = urldefrag(current_url)[0]  # supprime fragment #
            if current_url in self._visited:
                continue
            self._visited.add(current_url)

            page_data = self._fetch_and_parse(current_url)
            if not page_data:
                continue

            urls.add(current_url)
            forms.extend(page_data["forms"])
            api_endpoints.update(page_data["api_endpoints"])
            comments.extend(page_data["comments"])

            if depth < self.max_depth:
                for link in page_data["links"]:
                    link_host = urlparse(link).hostname or seed_host
                    if link_host == seed_host:
                        urls.add(link)
                        if link not in self._visited:
                            queue.append((link, depth + 1))

        # Bonus : robots.txt + sitemap.xml
        extra_urls = self._fetch_robots_sitemap(seed_url)
        urls.update(extra_urls)

        result = {
            "seed": seed_url,
            "urls": sorted(list(urls))[:self.max_pages],
            "forms": forms,
            "api_endpoints": sorted(list(api_endpoints)),
            "comments_html": comments[:10],
            "stats": {
                "pages_visited": len(self._visited),
                "urls_discovered": len(urls),
                "forms_discovered": len(forms),
                "api_endpoints_discovered": len(api_endpoints),
            },
        }
        logger.info(f"Crawler : {result['stats']}")
        return result

    # -----------------------------------------------------------
    # Internes
    # -----------------------------------------------------------
    def _fetch_and_parse(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            req_headers = {"User-Agent": self.user_agent}
            req_headers.update((self._auth or {}).get("headers", {}))
            cookies = (self._auth or {}).get("cookies", {})
            r = requests.get(url, timeout=self.timeout,
                             headers=req_headers, cookies=cookies,
                             allow_redirects=True)
            if r.status_code >= 400:
                return None
            body = r.text
        except Exception as e:
            logger.debug(f"Crawler skip {url} : {e}")
            return None

        page_data = {
            "links": set(),
            "forms": [],
            "api_endpoints": set(),
            "comments": [],
        }

        if HAS_BS4:
            soup = BeautifulSoup(body, "html.parser")

            # Liens <a href>
            for a in soup.find_all("a", href=True):
                href = a["href"]
                abs_url = urljoin(url, href)
                if re.match(r"^https?://", abs_url):
                    page_data["links"].add(abs_url)

            # Formulaires
            for form in soup.find_all("form"):
                page_data["forms"].append(self._parse_form(form, url))

            # Commentaires HTML
            from bs4 import Comment
            for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                txt = str(c).strip()
                if len(txt) > 3:
                    page_data["comments"].append(txt[:500])

            # Endpoints API dans le JS
            for script in soup.find_all("script"):
                code = script.get_text() or ""
                if code.strip():
                    page_data["api_endpoints"].update(self._extract_endpoints(code, url))
        else:
            # Fallback regex sans bs4
            for m in re.finditer(r'href=["\']([^"\']+)["\']', body):
                abs_url = urljoin(url, m.group(1))
                if re.match(r"^https?://", abs_url):
                    page_data["links"].add(abs_url)

        return page_data

    @staticmethod
    def _parse_form(form, base_url: str) -> Dict[str, Any]:
        action = form.get("action", "") or base_url
        action = urljoin(base_url, action)
        method = (form.get("method", "GET") or "GET").upper()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            ftype = inp.get("type", "text")
            if ftype in ("submit", "button", "image", "reset"):
                continue
            fields.append({
                "name": inp.get("name", ""),
                "type": ftype,
                "value": inp.get("value", ""),
                "required": inp.has_attr("required"),
            })
        return {
            "action": action,
            "method": method,
            "fields": [f for f in fields if f["name"]],
            "id": form.get("id", ""),
        }

    @staticmethod
    def _extract_endpoints(js_code: str, base_url: str) -> Set[str]:
        """Cherche fetch("/api/..."), $.ajax({url:"..."}), etc."""
        endpoints = set()
        # fetch("...") ou fetch('...')
        for m in re.finditer(r'fetch\s*\(\s*["\']([^"\']+)["\']', js_code):
            endpoints.add(urljoin(base_url, m.group(1)))
        # url: "..." (jQuery / axios)
        for m in re.finditer(r'url\s*:\s*["\']([^"\']+)["\']', js_code):
            endpoints.add(urljoin(base_url, m.group(1)))
        # axios.get("...") / axios.post("...")
        for m in re.finditer(r'axios\.\w+\(\s*["\']([^"\']+)["\']', js_code):
            endpoints.add(urljoin(base_url, m.group(1)))
        # XMLHttpRequest.open("METHOD", "url")
        for m in re.finditer(r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']', js_code):
            endpoints.add(urljoin(base_url, m.group(1)))
        return endpoints

    def _fetch_robots_sitemap(self, seed_url: str) -> Set[str]:
        """Récupère robots.txt + sitemap.xml pour découvrir des URLs cachées."""
        urls: Set[str] = set()
        parsed = urlparse(seed_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ("/robots.txt", "/sitemap.xml"):
            try:
                r = requests.get(base + path, timeout=self.timeout,
                                 headers={"User-Agent": self.user_agent})
                if r.status_code != 200:
                    continue
                # robots.txt : Disallow: /path
                for m in re.finditer(r"(?:Disallow|Allow|Sitemap):\s*(\S+)", r.text, re.I):
                    val = m.group(1)
                    if val.startswith("http"):
                        urls.add(val)
                    else:
                        urls.add(urljoin(base, val))
                # sitemap.xml : <loc>...</loc>
                for m in re.finditer(r"<loc>([^<]+)</loc>", r.text):
                    urls.add(m.group(1))
            except Exception:
                continue
        return urls

    @staticmethod
    def _empty_result(seed: str) -> Dict[str, Any]:
        return {
            "seed": seed, "urls": [seed], "forms": [], "api_endpoints": [],
            "comments_html": [],
            "stats": {"pages_visited": 0, "urls_discovered": 1,
                      "forms_discovered": 0, "api_endpoints_discovered": 0},
        }
