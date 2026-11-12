"""Analiza sklepu. Funkcja analyze_shop zwraca raport dla konsoli lub przyszłej strony WWW."""
import hashlib
import re
import time
from urllib.parse import unquote, urljoin, urlsplit
from zoneinfo import ZoneInfoNotFoundError
from bs4 import BeautifulSoup
from network import (
    check_dns,
    check_domain_age,
    check_tls,
    fetch_resource,
    normalize_url,
    outcome,
    plain,
    registrable_domain,
    utc_now,
)
from company import (
    MAX_VAT_LOOKUPS,
    compare_name,
    extract_german_vat_ids,
    extract_nips,
    get_vat_company,
    is_valid_nip,
    polish_date,
    summarize_seller,
)


MAX_EXTRA_PAGES = 4


SCAN_SECONDS = 120


LEGAL_PATTERNS = {
    "Regulamin": r"\b(?:regulamin\w*|terms|warunki[\s-]+sprzedazy)\b",
    "Polityka prywatności": r"\b(?:prywatn\w*|privacy|rodo|gdpr)\b",
    "Zwroty / odstąpienie": r"\b(?:zwrot\w*|odstapien\w*|returns|refund\w*)\b",
    "Kontakt": r"\b(?:kontakt\w*|contact|skontaktuj\w*)\b",
    "Reklamacje": r"\b(?:reklamacj\w*|rekojmi\w*|complaint\w*|warranty)\b",
    "Dostawa i płatności": r"\b(?:dostaw\w*|wysyl\w*|platnos\w*|shipping|delivery|payment)\b",
}


def page_soup(page):
    charset = page["data"].get("charset")
    try:
        return BeautifulSoup(page["data"]["body"], "html.parser", from_encoding=charset)
    except LookupError:
        return BeautifulSoup(page["data"]["body"], "html.parser")


def collect_links(soup, base_url):
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = urljoin(base_url, base_tag["href"])
    links = {}
    for tag in soup.find_all("a", href=True):
        raw = tag["href"].strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            url = normalize_url(urljoin(base_url, raw))
        except (ValueError, UnicodeError):
            continue
        text = tag.get_text(" ", strip=True)
        searchable = plain(text + " " + unquote(urlsplit(url).path))
        labels = [label for label, pattern in LEGAL_PATTERNS.items() if re.search(pattern, searchable)]
        if re.search(r"\b(?:o[\s-]+nas|about|informacje[\s-]+o[\s-]+(?:sklepie|firmie)|informacje[\s-]+prawne|legal|impressum)\b", searchable):
            labels.append("O firmie")
        if labels:
            item = links.setdefault(url, {"url": url, "text": text, "labels": []})
            item["labels"] = sorted(set(item["labels"] + labels))
    return list(links.values())


def rank_company_pages(links, base_url):
    """Kolejność pobierania i jej powód, również dla przyszłego interfejsu WWW."""
    priorities = {"Kontakt": 0, "Regulamin": 1, "O firmie": 2, "Polityka prywatności": 3}
    candidates = []
    seen = {base_url}
    for link in links:
        url = link["url"]
        if url in seen or urlsplit(url).hostname != urlsplit(base_url).hostname:
            continue
        labels = [label for label in link["labels"] if label in priorities]
        if not labels:
            continue
        label = min(labels, key=priorities.get)
        text = plain(link.get("text", "") + " " + unquote(urlsplit(url).path))
        # Ogólne FAQ i newsletter mają mniejszą wartość niż dane firmy.
        secondary = bool(re.search(r"\b(?:faq|newsletter)\b", text))
        candidates.append({"url": url, "text": link.get("text", ""), "category": label,
                           "priority": priorities[label] + (10 if secondary else 0),
                           "reason": "Dopasowany link: " + label,
                           "secondary": secondary})
        seen.add(url)
    return sorted(candidates, key=lambda item: item["priority"])


def choose_company_pages(links, base_url):
    return [item["url"] for item in rank_company_pages(links, base_url)[:MAX_EXTRA_PAGES]]


def content_fingerprint(page):
    """Identyczna odpowiedź HTML nie wymaga powtórnej analizy."""
    return hashlib.sha256(page["data"]["body"]).hexdigest()


def page_details(page):
    """Metadane do raportu; bez dużej zawartości HTML."""
    return {key: value for key, value in page.items() if key != "data"}


def fetch_company_pages(page, soup, links, final_url, deadline, report):
    """Pobiera wybrane podstrony i zapisuje pokrycie analizy w raporcie."""
    host = urlsplit(final_url).hostname
    pages = [(page, soup)]
    seen = {final_url}
    fingerprints = {content_fingerprint(page): final_url}
    candidates = rank_company_pages(links, final_url)
    report["page_selection"] = candidates
    attempts = 0
    for candidate in candidates:
        candidate["status"] = "not_fetched"
    for candidate in candidates:
        # Duplikaty nie zajmują limitu analizy. Liczba żądań też ma limit.
        if len(pages) >= MAX_EXTRA_PAGES + 1 or attempts >= MAX_EXTRA_PAGES * 2:
            break
        sub_url = candidate["url"]
        if sub_url in seen:
            candidate["status"] = "duplicate_url"
            continue
        attempts += 1
        fetched = fetch_resource(sub_url, deadline, allowed_host=host)
        seen.add(sub_url)
        candidate["status"] = fetched["status"]
        if fetched["status"] != "ok":
            report["pages"].append(page_details(fetched))
            continue
        fingerprint = content_fingerprint(fetched)
        duplicate_of = fingerprints.get(fingerprint)
        if fetched["source"] in seen and fetched["source"] != sub_url:
            duplicate_of = fetched["source"]
        seen.add(fetched["source"])
        if duplicate_of:
            candidate["status"] = "duplicate"
            report["duplicates"].append({"source": sub_url, "duplicate_of": duplicate_of})
            continue
        fingerprints[fingerprint] = fetched["source"]
        pages.append((fetched, page_soup(fetched)))
    return pages


def analyze_shop(user_input, skip_vat=False):
    started = utc_now()
    deadline = time.monotonic() + SCAN_SECONDS
    url = normalize_url(user_input)
    report = {"started_at": started, "input_url": url, "checks": {}, "pages": [],
              "schema_version": 2, "links": [], "page_selection": [], "duplicates": [],
              "scope": {"max_extra_pages": MAX_EXTRA_PAGES, "javascript": False},
              "findings": [], "foreign_identifiers": [], "extraction_warnings": [], "limitations": [
                  "Analiza ograniczona do strony startowej i wybranych podstron; bez wykonywania JavaScript.",
                  "Nazwy i role w HTML/JSON-LD są deklaracjami autora strony.",
                  "Brak danych nie oznacza zagrożenia; poprawny TLS lub NIP nie gwarantuje uczciwości.",
                  "Pamięć wyników VAT działa tylko w tej analizie; ponowne uruchomienie zużywa limit API.",
                  "Wykrywanie zagranicznych VAT ID obejmuje obecnie format niemiecki DE; bez weryfikacji rejestrowej.",
              ]}
    page = fetch_resource(url, deadline)
    final_url = page["source"] if page["status"] == "ok" else url
    host = urlsplit(final_url).hostname
    domain = registrable_domain(host)
    report.update({"final_url": final_url, "technical_host": host, "registrable_domain": domain,
                   "redirects": page["data"].get("redirects", [])})
    report["checks"]["domain_age"] = check_domain_age(host, deadline)
    report["checks"]["tls"] = check_tls(host, deadline)
    if domain:
        report["checks"]["mx"] = check_dns(domain, "MX", deadline)
        report["checks"]["spf"] = check_dns(domain, "TXT", deadline, "v=spf1")
        report["checks"]["dmarc"] = check_dns(domain, "TXT", deadline, "v=DMARC1")
    else:
        for key in ("mx", "spf", "dmarc"):
            report["checks"][key] = outcome("unknown", message="Nie ustalono domeny do analizy poczty.")
    if page["status"] != "ok":
        report["pages"].append(page_details(page))
        report["checks"]["legal_links"] = outcome("unknown", source=url, message="Nie pobrano strony startowej.")
        report["seller"] = outcome("unknown", message="Brak HTML do analizy podmiotów.")
        report["finished_at"] = utc_now()
        return report
    soup = page_soup(page)
    links = collect_links(soup, final_url)
    report["links"] = links
    report["checks"]["legal_links"] = outcome("ok", {
        label: [link["url"] for link in links if label in link["labels"]] for label in LEGAL_PATTERNS
    }, final_url, "Dopasowano odnośniki; nie oceniono poprawności dokumentów.")
    pages = fetch_company_pages(page, soup, links, final_url, deadline, report)
    grouped = {}
    for fetched, parsed in pages:
        report["pages"].append({"source": fetched["source"], "status": "ok",
                                "checked_at": fetched["checked_at"],
                                "redirects": fetched["data"].get("redirects", [])})
        evidence, warnings = extract_nips(parsed, fetched["source"])
        for foreign in extract_german_vat_ids(parsed, fetched["source"]):
            if foreign not in report["foreign_identifiers"]:
                report["foreign_identifiers"].append(foreign)
        report["extraction_warnings"].extend(warnings)
        for item in evidence:
            nip = item.pop("nip")
            if item not in grouped.setdefault(nip, []):
                grouped[nip].append(item)
    cache = {}
    lookups = 0
    rate_limited = False
    try:
        checked_date = polish_date()
    except ZoneInfoNotFoundError:
        checked_date = None
    # Wszystkie numery są raportowane; jawni kandydaci sprzedawcy mają priorytet API.
    sorted_items = sorted(grouped.items(), key=lambda item: (
        not any(e["role"] == "seller_declared" for e in item[1]), item[0]))
    for nip, evidence in sorted_items:
        valid = is_valid_nip(nip)
        if not valid:
            vat = outcome("invalid", message="Niepoprawna suma kontrolna; nie odpytano API.")
        elif skip_vat:
            vat = outcome("skipped", message="Sprawdzanie VAT wyłączone opcją --skip-vat.")
        elif checked_date is None:
            vat = outcome("error", message="Brak strefy Europe/Warsaw; zainstaluj tzdata.")
        elif rate_limited or lookups >= MAX_VAT_LOOKUPS:
            vat = outcome("skipped", message="Osiągnięto limit zapytań lub API ograniczyło dostęp.")
        else:
            vat = get_vat_company(nip, checked_date, deadline, cache)
            lookups += 1
            rate_limited = vat["status"] == "rate_limited"
        report["findings"].append({"nip": nip, "checksum_valid": valid, "evidence": evidence,
                                    "vat": vat, "name_comparison": compare_name(vat["data"].get("name"), evidence)})
    report["seller"] = summarize_seller(report["findings"])
    report["finished_at"] = utc_now()
    return report
