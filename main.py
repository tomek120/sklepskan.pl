import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import requests
from bs4 import BeautifulSoup


LEGAL_PAGES = {
    "Regulamin": [
        "regulamin", "warunki-korzystania", "warunki-sprzedaży",
        "warunki-sprzedazy", "ogólne-warunki", "ogolne-warunki", "owh",
        "terms", "tos",
    ],
    "Polityka prywatności": [
        "prywatność", "prywatnosc", "prywatności", "prywatnosci",
        "ochrona-danych", "ochrona-prywatności", "ochrona-prywatnosci",
        "rodo", "gdpr", "dane-osobowe", "przetwarzanie-danych", "privacy",
    ],
    "Zwroty / odstąpienie": [
        "zwrot", "odstąpien", "odstapien", "formularz-odstąpienia",
        "formularz-odstapienia", "wzór-odstąpienia", "wzor-odstapienia",
        "14-dni", "wymiana", "returns", "return-policy", "refund", "withdrawal",
    ],
    "Kontakt": [
        "kontakt", "skontaktuj", "napisz-do-nas", "contact",
    ],
    "Reklamacje": [
        "reklamacj", "gwarancja", "rękojmia", "rekojmia", "complaint", "warranty",
    ],
    "Dostawa i płatności": [
        "dostaw", "wysyłka", "wysylka", "czas-realizacji", "płatność",
        "platnosc", "płatności", "platnosci", "shipping", "delivery", "payment",
    ],
}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; sklepradar/0.1)"}
MAX_EXTRA_PAGES = 4


def get_registration_date(domain):
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if response.status_code != 200:
            return None
        data = response.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                return event.get("eventDate")
    except (requests.RequestException, ValueError):
        return None
    return None


def calculate_age_in_days(date_text):
    date = datetime.fromisoformat(date_text.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - date).days


def get_certificate(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as secure_connection:
                return secure_connection.getpeercert()
    except OSError:
        return None


def get_issuer_name(certificate):
    for item in certificate.get("issuer", []):
        for key, value in item:
            if key == "organizationName":
                return value
    return "unknown"


def calculate_certificate_age_in_days(certificate):
    issued_at = ssl.cert_time_to_seconds(certificate["notBefore"])
    return int((time.time() - issued_at) / 86400)


def get_dns_records(name, record_type):
    return list(dns.resolver.resolve(name, record_type, lifetime=10))


def get_txt_values(name):
    records = resolve_dns(name, "TXT")
    if records is None:
        return None
    return [b"".join(record.strings).decode("utf-8", errors="replace") for record in records]


def resolve_dns(name, record_type):
    try:
        return get_dns_records(name, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException:
        return None


def mx_record(domain):
    records = resolve_dns(domain, "MX")
    if records is None:
        return None
    return any(record.exchange.to_text() != "." for record in records)


def spf_record(domain):
    values = get_txt_values(domain)
    if values is None:
        return None
    return any(value.lower().startswith("v=spf1") for value in values)


def dmarc_record(domain):
    values = get_txt_values("_dmarc." + domain)
    if values is None:
        return None
    return any(value.startswith("v=DMARC1") for value in values)


def fetch_page(url):
    """Zwraca (HTML, końcowy URL); przy błędzie HTML ma wartość None."""
    try:
        response = requests.get(url, timeout=10, headers=HEADERS)
        if response.status_code != 200:
            print(f"Nie pobrano {url}: HTTP {response.status_code} (brak danych).")
            return None, url
        return response.text, response.url
    except requests.RequestException as error:
        print(f"Nie pobrano {url}: {error}")
        return None, url


def check_legal_pages(html):
    soup = BeautifulSoup(html, "html.parser")
    results = {label: False for label in LEGAL_PAGES}
    for link in soup.find_all("a"):
        text = link.get_text(" ", strip=True).lower()
        href = (link.get("href") or "").lower()
        for label, variants in LEGAL_PAGES.items():
            if any(variant in text or variant in href for variant in variants):
                results[label] = True
    return results


def is_valid_nip(nip):
    nip = re.sub(r"[\s-]", "", str(nip))
    if not re.fullmatch(r"[0-9]{10}", nip) or len(set(nip)) == 1:
        return False
    weights = [6, 5, 7, 2, 3, 4, 5, 6, 7]
    total = sum(int(nip[i]) * weights[i] for i in range(9))
    return total % 11 == int(nip[9])


def find_nips(html):
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style"]):
        element.decompose()
    text = soup.get_text(" ", strip=True)
    pattern = r"\bNIP\b\s*(?:/\s*VAT\s*ID)?\s*:?\s*(?:PL\s*)?([0-9](?:[\s-]*[0-9]){9})(?![0-9])"
    matches = re.findall(pattern, text, flags=re.IGNORECASE)
    nips = []
    for match in matches:
        nip = re.sub(r"[\s-]", "", match)
        if nip not in nips:
            nips.append(nip)
    return nips


def find_company_pages(html, base_url):
    """Znajduje maksymalnie cztery podstrony kontaktu, regulaminu lub firmy."""
    soup = BeautifulSoup(html, "html.parser")
    pages = []
    keywords = ["kontakt", "contact", "regulamin", "terms", "o-nas", "about", "informacje-o-sklepie"]
    base = urlsplit(base_url)
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        text = link.get_text(" ", strip=True).lower()
        if not href or href.startswith("#"):
            continue
        if not any(word in text or word in href.lower() for word in keywords):
            continue
        url = urljoin(base_url, href).split("#", 1)[0]
        target = urlsplit(url)
        if target.scheme not in ("http", "https") or target.netloc != base.netloc:
            continue
        if url != base_url.split("#", 1)[0] and url not in pages:
            pages.append(url)
        if len(pages) >= MAX_EXTRA_PAGES:
            break
    return pages


def show_dns_result(result):
    if result is None:
        return "brak danych (błąd zapytania DNS)"
    return "tak" if result else "NIE"


def main():
    user_input = input("Podaj domenę lub adres sklepu: ").strip()
    url = user_input if "://" in user_input else "https://" + user_input
    try:
        parsed = urlsplit(url)
        domain = parsed.hostname
        if parsed.scheme not in ("http", "https") or not domain:
            raise ValueError("Podaj poprawną domenę lub adres HTTP/HTTPS.")
        if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            raise ValueError("Podaj adres bez danych logowania i niestandardowego portu.")
        domain = domain.encode("idna").decode("ascii")
    except (ValueError, UnicodeError) as error:
        print("Niepoprawny adres:", error)
        return

    print("\n--- Wiek domeny ---")
    date_text = get_registration_date(domain)
    if date_text is None:
        print("Nie udało się pobrać daty rejestracji.")
    else:
        try:
            print(domain, "ma", calculate_age_in_days(date_text), "dni")
        except (ValueError, TypeError):
            print("Nie udało się odczytać daty rejestracji.")

    print("\n--- Certyfikat TLS ---")
    certificate = get_certificate(domain)
    if certificate is None:
        print("Brak ważnego certyfikatu albo nie udało się połączyć.")
    else:
        print("Wystawca:", get_issuer_name(certificate))
        print("Certyfikat wydany", calculate_certificate_age_in_days(certificate), "dni temu")

    print("\n--- DNS ---")
    print("MX:", show_dns_result(mx_record(domain)))
    print("SPF:", show_dns_result(spf_record(domain)))
    print("DMARC:", show_dns_result(dmarc_record(domain)))

    print("\n--- Treść strony ---")
    html, final_url = fetch_page(url)
    if html is None:
        print("Brak danych do analizy treści i NIP-u.")
        return
    print("Sprawdzane linki na stronie:", final_url)
    for label, found in check_legal_pages(html).items():
        print(label + ":", "znaleziono link" if found else "nie znaleziono linku")

    print("\n--- NIP ---")
    sources = {}
    pages = [(final_url, html)]
    for page_url in find_company_pages(html, final_url):
        print("Sprawdzam podstronę:", page_url)
        page_html, resolved_url = fetch_page(page_url)
        if page_html is not None:
            pages.append((resolved_url, page_html))
    for page_url, page_html in pages:
        for nip in find_nips(page_html):
            sources.setdefault(nip, [])
            if page_url not in sources[nip]:
                sources[nip].append(page_url)
    if not sources:
        print("Nie znaleziono NIP-u pasującego do wzorca na pobranych stronach.")
    for nip, urls in sources.items():
        result = "poprawna" if is_valid_nip(nip) else "niepoprawna"
        print(f"NIP: {nip} — suma kontrolna: {result}")
        for source_url in urls:
            print("  Źródło:", source_url)
    print("Poprawna suma kontrolna nie potwierdza tożsamości właściciela sklepu.")


if __name__ == "__main__":
    main()
