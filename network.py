"""Połączenia HTTP, TLS, DNS i RDAP oraz wspólny format wyników."""
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
import dns.exception
import dns.resolver
import certifi
import tldextract


MAX_PAGE_BYTES = 2_000_000


MAX_REDIRECTS = 5


OPERATION_SECONDS = 10


USER_AGENT = "SklepRadar/0.2 (local research prototype)"


EXTRACT_DOMAIN = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def outcome(status, data=None, source=None, message=""):
    return {"status": status, "data": data or {}, "source": source,
            "message": message, "checked_at": utc_now()}


def plain(value):
    """Normalizacja tekstu tylko do dopasowań, nie do prezentacji źródeł."""
    value = unicodedata.normalize("NFKD", value.casefold().replace("ł", "l"))
    return "".join(c for c in value if not unicodedata.combining(c))


class FetchError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise FetchError("timeout", "Wyczerpano budżet czasu analizy.")
    return min(OPERATION_SECONDS, seconds)


def normalize_url(value):
    value = value.strip()
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Pusty adres lub niedozwolone znaki w URL.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Wymagany jest adres HTTP lub HTTPS z nazwą hosta.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Adres nie może zawierać danych logowania.")
    port = parts.port
    if port not in (None, 443 if scheme == "https" else 80):
        raise ValueError("Dozwolone są tylko standardowe porty HTTP i HTTPS.")
    host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    try:
        address = ipaddress.ip_address(host)
        host_part = f"[{host}]" if address.version == 6 else host
    except ValueError:
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("Niepoprawna nazwa hosta.")
        host_part = host
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="%=&?/:@!$'()*+,;~-._")
    return urlunsplit((scheme, host_part, path, query, ""))


def public_address(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network("64:ff9b::/96"):
            return False
    return (address.is_global and not address.is_multicast
            and not address.is_reserved and not address.is_unspecified)


def resolve_public(host, deadline):
    """Sprawdza wszystkie odpowiedzi A/AAAA. Żadne późniejsze DNS w połączeniu."""
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise FetchError("blocked", "Adres lokalny jest zablokowany.")
        addresses = []
        resolver = dns.resolver.Resolver()
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(host, record_type, lifetime=remaining(deadline),
                                          search=False)
                addresses.extend(record.address for record in answer)
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                raise FetchError("dns_not_found", "Host nie istnieje w DNS.")
            except dns.exception.Timeout:
                raise FetchError("timeout", "Przekroczono czas zapytania DNS.")
            except dns.exception.DNSException:
                raise FetchError("dns_error", "Nie udało się rozwiązać nazwy hosta.")
    if not addresses:
        raise FetchError("dns_not_found", "Brak adresów IP hosta.")
    if not all(public_address(address) for address in addresses):
        raise FetchError("blocked", "Host wskazuje adres niepubliczny lub niedozwolony.")
    return list(dict.fromkeys(addresses))


def create_tls_context():
    """Systemowy magazyn CA uzupełniony zaufanymi korzeniami Mozilla/certifi.

    Nie pobiera certyfikatów od badanego serwera i nie wyłącza weryfikacji.
    Nie naprawi brakującego certyfikatu pośredniego w łańcuchu serwera.
    """
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=certifi.where())
    return context


def connect_public(host, port, use_tls, deadline):
    errors = []
    for address in resolve_public(host, deadline):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(remaining(deadline))
            # Numeryczne IP jest już zweryfikowane. Nie rozwiązujemy hosta ponownie.
            connection.connect((address, port))
            if use_tls:
                connection.settimeout(remaining(deadline))
                connection = create_tls_context().wrap_socket(
                    connection, server_hostname=host)
            return connection
        except ssl.SSLCertVerificationError as error:
            connection.close()
            code = getattr(error, "verify_code", "brak")
            detail = getattr(error, "verify_message", None) or str(error)
            raise FetchError(
                "tls_invalid",
                f"Weryfikacja TLS dla {host} nie powiodła się "
                f"(kod {code}): {detail}. Nie wyłączono kontroli certyfikatu.",
            )
        except FetchError:
            connection.close()
            raise
        except OSError as error:
            connection.close()
            errors.append(error)
    if errors and all(isinstance(e, TimeoutError) for e in errors):
        raise FetchError("timeout", "Przekroczono czas połączenia.")
    raise FetchError("network_error", "Nie udało się połączyć z publicznymi adresami hosta.")


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, use_tls, deadline):
        super().__init__(host, 443 if use_tls else 80, timeout=remaining(deadline))
        self.use_tls = use_tls
        self.deadline = deadline

    def connect(self):
        self.sock = connect_public(self.host, self.port, self.use_tls, self.deadline)


def fetch_resource(url, deadline, kind="html", allowed_host=None):
    """Kontroluje każdy redirect, IP, TLS, typ i rozmiar odpowiedzi."""
    history = []
    current = url
    try:
        current = normalize_url(url)
        for hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if allowed_host and parts.hostname != allowed_host:
                raise FetchError("blocked", "Przekierowanie poza dozwolony host.")
            if current in history:
                raise FetchError("redirect_error", "Pętla przekierowań.")
            history.append(current)
            conn = PinnedConnection(parts.hostname, parts.scheme == "https", deadline)
            response = None
            try:
                target = parts.path + ("?" + parts.query if parts.query else "")
                conn.request("GET", target, headers={
                    "User-Agent": USER_AGENT, "Accept-Encoding": "identity",
                    "Accept": "application/json" if kind == "json" else "text/html,application/xhtml+xml",
                    "Connection": "close",
                })
                conn.sock.settimeout(remaining(deadline))
                response = conn.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location or hop == MAX_REDIRECTS:
                        raise FetchError("redirect_error", "Brak celu lub zbyt wiele przekierowań.")
                    next_url = normalize_url(urljoin(current, location))
                    if parts.scheme == "https" and urlsplit(next_url).scheme == "http":
                        raise FetchError("blocked", "Przekierowanie z HTTPS do HTTP zostało zablokowane.")
                    current = next_url
                    continue
                if response.status != 200:
                    status = "rate_limited" if response.status == 429 else "http_error"
                    return outcome(status, {"http_status": response.status,
                                           "redirects": history}, current,
                                   f"HTTP {response.status}; brak danych do analizy.")
                content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                accepted = (content_type in ("text/html", "application/xhtml+xml")
                            if kind == "html" else
                            content_type == "application/json" or content_type.endswith("+json"))
                if not accepted:
                    raise FetchError("unsupported_type", "Nieoczekiwany typ treści: " + content_type)
                if response.getheader("Content-Encoding", "identity").lower() not in ("", "identity"):
                    raise FetchError("unsupported_encoding", "Serwer zignorował żądanie nieskompresowanej treści.")
                length = response.getheader("Content-Length")
                if length and int(length) > MAX_PAGE_BYTES:
                    raise FetchError("too_large", "Odpowiedź przekracza limit rozmiaru.")
                body = bytearray()
                # Po getresponse() HTTPConnection może oddać własność socketu response.
                # Timeout ustawiono przed odczytem; budżet jest sprawdzany między porcjami.
                while True:
                    remaining(deadline)
                    chunk = response.read1(min(16384, MAX_PAGE_BYTES + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > MAX_PAGE_BYTES:
                        raise FetchError("too_large", "Odpowiedź przekracza limit rozmiaru.")
                return outcome("ok", {"body": bytes(body), "redirects": history,
                                      "charset": response.headers.get_content_charset(),
                                      "content_type": content_type}, current)
            finally:
                if response is not None:
                    response.close()
                conn.close()
    except FetchError as error:
        return outcome(error.status, {"redirects": history}, current, str(error))
    except (TimeoutError, socket.timeout):
        return outcome("timeout", {"redirects": history}, current, "Przekroczono czas odpowiedzi.")
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        return outcome("network_error", {"redirects": history}, current,
                       "Nie udało się odczytać poprawnej odpowiedzi HTTP.")


def fetch_json(url, deadline, allowed_host=None):
    fetched = fetch_resource(url, deadline, "json", allowed_host)
    if fetched["status"] != "ok":
        return fetched
    try:
        payload = json.loads(fetched["data"]["body"])
    except (ValueError, UnicodeError, RecursionError):
        return outcome("invalid_response", source=fetched["source"], message="Niepoprawny JSON.")
    return outcome("ok", {"payload": payload}, fetched["source"])


def registrable_domain(host):
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        extracted = EXTRACT_DOMAIN(host)
        return f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else None


def check_domain_age(host, deadline):
    domain = registrable_domain(host)
    if not domain:
        return outcome("unknown", source=host, message="Nie ustalono domeny rejestrowalnej.")
    source = f"https://rdap.org/domain/{domain}"
    fetched = fetch_json(source, deadline)
    if fetched["status"] != "ok":
        return outcome(
            "unavailable",
            {"domain": domain, "dependency_status": fetched["status"],
             "redirects": fetched["data"].get("redirects", [])},
            fetched["source"] or source,
            "Nie ustalono wieku domeny: nie udało się pobrać danych z usługi RDAP. "
            "To problem odczytu źródła danych, a nie wynik kontroli TLS sklepu. "
            + fetched["message"],
        )
    payload = fetched["data"]["payload"]
    events = payload.get("events") if isinstance(payload, dict) else None
    if events is None:
        return outcome("unknown", {"domain": domain}, source, "Brak zdarzeń rejestracji w odpowiedzi.")
    if not isinstance(events, list):
        return outcome("invalid_response", source=source, message="Niepoprawny typ listy zdarzeń RDAP.")
    dates = []
    try:
        for event in events:
            if not isinstance(event, dict):
                raise ValueError
            if event.get("eventAction") == "registration":
                raw = event.get("eventDate")
                if not isinstance(raw, str):
                    raise ValueError
                registered = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if registered.tzinfo is None or registered > datetime.now(timezone.utc):
                    raise ValueError
                dates.append(registered.astimezone(timezone.utc))
    except (ValueError, TypeError):
        return outcome("invalid_response", source=source, message="Nieprawidłowa data rejestracji RDAP.")
    if not dates:
        return outcome("unknown", {"domain": domain}, source, "Brak daty rejestracji.")
    if len(set(dates)) > 1:
        return outcome("ambiguous", {"domain": domain}, source, "Różne daty rejestracji w RDAP.")
    return outcome("ok", {"domain": domain, "registered_at": dates[0].isoformat(),
                          "age_days": (datetime.now(timezone.utc) - dates[0]).days}, source,
                   "Wiek domeny nie potwierdza wieku sklepu ani jego właściciela.")


def check_tls(host, deadline):
    source = f"{host}:443"
    try:
        with connect_public(host, 443, True, deadline) as connection:
            certificate = connection.getpeercert()
        issuer = dict(pair for group in certificate.get("issuer", ()) for pair in group)
        issued = ssl.cert_time_to_seconds(certificate["notBefore"])
        expires = ssl.cert_time_to_seconds(certificate["notAfter"])
        return outcome("ok", {"host": host, "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                              "age_days": int((time.time() - issued) // 86400),
                              "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat()}, source,
                       "Certyfikat przeszedł weryfikację. Nie potwierdza uczciwości sklepu.")
    except FetchError as error:
        return outcome(error.status, source=source, message=str(error))
    except (OSError, KeyError, ValueError, TypeError):
        return outcome("error", source=source, message="Nie udało się odczytać danych certyfikatu.")


def check_dns(domain, record_type, deadline, prefix=None):
    name = "_dmarc." + domain if prefix == "v=DMARC1" else domain
    source = f"dns:{name}/{record_type}"
    try:
        records = list(dns.resolver.resolve(name, record_type, search=False,
                                           lifetime=remaining(deadline)))
    except dns.resolver.NXDOMAIN:
        return outcome("dns_not_found", source=source, message="Nazwa nie istnieje w DNS.")
    except dns.resolver.NoAnswer:
        return outcome("not_found", source=source, message="Brak rekordu tego typu.")
    except (dns.exception.Timeout, FetchError):
        return outcome("timeout", source=source, message="Przekroczono czas zapytania DNS.")
    except dns.exception.DNSException:
        return outcome("error", source=source, message="Błąd zapytania DNS.")
    if record_type == "MX":
        if any(record.exchange.to_text() == "." for record in records):
            status = "no_mail" if len(records) == 1 else "ambiguous"
            return outcome(status, {"records": [r.to_text() for r in records]}, source,
                           "Wykryto Null MX (deklarację nieprzyjmowania poczty).")
        return outcome("present", {"records": [r.to_text() for r in records]}, source)
    values = [b"".join(record.strings).decode("utf-8", errors="replace") for record in records]
    pattern = r"^v=spf1(?:\s|$)" if prefix == "v=spf1" else r"^v=DMARC1(?:\s*;|\s*$)"
    matches = [value for value in values if re.search(pattern, value, re.IGNORECASE)]
    status = "ambiguous" if len(matches) > 1 else "present" if matches else "not_found"
    return outcome(status, {"records": matches}, source,
                   "Sprawdzono obecność wpisu; bez pełnej walidacji składni i polityki.")
