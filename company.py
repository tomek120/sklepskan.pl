"""Odczytywanie identyfikatorów firm i sprawdzanie polskiego wykazu VAT."""
import copy
import json
import re
from datetime import datetime
from urllib.parse import urlencode, urlsplit
from zoneinfo import ZoneInfo
from bs4 import NavigableString, Tag
from network import (
    fetch_json,
    outcome,
    plain,
)


MAX_VAT_LOOKUPS = 10


VAT_BASE = "https://wykazpodatnikowvat.mf.gov.pl/api"


def normalize_nip(value):
    return re.sub(r"[\s\-\u2010-\u2015]", "", str(value)).removeprefix("PL")


def is_valid_nip(value):
    nip = normalize_nip(value)
    if not re.fullmatch(r"[0-9]{10}", nip) or len(set(nip)) == 1:
        return False
    weights = [6, 5, 7, 2, 3, 4, 5, 6, 7]
    return sum(int(digit) * weight for digit, weight in zip(nip[:9], weights)) % 11 == int(nip[9])


NIP_PATTERN = re.compile(
    r"\b(?:NIP(?:[\s-]*UE)?(?:\s*/\s*VAT\s*ID)?|VAT\s*ID)\b"
    r"\s*[:=]?\s*(?:PL\s*:?\s*)?"
    r"(?P<number>[0-9](?:[ \t\u00a0\-\u2010-\u2015]*[0-9])*)"
    r"(?![\w]|[ \t\u00a0\-\u2010-\u2015]*[0-9])",
    re.IGNORECASE,
)


BLOCK_TAGS = {"p", "div", "section", "article", "footer", "header", "li", "tr",
              "dt", "dd", "address", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}


def text_blocks(soup):
    """Nie łączy numerów z osobnych akapitów; zachowuje relację dt -> dd."""
    root = copy.deepcopy(soup)
    for tag in root.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()
    for tag in list(root.find_all(attrs={"hidden": True})):
        if tag.parent:
            tag.decompose()
    for tag in root.find_all("dd"):
        previous = tag.find_previous_sibling()
        if previous and previous.name == "dt":
            label = previous.get_text(" ", strip=True)
            if re.fullmatch(r"(?:NIP(?:\s*/\s*VAT\s*ID)?|VAT(?:\s*ID)?|Numer VAT|USt[.-]?\s*IdNr[.]?|Sprzedawca|Właściciel sklepu|Operator(?: płatności)?)\s*:?", label, re.IGNORECASE):
                tag.insert(0, label + " ")
    blocks = []
    def visit(node):
        buffer = []
        def flush():
            text = re.sub(r"\s+", " ", " ".join(buffer)).strip()
            if text:
                blocks.append(text)
            buffer.clear()
        def inline(child):
            if isinstance(child, NavigableString):
                buffer.append(str(child))
            elif isinstance(child, Tag):
                if child.name in BLOCK_TAGS:
                    flush()
                    visit(child)
                else:
                    for nested in child.children:
                        inline(nested)
        for child in node.children:
            inline(child)
        flush()
    visit(root)
    return blocks


def declared_role(context):
    text = plain(context)
    seller = bool(re.search(r"\b(?:sprzedawca|sprzedawcy|sprzedawce|wlasciciel\s+sklepu)\b", text))
    payment = bool(re.search(r"\b(?:operator\w*\s+platnos\w*|dostawc\w*\s+uslug\s+platniczych|instytucj\w*\s+platnicz\w*)\b", text))
    if seller and payment:
        return "ambiguous"
    if seller:
        return "seller_declared"
    if payment:
        return "payment_declared"
    return "unknown"


def adjacent_company_context(blocks, index):
    """Połącz kompletny NIP z bezpośrednią, poprzedzającą deklaracją firmy.

    Nie skleja cyfr między akapitami. Dopuszcza tylko NIP na początku bloku,
    bez poprzedniego NIP-u i z jednoznaczną etykietą w maks. dwóch blokach.
    Nie łączy dowolnego tekstu z całej strony.
    """
    block = blocks[index]
    if not NIP_PATTERN.match(block) or index == 0:
        return block, False
    previous = blocks[index - 1]
    label = r"(?:sprzedawca|wlasciciel\s+sklepu|operator\s+platnosci)"
    if len(previous) > 400 or NIP_PATTERN.search(previous):
        return block, False
    # Np. <p>Sprzedawca – Podwysocki sp.j., adres...</p><p>NIP ...</p>
    if re.match(r"^" + label + r"(?:\s*[:–—-]\s*|\s+)[A-Z0-9]", plain(previous), re.I):
        if declared_role(previous) in ("seller_declared", "payment_declared"):
            return previous + " | " + block, True
    # Np. <p>Sprzedawca:</p><p>PAN SADZONKA SPÓŁKA ...</p><p>NIP ...</p>
    if index >= 2 and re.fullmatch(label + r"\s*[:–—-]?", plain(blocks[index - 2])):
        # Krótki blok musi wyglądać jak nazwa firmy; nie dowolny nagłówek.
        legal_form = r"\b(?:spolka|sp\s*[.]|s[.]\s*a[.])"
        if re.search(legal_form, plain(previous)):
            return blocks[index - 2] + " | " + previous + " | " + block, True
    return block, False


def extract_nips(soup, source):
    evidence = []
    warnings = []
    blocks = text_blocks(soup)
    for index, block in enumerate(blocks):
        combined_block, adjacent = adjacent_company_context(blocks, index)
        matches = list(NIP_PATTERN.finditer(block))
        block_nips = {normalize_nip(m.group("number")) for m in matches}
        for match in matches:
            raw = match.group("number")
            nip = normalize_nip(raw)
            start = max(0, match.start() - 220)
            end = min(len(block), match.end() + 220)
            # Nie pokazuj urwanych słów, np. "rator" zamiast "Operator".
            while start > 0 and not block[start - 1].isspace():
                start -= 1
            while end < len(block) and not block[end].isspace():
                end += 1
            context = ("…" if start else "") + block[start:end] + ("…" if end < len(block) else "")
            if len(nip) != 10:
                warnings.append({"source": source, "context": context,
                                 "message": "Odrzucono niejednoznaczny ciąg cyfr przy etykiecie NIP/VAT ID."})
                continue
            # Do analizy roli używaj całego lokalnego bloku. Skrót służy tylko
            # do wyświetlania. W bloku z różnymi NIP-ami nie przypisuj roli firmie.
            use_full_block = len(block_nips) == 1 and len(block) <= 5000
            analysis_context = combined_block if use_full_block else context
            role = declared_role(analysis_context) if use_full_block else "ambiguous"
            if adjacent and use_full_block:
                context = analysis_context
            item = {"nip": nip, "source": source, "context": context,
                    "analysis_context": analysis_context,
                    "kind": "html", "role": role,
                    "role_basis": (
                        ("Bezpośrednia deklaracja firmy w sąsiednich blokach; deklaracja strony."
                         if adjacent else "Słowa w całym lokalnym bloku zawierającym jeden NIP; deklaracja strony.")
                        if use_full_block else
                        "Różne numery NIP w jednym bloku lub zbyt obszerny blok; nie przypisano roli."
                    )}
            if item not in evidence:
                evidence.append(item)
    # JSON-LD to deklaracja autora strony, nie niezależny rejestr.
    for script in soup.find_all("script", attrs={"type": re.compile(r"^application/ld\+json$", re.I)}):
        try:
            payload = json.loads(script.string or script.get_text())
        except (ValueError, TypeError, RecursionError):
            continue
        stack = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
                for key in ("taxID", "vatID"):
                    value = node.get(key)
                    if not isinstance(value, str):
                        continue
                    nip = normalize_nip(value.upper())
                    if not re.fullmatch(r"[0-9]{10}", nip):
                        continue
                    name = node.get("name")
                    context = json.dumps({key: value, "name": name if isinstance(name, str) else None}, ensure_ascii=False)
                    item = {"nip": nip, "source": source, "context": context[:600],
                            "kind": "json_ld", "role": "unknown",
                            "role_basis": "Dane strukturalne zadeklarowane przez stronę."}
                    if item not in evidence:
                        evidence.append(item)
    return evidence, warnings


def extract_german_vat_ids(soup, source):
    """Wykrywa deklarowany VAT DE + 9 cyfr; bez potwierdzenia w rejestrze.

    Celowo nie stosuje polskiej sumy kontrolnej ani API MF. Inne kraje
    wymagają osobnych formatów i osobnej obsługi.
    """
    pattern = re.compile(
        r"\b(?:NIP|(?:numer\s+)?VAT(?:\s+(?:ID|number|registration\s+number))?"
        r"|USt[.-]?\s*IdNr[.]?)\s*:?\s*"
        r"DE\s*(?P<number>[0-9](?:[ \t.\-]*[0-9])*)"
        r"(?!\w|[ \t.\-]*[0-9])", re.IGNORECASE)
    items = []
    for block in text_blocks(soup):
        for match in pattern.finditer(block):
            digits = re.sub(r"[ \t.\-]", "", match.group("number"))
            if len(digits) != 9:
                continue
            context = block[max(0, match.start() - 180):match.end() + 100]
            item = {"identifier": "DE" + digits, "country": "DE", "source": source,
                    "context": context, "verification_status": "not_checked",
                    "message": "Wykryto format niemieckiego VAT ID. Nie sprawdzono rejestru ani przypisania do firmy."}
            if item not in items:
                items.append(item)
    # Dane strukturalne również traktujemy jedynie jako deklarację strony.
    for script in soup.find_all("script", attrs={"type": re.compile(r"^application/ld\+json$", re.I)}):
        try:
            payload = json.loads(script.string or script.get_text())
        except (ValueError, TypeError, RecursionError):
            continue
        stack = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
                for key in ("vatID", "taxID"):
                    raw = node.get(key)
                    if not isinstance(raw, str):
                        continue
                    normalized = re.sub(r"[\s.-]", "", raw).upper()
                    if re.fullmatch(r"DE[0-9]{9}", normalized):
                        items.append({"identifier": normalized, "country": "DE", "source": source,
                                      "context": json.dumps({key: raw, "name": node.get("name")}, ensure_ascii=False)[:600],
                                      "verification_status": "not_checked",
                                      "message": "Numer z JSON-LD; deklaracja niepotwierdzona w rejestrze."})
    return items


def polish_date():
    return datetime.now(ZoneInfo("Europe/Warsaw")).date().isoformat()


def validate_vat_payload(payload, nip, checked_date, source):
    data = {"requested_nip": nip, "checked_date": checked_date}
    if not isinstance(payload, dict) or not isinstance(payload.get("result"), dict):
        return outcome("invalid_response", data, source, "Brak poprawnego obiektu result.")
    result = payload["result"]
    if "subject" not in result:
        return outcome("invalid_response", data, source, "Brak pola subject; nie oznacza to braku firmy.")
    request_id = result.get("requestId")
    data["request_id"] = request_id if isinstance(request_id, str) else None
    subject = result["subject"]
    if subject is None:
        return outcome("not_found", data, source, "Brak podmiotu w wykazie na wskazany dzień; nie jest to dowód nieistnienia firmy.")
    if not isinstance(subject, dict):
        return outcome("invalid_response", data, source, "Niepoprawny typ danych podmiotu.")
    returned_nip = subject.get("nip")
    name = subject.get("name")
    if not isinstance(returned_nip, str) or normalize_nip(returned_nip) != nip:
        return outcome("invalid_response", data, source, "NIP z odpowiedzi jest brakujący lub inny niż wysłany.")
    if not isinstance(name, str) or not name.strip():
        return outcome("invalid_response", data, source, "Brak nazwy podmiotu w odpowiedzi.")
    for field in ("statusVat", "workingAddress", "residenceAddress", "regon", "krs"):
        if subject.get(field) is not None and not isinstance(subject[field], str):
            return outcome("invalid_response", data, source, "Nieoczekiwany typ pola: " + field)
    data.update({"nip": nip, "name": name.strip(), "vat_status": subject.get("statusVat"),
                 "working_address": subject.get("workingAddress"),
                 "residence_address": subject.get("residenceAddress"),
                 "regon": subject.get("regon"), "krs": subject.get("krs")})
    status = "found" if data["vat_status"] in ("Czynny", "Zwolniony", "Niezarejestrowany") else "partial"
    return outcome(status, data, source, "Dane podmiotu w wykazie VAT; nie potwierdzają jego związku z domeną.")


def get_vat_company(nip, checked_date, deadline, cache):
    nip = normalize_nip(nip)
    if not is_valid_nip(nip):
        return outcome("invalid", message="Niepoprawny zapis lub suma kontrolna NIP-u.")
    key = (nip, checked_date)
    if key in cache:
        return copy.deepcopy(cache[key])
    source = VAT_BASE + "/search/nip/" + nip + "?" + urlencode({"date": checked_date})
    fetched = fetch_json(source, deadline, urlsplit(VAT_BASE).hostname)
    if fetched["status"] == "ok":
        result = validate_vat_payload(fetched["data"]["payload"], nip, checked_date, source)
    else:
        result = outcome(fetched["status"], {"requested_nip": nip, "checked_date": checked_date},
                         source, fetched["message"])
    cache[key] = result
    return copy.deepcopy(result)


def normalize_company_name(text, expand_legal_form=False):
    normalized = re.sub(r"[^a-z0-9]+", " ", plain(text)).strip()
    if expand_legal_form:
        # Rozwijaj znany skrót, zamiast usuwać formę prawną lub stosować
        # podobieństwo tekstu, które mogłoby połączyć różne podmioty.
        normalized = re.sub(
            r"\b(?:sp|spolka)\s+z\s+(?:o\s+o|oo)\b",
            "spolka z ograniczona odpowiedzialnoscia",
            normalized,
        )
        normalized = re.sub(r"\bsp\s+j\b", "spolka jawna", normalized)
    return normalized


def compare_name(name, evidence):
    if not name:
        return "unknown"
    for expand in (False, True):
        expected = normalize_company_name(name, expand)
        for item in evidence:
            context = normalize_company_name(item.get("analysis_context", item["context"]), expand)
            if expected and re.search(r"(?<!\w)" + re.escape(expected) + r"(?!\w)", context):
                return "name_equivalent" if expand else "name_present"
    # Marka może różnić się od nazwy firmy: brak dopasowania nie jest sprzecznością.
    return "not_established"


def summarize_seller(findings):
    candidates = []
    conflicts = []
    for item in findings:
        if not is_valid_nip(item["nip"]):
            continue
        roles = {e["role"] for e in item["evidence"]}
        if "ambiguous" in roles or {"seller_declared", "payment_declared"} <= roles:
            conflicts.append(item["nip"])
        elif "seller_declared" in roles:
            candidates.append(item["nip"])
    if conflicts or len(candidates) > 1:
        return outcome("ambiguous", {"candidates": candidates, "conflicts": conflicts},
                       message="Różne lub sprzeczne wskazania sprzedawcy. Wymagana analiza źródeł.")
    if len(candidates) == 1:
        return outcome("declared", {"candidate": candidates[0]},
                       message="Tekst sugeruje rolę sprzedawcy. To deklaracja strony, nie potwierdzenie właściciela domeny.")
    return outcome("unknown", message="Nie ustalono jednoznacznego wskazania sprzedawcy.")
