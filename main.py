"""Interfejs konsolowy. Uruchom: python main.py [domena] [--verbose] [--json raport.json]."""
import argparse
import json
from pathlib import Path
from scanner import (
    analyze_shop,
)


def terminal_text(value):
    # Treść z obcej strony nie może wysyłać sekwencji sterujących do terminala.
    return "".join(c if c.isprintable() else " " for c in str(value))


ROLE_LABELS = {"seller_declared": "tekst sugeruje sprzedawcę (deklaracja)",
               "payment_declared": "tekst sugeruje operatora płatności (deklaracja)",
               "ambiguous": "niejednoznaczny kontekst", "unknown": "rola nieustalona"}


def print_detailed_report(report):
    def say(*parts):
        print(" ".join(terminal_text(part) for part in parts))
    say("Adres wejściowy:", report["input_url"])
    say("Adres końcowy:", report["final_url"])
    say("Host badany technicznie:", report["technical_host"])
    say("Domena rejestrowalna:", report["registrable_domain"] or "nie ustalono")
    if len(report["redirects"]) > 1:
        say("Przekierowania:", " -> ".join(report["redirects"]))
    for label, key in (("Wiek domeny", "domain_age"), ("TLS", "tls"),
                       ("MX", "mx"), ("SPF", "spf"), ("DMARC", "dmarc")):
        check = report["checks"][key]
        print()
        say(label, "| status:", check["status"], "| źródło:", check["source"] or "brak")
        for field, value in check["data"].items():
            say(" ", field + ":", value)
        if check["message"]:
            say(" ", check["message"])
    print("\n--- Linki do informacji ---")
    legal = report["checks"]["legal_links"]
    if legal["status"] == "ok":
        for label, urls in legal["data"].items():
            say(label + ":", "znaleziono odnośnik" if urls else "nie znaleziono pasującego odnośnika")
    else:
        say(legal["message"])
    for link in report.get("links", []):
        say("Odnośnik:", link["text"], "|", link["url"], "|", ", ".join(link["labels"]))
    for item in report.get("page_selection", []):
        say("Wybór:", item["url"], "|", item["reason"], "|", item["status"])
    for item in report.get("duplicates", []):
        say("Duplikat:", item["source"], "| identyczna treść lub adres końcowy:", item["duplicate_of"])
    print("\n--- Pokrycie analizy HTML ---")
    for page in report["pages"]:
        say(page["status"], page["source"], page.get("message", ""))
    print("\n--- Wszystkie znalezione numery NIP ---")
    say("Liczba różnych numerów:", len(report["findings"]))
    if not report["findings"]:
        if not any(page["status"] == "ok" for page in report["pages"]):
            say("Analiza NIP niewykonana — nie pobrano treści strony.")
        else:
            say("Nie znaleziono polskich NIP-ów rozpoznanych przez parser w pobranym HTML.")
    for item in report["findings"]:
        print()
        say("NIP:", item["nip"], "| suma kontrolna:", "poprawna" if item["checksum_valid"] else "niepoprawna")
        for evidence in item["evidence"]:
            say("Źródło:", evidence["source"], "|", evidence["kind"])
            say("Wskazówka roli:", ROLE_LABELS[evidence["role"]])
            say("Kontekst:", evidence["context"])
        vat = item["vat"]
        say("Wykaz VAT | status:", vat["status"])
        if vat["status"] in ("found", "partial"):
            data = vat["data"]
            say("Podmiot przypisany do NIP-u:", data["name"])
            say("Status VAT:", data["vat_status"] or "brak danych")
            say("Adres w rejestrze:", data["working_address"] or data["residence_address"] or "brak danych")
            say("Nazwa rejestrowa w kontekście:",
                {"name_present": "znaleziono zapis nazwy",
                 "name_equivalent": "zgodny zapis po rozwinięciu skrótu formy prawnej",
                 "not_established": "nie ustalono zgodności",
                 "unknown": "brak danych"}[item["name_comparison"]])
        say(vat["message"])
        if vat["data"].get("checked_date"):
            say("Dane na dzień:", vat["data"]["checked_date"])
        if vat["data"].get("request_id"):
            say("Identyfikator zapytania:", vat["data"]["request_id"])
    if report.get("foreign_identifiers"):
        print("\n--- Zagraniczne identyfikatory VAT ---")
        for item in report["foreign_identifiers"]:
            say(item["identifier"], "| kraj:", item["country"], "| niezweryfikowany")
            say("Źródło:", item["source"])
            say("Kontekst:", item["context"])
            say(item["message"])
    for warning in report["extraction_warnings"]:
        say("Uwaga parsera:", warning["message"], warning["source"], warning["context"])
    print("\n--- Wskazanie sprzedawcy ---")
    say(report["seller"]["status"], report["seller"]["message"])
    if report["seller"]["data"]:
        say(report["seller"]["data"])
    for limitation in report["limitations"]:
        say("Uwaga:", limitation)


def print_report(report, verbose=False):
    if verbose:
        print_detailed_report(report)
        return

    def say(*parts):
        print(" ".join(terminal_text(part) for part in parts))

    labels = {"present": "wykryto", "not_found": "nie wykryto",
              "no_mail": "deklaracja nieprzyjmowania poczty", "ambiguous": "niejednoznaczne",
              "dns_not_found": "nazwa nie istnieje w DNS", "skipped": "pominięto",
              "rate_limited": "limit API", "invalid_response": "błędna odpowiedź API",
              "invalid": "niepoprawny numer", "timeout": "przekroczono czas"}
    say("SklepRadar |", report["final_url"])
    if report["input_url"] != report["final_url"]:
        say("Przekierowano z:", report["input_url"])

    age = report["checks"]["domain_age"]
    if age["status"] == "ok" and isinstance(age["data"].get("age_days"), int):
        say("Wiek domeny:", age["data"]["age_days"], "dni")
    elif age["data"].get("dependency_status") == "tls_invalid":
        say("Wiek domeny: brak danych — błąd zaufania TLS usługi RDAP.")
    else:
        say("Wiek domeny: brak danych —", labels.get(age["status"], "odczyt nieudany"))
    tls = report["checks"]["tls"]
    say("TLS sklepu:", "certyfikat zweryfikowany" if tls["status"] == "ok"
        else "certyfikat nie przeszedł weryfikacji" if tls["status"] == "tls_invalid"
        else "brak wyniku (połączenie lub dane niedostępne)")
    say("DNS poczty:", " | ".join(
        key.upper() + ": " + labels.get(report["checks"][key]["status"], "brak danych")
        for key in ("mx", "spf", "dmarc")))
    legal = report["checks"]["legal_links"]
    if legal["status"] == "ok":
        found = [label for label, urls in legal["data"].items() if urls]
        missing = [label for label, urls in legal["data"].items() if not urls]
        say("Linki wykryte:", ", ".join(found) or "brak")
        if missing:
            say("Linki niewykryte:", ", ".join(missing))
    else:
        say("Linki do informacji: brak danych.")
    succeeded = sum(page["status"] == "ok" for page in report["pages"])
    failed = len(report["pages"]) - succeeded
    say("Pobrane strony:", succeeded, "| nieudane:", failed)

    print("\nFirmy i NIP-y:")
    if not report["findings"]:
        if succeeded == 0:
            say("Analiza NIP niewykonana — nie pobrano treści strony.")
        else:
            say("Nie znaleziono polskich NIP-ów rozpoznanych przez parser w pobranym HTML.")
    for item in report["findings"]:
        vat = item["vat"]
        name = vat["data"].get("name")
        say("-", item["nip"], "|", name or "nie ustalono nazwy w wykazie VAT")
        if not item["checksum_valid"]:
            say("  Suma kontrolna niepoprawna; nie odpytano wykazu.")
        elif vat["status"] in ("found", "partial"):
            say("  VAT:", vat["data"].get("vat_status") or "brak danych",
                "| nazwa w źródle:", "zgodny zapis" if item["name_comparison"] in
                ("name_present", "name_equivalent") else "zgodność nieustalona")
        else:
            say("  Wykaz VAT:", labels.get(vat["status"], "brak danych"))
        roles = {e["role"] for e in item["evidence"]} - {"unknown"}
        role = ("ambiguous" if "ambiguous" in roles or len(roles) > 1
                else next(iter(roles)) if roles else "unknown")
        say("  Rola:", ROLE_LABELS[role])
    foreign_numbers = sorted({item["identifier"] for item in report.get("foreign_identifiers", [])})
    if foreign_numbers:
        say("Zagraniczne VAT ID:", ", ".join(foreign_numbers))
        say("  Format DE wykryty; dane firmy i rejestr VAT nie zostały zweryfikowane.")
    seller = report["seller"]
    print()
    if seller["status"] == "declared":
        say("Deklarowany sprzedawca — NIP:", seller["data"]["candidate"])
    elif seller["status"] == "ambiguous":
        say("Sprzedawca: sprzeczne lub niejednoznaczne wskazania.")
    elif succeeded == 0:
        say("Sprzedawca: nie oceniono — brak treści strony.")
    else:
        say("Sprzedawca: nie ustalono jednoznacznego wskazania.")
    if report["extraction_warnings"]:
        say("Ostrzeżenia parsera:", len(report["extraction_warnings"]), "(szczegóły: --verbose)")
    say("Wynik nie potwierdza uczciwości sklepu. Szczegóły: --verbose; zapis: --json raport.json")


def main():
    parser = argparse.ArgumentParser(description="SklepRadar: lokalna analiza publicznych informacji o sklepie.")
    parser.add_argument("url", nargs="?", help="Domena lub URL")
    parser.add_argument("--json", dest="json_path", help="Zapis raportu jako JSON")
    parser.add_argument("--skip-vat", action="store_true", help="Bez zapytań do wykazu VAT")
    parser.add_argument("--verbose", action="store_true", help="Pełny raport: źródła, konteksty i diagnostyka")
    args = parser.parse_args()
    try:
        url = args.url or input("Podaj domenę lub adres sklepu: ").strip()
        report = analyze_shop(url, args.skip_vat)
        print_report(report, verbose=args.verbose)
        if args.json_path:
            # Zapis nowego pliku; nie nadpisujemy istniejącego raportu/kodu.
            with Path(args.json_path).open("x", encoding="utf-8") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
            print("Zapisano raport:", terminal_text(args.json_path))
    except (ValueError, UnicodeError) as error:
        print("Błąd danych:", terminal_text(error))
        return 1
    except OSError as error:
        print("Błąd zapisu lub konfiguracji:", terminal_text(error))
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nPrzerwano analizę.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
