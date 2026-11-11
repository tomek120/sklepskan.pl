# SklepRadar

SklepRadar to projekt strony internetowej, która ma pomagać kupującym oceniać ryzyko zakupów w sklepach online na podstawie publicznie dostępnych informacji (OSINT). Użytkownik poda adres sklepu, a serwis przedstawi raport z wykrytymi sygnałami ryzyka, źródłami i wyjaśnieniami.

Projekt rozwijany jako portfolio z zakresu Pythona i cyberbezpieczeństwa.

**Obecny etap:** prototyp mechanizmu analizy w Pythonie, uruchamiany w terminalu. Interfejs internetowy i ocena ryzyka są planowane; obecna wersja zbiera dane i wyświetla wyniki kontroli.

## Działające funkcje

- Wiek domeny na podstawie danych RDAP.
- Weryfikacja certyfikatu TLS oraz odczyt jego wystawcy i wieku.
- Wykrywanie rekordów MX, SPF i DMARC.
- Wyszukiwanie linków do regulaminu, prywatności, zwrotów, kontaktu, reklamacji oraz dostawy i płatności.
- Wyszukiwanie NIP-u na wskazanej stronie i maksymalnie czterech podstronach dotyczących firmy.
- Sprawdzanie sumy kontrolnej NIP-u i wyświetlanie adresów źródeł.

**Technologie:** Python, requests, BeautifulSoup, dnspython.

## Uruchomienie prototypu lokalnie

Wymagania: Python 3 i dostęp do internetu. W folderze z `main.py` utwórz środowisko:

```bash
python -m venv venv
```

Aktywuj je w PowerShellu:

```powershell
.\venv\Scripts\Activate.ps1
```

Lub w Linux / macOS (do utworzenia środowiska użyj `python3`):

```bash
source venv/bin/activate
```

Zainstaluj biblioteki i uruchom program:

```bash
python -m pip install requests dnspython beautifulsoup4
python main.py
```

Podaj domenę, np. `example.com`, albo pełny adres strony. Klucze API nie są potrzebne.

## Ograniczenia

- Brak danych lub błąd pobierania nie oznacza zagrożenia. Program nie wykonuje JavaScript i może pominąć część treści.
- Znaleziony link nie potwierdza poprawności dokumentu, a poprawna suma kontrolna NIP-u nie potwierdza tożsamości firmy.
- Wiek domeny, ważny TLS i obecność rekordów DNS nie gwarantują uczciwości sklepu.
- Analiza obejmuje ograniczoną liczbę podstron i korzysta z dopasowań tekstowych, więc może pomijać informacje lub błędnie je rozpoznawać.
- Prototyp jest przeznaczony do lokalnego użycia. Przed udostępnieniem publicznego formularza URL wymaga ochrony przed SSRF i limitów pobierania danych.

## Plan rozwoju

- Ujednolicić format wyników kontroli i obsługę błędów.
- Dodać testy automatyczne parserów i walidacji.
- Sprawdzać znalezione dane firmy w zewnętrznych rejestrach.
- Opracować ocenę ryzyka z uzasadnieniem i rozróżnieniem braku danych od ostrzeżeń.
- Zbudować backend i interfejs strony z formularzem adresu sklepu oraz raportem.
- Wdrożyć serwis po dodaniu ochrony przed SSRF i limitów zapytań.
