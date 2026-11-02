import socket
import ssl
import time
from datetime import datetime, timezone

import requests


def get_registration_date(domain):
    url = f"https://rdap.org/domain/{domain}"
    response = requests.get(url, timeout=10)

    if response.status_code != 200:
        return None

    data = response.json()
    for event in data.get("events", []):
        if event["eventAction"] == "registration":
            return event["eventDate"]
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
    for item in certificate["issuer"]:
        if item[0][0] == "organizationName":
            return item[0][1]
    return "unknown"


def calculate_certificate_age_in_days(certificate):
    issued_at = ssl.cert_time_to_seconds(certificate["notBefore"])
    return int((time.time() - issued_at) / 86400)


domain = input("Podaj domenę: ")

print("Wiek domeny")
date_text = get_registration_date(domain)
if date_text is None:
    print("Nie udało się pobrać daty rejestracji.")
else:
    print(domain, "ma", calculate_age_in_days(date_text), "dni\n")
print("Certyfikat TLS")
certificate = get_certificate(domain)
if certificate is None:
    print("Brak ważnego certyfikatu albo nie udało się połączyć (sygnał ostrzegawczy).")
else:
    print("Wystawca:", get_issuer_name(certificate))
    print("Certyfikat wydany", calculate_certificate_age_in_days(certificate), "dni temu")
