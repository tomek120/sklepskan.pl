"""Lokalna strona SklepSkanu. Start: python app.py."""
import secrets
import threading
from flask import Flask, jsonify, render_template, request, session
from scanner import analyze_shop

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=4096, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Strict')
scan_lock = threading.Lock()


@app.before_request
def local_requests_only():
    # Ochrona lokalnej aplikacji przed obcymi nazwami hosta.
    if request.host not in ('127.0.0.1:5000', 'localhost:5000'):
        return 'Niedozwolony adres serwera.', 400


@app.after_request
def response_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return response


@app.get('/')
def index():
    if 'token' not in session:
        session['token'] = secrets.token_urlsafe(32)
    return render_template('index.html', token=session['token'])


@app.post('/analyze')
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Niepoprawne dane formularza.'), 400
    token = request.headers.get('X-CSRF-Token', '')
    if not session.get('token') or not secrets.compare_digest(token, session['token']):
        return jsonify(error='Odśwież stronę i spróbuj ponownie.'), 403
    address = data.get('address')
    if not isinstance(address, str) or not address.strip() or len(address) > 2048:
        return jsonify(error='Podaj domenę lub adres sklepu (maksymalnie 2048 znaków).'), 400
    if not scan_lock.acquire(blocking=False):
        return jsonify(error='Trwa już analiza. Poczekaj na jej zakończenie.'), 429
    try:
        report = analyze_shop(address.strip())
        html = render_template('report.html', report=report)
        return jsonify(html=html, report=report)
    except (ValueError, UnicodeError):
        return jsonify(error='Niepoprawny adres. Podaj np. sklep.pl lub https://sklep.pl.'), 400
    except Exception:
        app.logger.exception('Nie udało się wykonać analizy')
        return jsonify(error='Analiza nie powiodła się. Szczegóły błędu zapisano w terminalu.'), 500
    finally:
        scan_lock.release()


if __name__ == '__main__':
    # Serwer wyłącznie do lokalnej pracy. Bez publicznego nasłuchiwania i debuggera.
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
