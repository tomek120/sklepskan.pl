const form = document.querySelector('#scan-form');
const button = document.querySelector('#submit');
const progress = document.querySelector('#progress');
const error = document.querySelector('#error');
const result = document.querySelector('#result');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = 'Sprawdzanie…';
  progress.hidden = false;
  error.hidden = true;
  result.replaceChildren();
  document.querySelector('#empty').hidden = true;
  try {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content},
      body: JSON.stringify({address: document.querySelector('#address').value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Nie udało się wykonać analizy.');
    // HTML pochodzi z naszego szablonu Jinja, który escapuje dane skanowanych stron.
    result.innerHTML = data.html;
    result.focus();
    document.querySelector('#download').addEventListener('click', () => {
      const file = new Blob([JSON.stringify(data.report, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(file);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'sklepskan-raport.json';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  } catch (problem) {
    error.textContent = problem instanceof TypeError ? 'Utracono połączenie. Sprawdź, czy serwer działa w terminalu. Analiza na serwerze mogła nadal trwać.' : problem.message;
    error.hidden = false;
    document.querySelector('#empty').hidden = false;
  } finally {
    progress.hidden = true;
    button.disabled = false;
    button.textContent = 'Sprawdź sklep →';
  }
});
