# DNS Propagation Checker 🌍

Una webapp containerizzata per visualizzare la propagazione dei record DNS in tutto il mondo, con interfaccia moderna, mappa interattiva e tema notte.

---

## 🚀 Funzionalità principali
- **Verifica DNS per nazione** tramite EDNS Client Subnet (ECS) su Google DoH.
- **Mappa Leaflet interattiva** con marker verdi/rossi (OK/KO).
- **UI moderna e responsive** con TailwindCSS.
- **Tema notte soft** 🌙 con toggle persistente (salvato in localStorage).
- **Completamente containerizzata**: pronta all'uso con Docker Compose.

---

## 📦 Struttura del progetto
```
dns-propagation-checker/
├── app.py
├── static/
│   └── index.html
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## ⚙️ Installazione e avvio

### 1️⃣ Clona o estrai il progetto
```bash
unzip dns-propagation-checker-soft-night-fixed.zip
cd dns-propagation-checker-soft-night-fixed
```

### 2️⃣ Avvia con Docker Compose
```bash
docker compose up --build
```
Apri poi **http://localhost:8080** nel browser.

---

## 🌐 API
**Endpoint:** `/api/check`  
Esegue la verifica DNS parallela per tutti i paesi configurati.

### Parametri:
| Nome | Tipo | Descrizione |
|------|------|--------------|
| `name` | string | Dominio da verificare (es. `www.example.com`) |
| `rtype` | string | Tipo record (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`) |

### Esempio:
```
GET /api/check?name=www.example.com&rtype=A
```

### Risposta JSON (esempio):
```json
{
  "query": {"name": "www.example.com", "type": "A"},
  "results": [
    {
      "resolver": "Italy (IT)",
      "transport": "doh-ecs",
      "status": "ok",
      "rcode": 0,
      "answers": [{"data": "93.184.216.34", "ttl": 86400, "type": "A"}],
      "geo": {"lat": 41.9, "lng": 12.49, "label": "Rome"}
    }
  ]
}
```

---

## 🧭 Configurazione paesi
Nel file `app.py`, i punti di vantage DNS sono definiti in `COUNTRY_POINTS`:
```python
{"code": "IT", "name": "Italy", "ecs": "151.0.0.0/24", "geo": {"lat": 41.9, "lng": 12.49, "label": "Rome"}}
```
Puoi aggiungere altri paesi modificando ECS e coordinate.

---

## 🎨 Personalizzazione tema
Le variabili CSS principali si trovano in `index.html`:

```css
:root {
  --bg: #f3f4f6;
  --card: #f9fafb;
  --text: #1e293b;
  --accent: #0284c7;
}
html[data-theme='night'] {
  --bg: #0f172a;
  --card: #0b1220;
  --text: #e5e7eb;
  --accent: #38bdf8;
}
```

---

## 🧰 Tecnologie utilizzate
- **FastAPI**
- **httpx**
- **Leaflet.js**
- **TailwindCSS**
- **Docker / Docker Compose**

---

## 💡 Possibili estensioni
- Salvare snapshot su database (SQLite/PostgreSQL).
- Grafici temporali per la propagazione.
- Integrazione con DNSSEC o altri resolver.
- Dashboard multi-dominio.

---

## 📝 Licenza
Rilasciato sotto licenza **MIT**.
