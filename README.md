# CTI Dashboard

A dark-themed Cyber Threat Intelligence dashboard that aggregates data from
**VirusTotal**, **AbuseIPDB**, and **Shodan** for any IP, domain, URL, or hash.

## Features

- 0-100 composite risk score with animated ring gauge
- Per-source confidence bars (VT, AbuseIPDB, Shodan)
- Geolocation map (Leaflet.js + CartoDB dark tiles)
- Engine breakdown chart (Chart.js doughnut)
- Open-port & CVE listing from Shodan
- Session history sidebar (last 20 lookups)
- One-click PDF export (WeasyPrint)
- Fully Dockerised

## Quick start

```bash
# 1. Copy env template and fill in your API keys
cp .env.example .env

# 2. Run with Docker
docker compose up --build

# 3. Open http://localhost:5000
```

### Local dev (no Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill keys
flask run
```

## API keys

| Service    | Free tier | Link |
|------------|-----------|------|
| VirusTotal | 500 req/day | https://virustotal.com |
| AbuseIPDB  | 1 000 req/day | https://abuseipdb.com |
| Shodan     | 100 query credits | https://shodan.io |

## Risk scoring

| Range | Label    |
|-------|----------|
| 0–24  | Low      |
| 25–49 | Medium   |
| 50–74 | High     |
| 75–100| Critical |

Score is computed from VT detection ratio (max 45 pts),
AbuseIPDB confidence (max 35 pts), and Shodan vuln/port count (max 20 pts).

## Project structure

```
threat-intel-dashboard/
├── app.py                  Flask application + risk scoring
├── modules/
│   ├── virustotal.py       VirusTotal v3 API wrapper
│   ├── abuseipdb.py        AbuseIPDB v2 API wrapper
│   └── shodan.py           Shodan API wrapper
├── templates/
│   ├── dashboard.html      Main dark UI
│   └── pdf_report.html     WeasyPrint PDF template
├── static/
│   ├── css/style.css       Dark theme design system
│   └── js/main.js          Chart.js + Leaflet + fetch logic
├── reports/                PDF exports (git-ignored)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
