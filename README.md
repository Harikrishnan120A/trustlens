# TrustLens — AI-Powered Website Trust Analyzer

<div align="center">

**V4.0 — 19 Real-Time Security Checks**

A professional web dashboard that analyzes any URL in real time and produces a trust score (0–100) with a detailed breakdown of security signals, powered by multi-AI analysis.

</div>

---

## Features

### 19 Security Checks

| # | Check | Type | Description |
|---|-------|------|-------------|
| 1 | **HTTPS Verification** | Static | Validates the URL uses a secure protocol |
| 2 | **URL Length Analysis** | Static | Flags unusually long URLs (>75 chars) |
| 3 | **Suspicious Keywords** | Static | Detects phishing keywords (login, verify, secure, account, update, bank, etc.) |
| 4 | **Hyphen Count** | Static | Excessive hyphens in domain indicate spoofing |
| 5 | **IP as Domain** | Static | Flags raw IP addresses instead of domain names |
| 6 | **Subdomain Count** | Static | More than 3 subdomains is suspicious |
| 7 | **Risky TLD** | Static | Checks against known risky top-level domains (.xyz, .top, .click, etc.) |
| 8 | **Typosquatting Detection** | Static | Compares domain to popular sites for misspellings |
| 9 | **Punycode / IDN Homograph** | Static | Detects internationalized domain name attacks |
| 10 | **DNS Resolution** | Live | Resolves domain DNS records to verify the site exists |
| 11 | **Live HTTP Probe** | Live | Sends real HTTP request, tracks redirects, captures response |
| 12 | **Security Headers** | Live | Checks for CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 13 | **Page Content Analysis** | Live | Scans HTML for login forms, hidden iframes, suspicious JS (eval, document.write), meta refresh, crypto miners, data URIs, excessive external resources |
| 14 | **Brand Impersonation** | Live | Detects if page claims to be a known brand (19 brands) but domain doesn't match |
| 15 | **WHOIS Domain Age** | API | Checks domain registration age (newer domains are riskier) |
| 16 | **SSL Certificate** | API | Validates certificate, checks expiry and issuer |
| 17 | **Google Safe Browsing** | API | Queries Google's threat database for known malicious URLs |
| 18 | **VirusTotal Scan** | API | Scans URL against 60+ security vendor engines |
| 19 | **AI Risk Assessment** | AI | Comprehensive AI-generated risk analysis using all collected data |

### Three-Tier AI Fallback

| Priority | Provider | Model |
|----------|----------|-------|
| 1st | Google Gemini | `gemini-2.5-flash` |
| 2nd | Groq | Llama 3.3 70B |
| 3rd | Rule-Based Engine | Local (always available) |

The AI receives all check results, live probe data, page content findings, and brand impersonation signals to produce a contextual risk assessment — not generic keyword matching.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, Vite 6, Tailwind CSS 4 |
| Backend | Express.js 4, Node.js |
| AI | Google Gemini 2.5 Flash, Groq Llama 3.3 70B |
| APIs | Google Safe Browsing v4, VirusTotal v3, WHOIS |
| Animations | Motion (Framer Motion) |
| Icons | Lucide React |

---

## Getting Started

### Prerequisites

- **Node.js** 18 or higher
- **npm** (included with Node.js)

### Installation

1. **Clone the repository:**
   ```bash
   git clone git@github.com:Harikrishnan120A/trustlens.git
   cd trustlens
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your API keys:

   | Key | Required | Free Tier | Get it at |
   |-----|----------|-----------|-----------|
   | `GEMINI_API_KEY` | Recommended | Yes | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
   | `GROQ_API_KEY` | Optional | Yes (30 req/min) | [console.groq.com/keys](https://console.groq.com/keys) |
   | `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | Yes | [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) |
   | `VIRUSTOTAL_API_KEY` | Optional | Yes (4 req/min) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |

   > The app works without any API keys — static checks, live probing, content analysis, and the rule-based AI engine run locally. API keys unlock additional checks.

4. **Start the development server:**
   ```bash
   npm run dev:all
   ```
   This starts:
   - **Backend** on `http://localhost:3001`
   - **Frontend** on `http://localhost:3000`

5. **Open** http://localhost:3000 in your browser.

---

## Project Structure

```
trustlens/
├── server/
│   ├── analyzer.ts      # Core analysis engine (19 checks)
│   ├── index.ts          # Express server (POST /api/analyze)
│   ├── types.ts          # TypeScript interfaces
│   └── whois-json.d.ts   # WHOIS module type declarations
├── src/
│   ├── App.tsx           # React frontend (dashboard UI)
│   ├── main.tsx          # App entry point
│   ├── index.css         # Tailwind CSS styles
│   └── utils/
│       └── analyzer.ts   # Frontend API client
├── .env.example          # API key template
├── index.html            # HTML entry point
├── package.json          # Dependencies & scripts
├── tsconfig.json         # TypeScript configuration
└── vite.config.ts        # Vite config (proxy, ports)
```

---

## API

### `POST /api/analyze`

Analyze a URL and return a trust score with detailed check results.

**Request:**
```json
{
  "url": "https://github.com"
}
```

**Response:**
```json
{
  "score": 100,
  "riskLevel": "SAFE",
  "checks": [
    {
      "name": "HTTPS Verified",
      "passed": true,
      "details": "URL uses secure HTTPS protocol",
      "scoreImpact": 0
    }
  ],
  "domain": {
    "name": "github.com",
    "registrar": "MarkMonitor Inc.",
    "createdDate": "2007-10-09T18:20:50Z"
  }
}
```

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev:all` | Start frontend + backend concurrently |
| `npm run dev` | Start Vite frontend only (port 3000) |
| `npm run server` | Start Express backend only (port 3001) |
| `npm run build` | Build for production |
| `npm run lint` | TypeScript type check |

---

## How It Works

1. **URL Parsing** — Normalizes and validates the input URL
2. **Static Analysis** — 9 instant checks on URL structure and domain patterns
3. **Live Probing** — DNS resolution, HTTP request with redirect tracking, security header inspection
4. **Content Analysis** — Fetches page HTML, scans for phishing patterns, detects brand impersonation
5. **External APIs** — WHOIS lookup, SSL validation, Google Safe Browsing, VirusTotal (parallel)
6. **AI Assessment** — Feeds all results to Gemini/Groq for contextual risk narrative
7. **Scoring** — Aggregates all check impacts into a 0–100 trust score with risk level

---

## License

This project is for educational and personal use.
