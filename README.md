# TrustLens — Website Trust Score Analyzer

Professional website security analysis with 13 checks: HTTPS, URL structure, WHOIS age, SSL certificate, Google Safe Browsing, Gemini AI risk assessment, and more.

## Run Locally

**Prerequisites:** Node.js 18+

1. Install dependencies:
   ```
   npm install
   ```
2. Copy `.env.example` to `.env` and add your API keys:
   ```
   GOOGLE_SAFE_BROWSING_API_KEY="your_key_here"
   GEMINI_API_KEY="your_key_here"
   ```
3. Run the app (starts both frontend on port 3000 and backend on port 3001):
   ```
   npm run dev:all
   ```
4. Open http://localhost:3000 in your browser
