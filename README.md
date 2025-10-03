# URLsafe

🔒 URLSafe — Suspicious URL Checker

URLSafe is a simple web app that detects whether a given URL is safe, suspicious, or malicious.
It combines custom heuristic rules (like spotting suspicious keywords or domains) with Google’s Safe Browsing API for double protection.

✨ Features

🛡️ Heuristic Analysis

Detects suspicious patterns (e.g., login, reset, banking).

Flags shorteners (e.g., bit.ly, tinyurl).

Checks for unusually long URLs, multiple subdomains, or strange characters.

Identifies if a raw IP address is used instead of a domain.

🌍 Google Safe Browsing Integration

Uses Google’s official API to cross-check URLs against known malware, phishing, and harmful sites.

🎨 Frontend (Bootstrap)

Simple and clean interface with an input box for the URL and a results display area.

⚙️ Modular Rule Engine (OOP)

Easy to extend with new rules (e.g., suspicious TLDs, entropy-based checks, typo-squatting).

🚀 Getting Started
Prerequisites

Node.js
 v16+

npm

A Google Safe Browsing API Key

Installation
# Clone the repo
git clone https://github.com/your-username/urlsafe.git
cd urlsafe

# Install dependencies
npm install

Environment Setup

Create a .env file in the root directory:

GOOGLE_API_KEY=your_google_api_key_here

🖥️ Running the App

Start the server:

node server.js


By default, the app runs on:
👉 http://localhost:3000

Open it in your browser and paste a URL to test.

🔍 API Endpoints
POST /check-url

Checks a given URL for suspicious or malicious patterns.

Request:

{
  "url": "http://bit.ly/fake-login"
}


Response:

{
  "url": "http://bit.ly/fake-login",
  "verdict": "suspicious",
  "reasons": [
    "Uses URL shortener",
    "Contains suspicious keywords: login"
  ]
}

🧪 Testing Safely

Google provides Safe Browsing test URLs for simulation:

✅ Safe: https://testsafebrowsing.appspot.com/s/any

🚨 Malware: https://testsafebrowsing.appspot.com/s/malware.html

🚨 Social Engineering: https://testsafebrowsing.appspot.com/s/social_engineering.html

⚠️ Always test in a virtual machine or sandbox environment when working with untrusted links.

📦 Project Structure
/urlsafe
 ├── index.html        # Frontend UI (Bootstrap)
 ├── style.css         # Optional custom styles
 ├── script.js         # Frontend logic
 ├── server.js         # Express backend & API
 ├── .env              # Google API Key
 ├── package.json
 └── README.md
