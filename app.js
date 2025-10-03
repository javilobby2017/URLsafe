const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();
const app = express();
app.use(express.json());

// Serve static files (CSS, JS, images)
app.use(express.static(__dirname));

// Serve the main HTML file
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

// Enhanced URL checking endpoint
app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ error: "URL is required" });

  console.log("Checking URL:", url); // Debug log

  // Enhanced heuristic checks
  const suspiciousPatterns = [
    "login", "verify", "update", "reset", "change", "banking", 
    "account", "security", "confirm", "validate", "password",
    "phishing", "scam", "fake", "suspicious"
  ];
  
  const suspiciousDomains = [
    "bit.ly", "tinyurl.com", "shorturl.at", "t.co", "goo.gl",
    "ow.ly", "is.gd", "v.gd", "short.link"
  ];
  
  const isIP = /^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url);
  const hasSuspiciousPattern = suspiciousPatterns.some(word =>
    url.toLowerCase().includes(word)
  );
  const hasSuspiciousDomain = suspiciousDomains.some(domain =>
    url.toLowerCase().includes(domain)
  );
  const isTooLong = url.length > 200;
  const hasMultipleSubdomains = (url.match(/\./g) || []).length > 3;
  const hasUnusualCharacters = /[^\w\-\.\/\:\?\=\&]/.test(url);

  // Debug logs
  console.log("Detection results:", {
    isIP,
    hasSuspiciousPattern,
    hasSuspiciousDomain,
    isTooLong,
    hasMultipleSubdomains,
    hasUnusualCharacters
  });

  class UrlChecker {
    constructor(url,rules) {
        this.url = url;
        this.rules = rules;
        this.verdict = "safe";
        this.reasons = [];
    }

    runAllChecks(){
        for (let rule of this.rules) {
            const reason = rule(this.url);
            if (reason) {
                this.verdict = "suspicious";
                this.reasons.push(reason);
            }
        }
        return { verdict: this.verdict, reasons: this.reasons };
    }

}

//define rules as functions 
const checkSuspiciousPattern = url => {
  const found = suspiciousPatterns.find(pattern => url.toLowerCase().includes(pattern));
  return found ? `Constains suspicious keywords: "${found}"` : null;
};

const checkTLD = url => {
  const suspiciousTLDs = ["xxx", "pw", "shop", "cc", "biz", "info", "net", "org", "com", "edu", "gov", "mil", "int", "io", "me", "biz", "info", "net", "org", "com", "edu", "gov", "mil", "int", "io", "me"];
  const tld = url.split(".").pop().split("/")[0].toLowerCase();
  return suspiciousTLDs.includes(tld) ? `Suspicious TLD: .${tld}` : null;
};

const checkRedirects = async url => {
  try {
    const response = await axios.head(url, {maxRedirects: 0});
    return null; //no redirects
  } catch (error) {
    if (err.response && err.response.status >= 300 && err.response.staus < 400)
      return "URL redirects to another location (possible cloaking)";
  }
  return null;

}

const rules = [
    checkSuspiciousPattern,
    checkTLD,
    checkRedirects,
    url => /^\d{1,3}(\.\d{1,3}){3}$/.test(url) ? "Uses IP address instead of domain name" : null,
    url => url.length > 200 ? "URL is unusually long" : null,
    url => shorteners.some(domain => url.includes(domain)) ? "Uses URL shortener" : null,
    url => !url.startsWith("https://") ? "Does not use https" : null,
];

const shorteners = [
    "login", "verify", "update", "reset", "change", "banking", 
    "account", "security", "confirm", "validate", "password",
    "phishing", "scam", "fake", "suspicious"
]



const checker = new UrlChecker(url, rules);
console.log(checker.runAllChecks());
  
  let verdict = checker.verdict;
  let reasons = checker.reasons;
  
  // if (isIP) {
  //   verdict = "suspicious";
  //   reasons.push("Uses IP address instead of domain name");
  // }
  // if (hasSuspiciousPattern) {
  //   verdict = "suspicious";
  //   reasons.push("Contains suspicious keywords");
  // }
  // if (hasSuspiciousDomain) {
  //   verdict = "suspicious";
  //   reasons.push("Uses URL shortener");
  // }
  // if (isTooLong) {
  //   verdict = "suspicious";
  //   reasons.push("URL is unusually long");
  // }
  // if (hasMultipleSubdomains) {
  //   verdict = "suspicious";
  //   reasons.push("Has multiple subdomains");
  // }
  // if (hasUnusualCharacters) {
  //   verdict = "suspicious";
  //   reasons.push("Contains unusual characters");
  // }

  // console.log("Final verdict:", verdict, "Reasons:", reasons); // Debug log

  // Google Safe Browsing API check
  if (process.env.GOOGLE_API_KEY) {
    try {
      const response = await axios.post(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
        {
          client: { 
            clientId: "url-checker", 
            clientVersion: "1.0" 
          },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }
      );

      if (response.data.matches && response.data.matches.length > 0) {
        verdict = "malicious";
        reasons.push("Detected by Google Safe Browsing");
      }
    } catch (error) {
      console.error("Safe Browsing error:", error.message);
    }
  } else {
    console.warn("No Google API key found, skipping Safe Browsing check");
  }

  res.json({ 
    url, 
    verdict, 
    reasons: reasons.length > 0 ? reasons : ["No suspicious patterns detected"]
  });
});