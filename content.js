// 🚨 Function 1️⃣: Detect Suspicious URLs (Common Phishing Patterns)
function isPhishingURL(url) {
    const suspiciousPatterns = [
        "free-login", "secure-verify", "account-update", "wallet-connect",
        "paypal-secure", "bank-login", "verify-payment", "update-billing",
        "confirm-identity", "reset-password", "gift-card-redeem"
    ];
    return suspiciousPatterns.some(pattern => url.toLowerCase().includes(pattern));
}

// 🚨 Function 2️⃣: Detect Insecure Websites (No HTTPS)
function isSecureSite() {
    return window.location.protocol === "https:";
}

// 🚨 Function 3️⃣: Extract URL Features for Analysis
function extractURLFeatures(url) {
    let urlObj = new URL(url);
    let domain = urlObj.hostname;

    return {
        url_length: url.length,
        num_dots: (url.match(/\./g) || []).length,
        num_hyphens: (url.match(/-/g) || []).length,
        has_at_symbol: url.includes("@") ? 1 : 0,
        uses_https: url.startsWith("https") ? 1 : 0,
        has_ip_address: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(domain) ? 1 : 0,
        contains_suspicious_keywords: /(secure|bank|login|verify|update|account|paypal)/i.test(url) ? 1 : 0
    };
}

// 🚀 Run URL Feature Extraction & Log Results
const features = extractURLFeatures(window.location.href);
console.log("🔍 Extracted URL Features:", features);

// 🚨 Function 4️⃣: Detect Fake Login Forms (Credential Harvesting)
function detectFakeLoginForms() {
    document.querySelectorAll("form").forEach(form => {
        if (form.innerHTML.toLowerCase().includes("password") && !window.location.hostname.includes("google.com")) {
            alert("⚠️ Warning: Suspicious login form detected!");
        }
    });
}

// 🚨 Function 5️⃣: Detect Suspicious JavaScript Events (Hidden Redirects)
function detectSuspiciousJS() {
    const suspiciousEvents = ["onmouseover", "onfocus", "onclick"];
    suspiciousEvents.forEach(event => {
        if (document.body.innerHTML.includes(event)) {
            alert("⚠️ Warning: Malicious JavaScript detected!");
        }
    });
}

// 🚨 Function 6️⃣: Detect Fake Popups (Social Engineering)
function detectFakePopups() {
    const keywords = ["urgent", "verify", "action required", "your account will be locked"];
    if (keywords.some(word => document.body.innerText.toLowerCase().includes(word))) {
        alert("⚠️ Warning: Possible social engineering attempt!");
    }
}

// 🚨 Function 7️⃣: Detect Invisible Elements (Hidden Phishing Forms)
function detectHiddenElements() {
    if (document.querySelectorAll("input[style*='display:none'], input[style*='visibility:hidden']").length > 0) {
        alert("⚠️ Warning: Hidden form fields detected!");
    }
}

// 🚨 Function 8️⃣: Detect Fake HTTPS (Untrusted SSL Certificates)
function detectFakeHTTPS() {
    fetch(window.location.href).then(response => {
        if (!response.headers.get("Public-Key-Pins")) {
            alert("⚠️ Warning: Untrusted HTTPS certificate detected!");
        }
    }).catch(() => console.error("Failed to check SSL certificate."));
}

// 🚨 Function 9️⃣: Detect Suspicious Redirects (Auto-Redirects)
function detectSuspiciousRedirects() {
    const suspiciousHosts = ["bit.ly", "tinyurl.com", "ow.ly"];
    if (suspiciousHosts.some(host => window.location.href.includes(host))) {
        alert("⚠️ Warning: Suspicious redirect detected!");
    }
}

// 🚨 Function 🔟: Detect Zero-Day Phishing Attacks (Google Safe Browsing API)
async function checkGoogleSafeBrowsing(url) {
    const apiKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"; // Replace with actual API key
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const requestBody = {
        client: { clientId: "phishing-detector", clientVersion: "1.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
        },
    };

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            body: JSON.stringify(requestBody),
            headers: { "Content-Type": "application/json" },
        });

        const data = await response.json();
        if (data.matches) {
            alert("⚠️ Warning: This website is flagged as phishing/malware!");
        }
    } catch (error) {
        console.error("Safe Browsing API error:", error);
    }
}

// 🚨 Function 1️⃣1️⃣: Detect Domain Spoofing (Levenshtein Distance)
function detectDomainSpoofing() {
    const trustedDomains = ["google.com", "paypal.com", "amazon.com"];
    const currentHost = window.location.hostname;

    trustedDomains.forEach(domain => {
        if (levenshteinDistance(domain, currentHost) <= 2) {
            alert(`⚠️ Warning: This domain is similar to ${domain}. Possible spoofing!`);
        }
    });
}

// 🚨 Function 1️⃣2️⃣: Detect Homograph Attacks (Unicode URLs)
function detectHomographAttack() {
    const currentHost = window.location.hostname;
    try {
        const punycodeHost = new URL("http://" + currentHost).hostname;
        if (currentHost !== punycodeHost) {
            alert("⚠️ Warning: Possible homograph attack detected!");
        }
    } catch (e) {
        console.error("Error checking homograph attack:", e);
    }
}

// 🚨 Function 1️⃣3️⃣: Detect Malicious Browser Extensions
function detectMaliciousExtensions() {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage("extension_id", {}, response => {
            if (!response) {
                alert("⚠️ Warning: Suspicious browser extension detected!");
            }
        });
    }
}

// 🚨 Function 1️⃣4️⃣: Detect Phishing Emails in Webmail
function detectPhishingEmails() {
    const emailKeywords = ["password reset", "verify account", "urgent action required"];
    document.querySelectorAll("td, div").forEach(element => {
        if (emailKeywords.some(keyword => element.innerText.toLowerCase().includes(keyword))) {
            alert("⚠️ Warning: Possible phishing email detected!");
        }
    });
}

// 🚨 Function 1️⃣5️⃣: Check Domain Age (Newly Registered Domains)
async function checkDomainAge() {
    const domain = window.location.hostname;
    const whoisAPI = `https://api.domaintools.com/v1/${domain}/whois/`;

    try {
        const response = await fetch(whoisAPI);
        const data = await response.json();
        if (new Date(data.create_date) > new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)) {
            alert("⚠️ Warning: This domain is newly registered. Be cautious!");
        }
    } catch (error) {
        console.error("Error checking domain age:", error);
    }
}

// 🚨 Function 1️⃣6️⃣: Detect Suspicious Keywords in Page Content
function detectSuspiciousKeywords() {
    const phishingKeywords = ["free gift", "win now", "verify identity", "urgent action"];
    if (phishingKeywords.some(keyword => document.body.innerText.toLowerCase().includes(keyword))) {
        alert("⚠️ Warning: Suspicious content detected on this page!");
    }
}

// 🚨 Function 1️⃣7️⃣: Monitor Form Submissions for Data Theft
function monitorFormSubmissions() {
    document.querySelectorAll("form").forEach(form => {
        form.addEventListener("submit", (event) => {
            alert("⚠️ Warning: This form may be attempting to steal your credentials!");
        });
    });
}

// 🚀 Run All Phishing Detection Checks
(async function runPhishingChecks() {
    const currentURL = window.location.href;
    if (isPhishingURL(currentURL) || !isSecureSite()) {
        alert("⚠️ Warning: This site might be a phishing attempt!");
    }
    detectFakeLoginForms();
    detectSuspiciousJS();
    detectFakePopups();
    detectHiddenElements();
    detectFakeHTTPS();
    detectSuspiciousRedirects();
    await checkGoogleSafeBrowsing(currentURL);
    detectDomainSpoofing();
    detectHomographAttack();
    detectMaliciousExtensions();
    detectPhishingEmails();
    await checkDomainAge();
    detectSuspiciousKeywords();
    monitorFormSubmissions();
})();

