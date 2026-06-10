// PhishGuard++ — Feature Extraction Logic (ESM)
// Sync with src/features/url_features.py and html_features.py

const AUTH_SECURITY_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "verification", "account",
  "update", "secure", "banking", "confirm", "password", "credential",
  "credentials", "suspend", "suspended", "alert", "urgent", "unlock",
  "validate", "authenticate", "auth", "otp", "kyc", "payment", "refund",
];

const HIGH_RISK_KEYWORDS = new Set([
  "password", "credential", "credentials", "suspend", "suspended",
  "urgent", "unlock", "otp", "kyc",
]);

const POPULAR_BRANDS = {
  paypal: ["paypal.com"],
  apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
  amazon: ["amazon.com", "amazon.in"],
  google: ["google.com", "google.co.in"],
  facebook: ["facebook.com"],
  netflix: ["netflix.com"],
  instagram: ["instagram.com"],
  twitter: ["twitter.com", "x.com"],
  linkedin: ["linkedin.com"],
  dropbox: ["dropbox.com"],
  adobe: ["adobe.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  citibank: ["citibank.com", "citi.com"],
  hsbc: ["hsbc.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  usps: ["usps.com"],
  sbi: ["sbi.co.in", "onlinesbi.sbi"],
  icici: ["icicibank.com", "icici.com"],
  hdfc: ["hdfcbank.com", "hdfc.com"],
  irctc: ["irctc.co.in"],
  irs: ["irs.gov"],
  uidai: ["uidai.gov.in"],
  gst: ["gst.gov.in"],
};

const TRUSTED_REGISTRABLE_DOMAINS = new Set([
  ...Object.values(POPULAR_BRANDS).flat(),
  "login.gov", "usa.gov", "ssa.gov", "va.gov", "cdc.gov", "nih.gov",
  "treasury.gov", "cms.gov", "india.gov.in", "mygov.in", "nic.in",
  "incometax.gov.in", "passportindia.gov.in", "epfindia.gov.in",
  "digilocker.gov.in", "github.com", "gitlab.com",
]);

const RESTRICTED_GOV_SUFFIXES = [
  ".gov", ".mil", ".gov.in", ".nic.in", ".gov.uk", ".gc.ca", ".gob.mx",
];

const MULTIPART_SUFFIXES = new Set([
  "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in",
  "co.uk", "gov.uk", "ac.uk", "com.au", "gov.au", "co.jp",
  "com.br", "com.mx", "gob.mx", "gc.ca",
]);

const KNOWN_TLDS = ["com", "net", "org", "edu", "gov", "info", "biz", "co", "io", "me", "in", "uk", "us", "ca", "au", "de", "fr"];

function shannonEntropy(s) {
  if (!s) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const len = s.length;
  return -Object.values(freq).reduce((acc, count) => {
    const p = count / len;
    return acc + p * Math.log2(p);
  }, 0);
}

function splitHostname(hostname) {
  const clean = (hostname || "").toLowerCase().replace(/\.+$/, "");
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 1 || /^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
    return { subdomain: "", registrableDomain: clean, fullDomain: clean };
  }

  const twoPartSuffix = parts.slice(-2).join(".");
  const suffixLabels = parts.length >= 3 && MULTIPART_SUFFIXES.has(twoPartSuffix) ? 2 : 1;
  const domainIndex = parts.length - suffixLabels - 1;
  const registrableDomain = domainIndex >= 0 ? parts.slice(domainIndex).join(".") : clean;
  const subdomain = domainIndex > 0 ? parts.slice(0, domainIndex).join(".") : "";
  return { subdomain, registrableDomain, fullDomain: clean };
}

function isTrustedContext(hostname, registrableDomain) {
  if (TRUSTED_REGISTRABLE_DOMAINS.has(registrableDomain)) return true;
  return RESTRICTED_GOV_SUFFIXES.some(suffix => hostname.endsWith(suffix));
}

function brandIsOfficial(brand, registrableDomain) {
  return (POPULAR_BRANDS[brand] || []).includes(registrableDomain);
}

export function extractUrlFeatures(url) {
  const features = new Array(20).fill(0);
  let parsed;
  try {
    parsed = new URL(url.includes('://') ? url : 'https://' + url);
  } catch (e) {
    return features;
  }

  const { subdomain, registrableDomain, fullDomain } = splitHostname(parsed.hostname);
  const path = parsed.pathname;
  const query = parsed.search;
  const urlLower = url.toLowerCase();
  const pathLower = path.toLowerCase();
  const trustedContext = isTrustedContext(fullDomain, registrableDomain);

  features[0] = url.length;
  features[1] = fullDomain.length;
  const subdomainParts = subdomain ? subdomain.split(".").filter(Boolean) : [];
  features[2] = subdomainParts.length;
  features[3] = (url.match(/\d/g) || []).length / Math.max(url.length, 1);
  features[4] = (url.match(/[@!#$%^&*()_+=~`|\\{}[\]<>?]/g) || []).length;
  features[5] = shannonEntropy(fullDomain);
  features[6] = /^(\d{1,3}\.){3}\d{1,3}$/.test(fullDomain) ? 1 : 0;
  const authKeywords = AUTH_SECURITY_KEYWORDS.filter(kw => (
    urlLower.includes(kw) && (!trustedContext || HIGH_RISK_KEYWORDS.has(kw))
  ));
  const impersonatedBrands = Object.keys(POPULAR_BRANDS).filter(brand => (
    urlLower.includes(brand) && !brandIsOfficial(brand, registrableDomain)
  ));
  features[7] = new Set([...authKeywords, ...impersonatedBrands]).size;
  features[8] = KNOWN_TLDS.some(tld => subdomain.includes('.' + tld + '.') || subdomain.startsWith(tld + '.')) ? 1 : 0;
  features[9] = Object.keys(POPULAR_BRANDS).some(brand => (
    pathLower.includes(brand) && !brandIsOfficial(brand, registrableDomain)
  )) ? 1 : 0;
  features[10] = url.toLowerCase().includes('xn--') ? 1 : 0;
  features[11] = Math.max(0, (url.match(/\/\//g) || []).length - 1);
  features[12] = parsed.protocol === 'https:' ? 1 : 0;
  const pathSegments = path.split('/').filter(s => s.length > 0);
  features[13] = pathSegments.length;
  features[14] = pathSegments.reduce((max, s) => Math.max(max, s.length), 0);
  features[15] = pathSegments.length > 0 ? pathSegments.reduce((sum, s) => sum + s.length, 0) / pathSegments.length : 0;
  features[16] = (query.match(/\d/g) || []).length;
  features[17] = (url.match(/\./g) || []).length;
  features[18] = (url.match(/\//g) || []).length;
  features[19] = (url.match(/&/g) || []).length;

  return features;
}
