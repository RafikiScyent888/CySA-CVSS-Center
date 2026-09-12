/* =====================================================================
   CySA CVSS Center — incident generator

   One object is the single source of truth for a scenario. Every tile
   renders a lens onto it, and every answer the page grades is COMPUTED
   from it rather than written alongside it. That is the whole point: the
   firewall tile asks "how many users clicked", and the count comes from
   counting the rows the generator actually emitted. Hand-matched answers
   drift the moment anything regenerates.

   Seeded, so a scenario number is stable while you work it and changes
   when the session seed changes (Shuffle) — same contract as Patch Bay's
   network-sim scenarios.
   ===================================================================== */

/* ---------------- seeded rng ---------------- */
export function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    var t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function R(rng) {
  return {
    int: (lo, hi) => lo + Math.floor(rng() * (hi - lo + 1)),
    pick: (arr) => arr[Math.floor(rng() * arr.length)],
    shuffle: (arr) => {
      var a = arr.slice();
      for (var i = a.length - 1; i > 0; i--) {
        var j = Math.floor(rng() * (i + 1));
        var t = a[i]; a[i] = a[j]; a[j] = t;
      }
      return a;
    },
    some: (arr, n) => {
      var a = arr.slice(), out = [];
      for (var i = 0; i < n && a.length; i++) out.push(a.splice(Math.floor(rng() * a.length), 1)[0]);
      return out;
    },
    chance: (p) => rng() < p
  };
}

/* ---------------- fixtures ---------------- */
const FIRST = ["Dana", "Marcus", "Priya", "Aiden", "Rosa", "Tomas", "Nadia", "Chen", "Kofi", "Lena",
  "Ravi", "Maya", "Erik", "Sofia", "Jamal", "Iris", "Otto", "Talia", "Hugo", "Nina"];
const LAST = ["Whitfield", "Obi", "Nakamura", "Reyes", "Kaur", "Lindqvist", "Amari", "Bauer",
  "Castellanos", "Duarte", "Fontaine", "Greer", "Halloran", "Ivanov", "Jensen", "Kovac"];
const DEPTS = ["Finance", "HR", "Legal", "Sales", "Engineering", "Operations", "Support", "Marketing"];

const ORGS = [
  { name: "Meridian Health", domain: "meridianhealth.org", data: "PHI (patient records)", reg: "HIPAA" },
  { name: "Cadence Bank", domain: "cadencebank.com", data: "cardholder data", reg: "PCI DSS" },
  { name: "Northwind Logistics", domain: "northwindlog.com", data: "customer shipping records", reg: "none stated" },
  { name: "Arclight Energy", domain: "arclightenergy.net", data: "SCADA/OT telemetry", reg: "NERC CIP" },
  { name: "Vantage Legal", domain: "vantagelegal.com", data: "privileged client files", reg: "none stated" }
];

// Adversary infrastructure. Defanged on purpose — these render into a page
// students read, and a live-looking URL in courseware is a bad habit to teach.
const BAD_DOMAINS = [
  "sso-login-verify", "account-securemsg", "docs-sharedrive", "payroll-updates",
  "mfa-reset-portal", "invoice-viewer", "hr-benefits-portal", "vendor-billing"
];
const BAD_TLD = ["com", "net", "co", "info"];
const GOOD_DOMAINS = ["office365.com", "salesforce.com", "workday.com", "zoom.us", "slack.com",
  "github.com", "atlassian.net", "docusign.net", "adobe.com", "dropbox.com"];

const COUNTRIES = ["Netherlands", "Romania", "Panama", "Seychelles", "Singapore", "Latvia"];

const BENIGN_PROC = [
  ["chrome.exe", "chrome.exe"], ["explorer.exe", "notepad.exe"], ["svchost.exe", "taskhostw.exe"],
  ["teams.exe", "teams.exe"], ["explorer.exe", "OUTLOOK.EXE"], ["services.exe", "svchost.exe"]
];

/* ---------------- attack families ---------------- */
/* Each family defines how the same seven lenses get populated. They differ in
   entry vector, so the noise a student has to cut through differs too.
   Five advisories apiece: twenty in the pool, fifteen dealt per session, so
   every scenario carries a different one. Metrics are spread deliberately —
   a page where every vector scores 9.8 teaches nothing about the scale. */
const FAMILIES = {
  phish: {
    key: "phish",
    label: "Credential phishing to C2",
    brief: "Multiple staff report a login page that 'looked wrong'. The mail gateway quarantined some copies of the message but not all of them.",
    cvssPool: [
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", t: "Session token replay in the SSO portal after a forged consent prompt" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N/E:F/RL:O", t: "Open redirect in the identity provider enables credential relay" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N", t: "Reflected content injection leaks the authentication response to a third party" },
      { v: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:P/RL:W", t: "Race in the token exchange allows an attacker-supplied code to be swapped in" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N", t: "Insufficient origin checking on the consent endpoint" }
    ]
  },
  webexploit: {
    key: "webexploit",
    label: "Web exploitation to webshell",
    brief: "The public web server is throwing 500s intermittently. An engineer noticed a file in the upload directory nobody recognises.",
    cvssPool: [
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", t: "Unauthenticated path traversal allows arbitrary file write" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:O", t: "Unrestricted upload of file with dangerous type in the CMS plugin" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", t: "Directory listing exposes backup archives to unauthenticated callers" },
      { v: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:P/RL:T", t: "Deserialisation of untrusted data in the session handler" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", t: "Authenticated command injection in the admin diagnostics page" }
    ]
  },
  bruteforce: {
    key: "bruteforce",
    label: "Exposed service brute force",
    brief: "A remote-access service answered from the internet after a firewall change last week. Helpdesk has had lockout calls all morning.",
    cvssPool: [
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", t: "Missing account lockout permits unlimited authentication attempts" },
      { v: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:U", t: "Username enumeration via response-timing difference on the logon endpoint" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", t: "Verbose error messages distinguish valid from invalid accounts" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", t: "Gateway leaks internal directory attributes to unauthenticated callers" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:F/RL:W", t: "Lockout policy weaponisable for denial of service against all accounts" }
    ]
  },
  macro: {
    key: "macro",
    label: "Malicious attachment to staging",
    brief: "An invoice attachment made it through to several mailboxes. One workstation has been noisy on the network since.",
    cvssPool: [
      { v: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", t: "Macro sandbox escape in the document viewer permits code execution" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:O", t: "Remote template injection loads an attacker-controlled payload" },
      { v: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:T", t: "Use-after-free in the font parser reachable from an embedded object" },
      { v: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N", t: "Protected-view bypass when the file arrives on a trusted share" },
      { v: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", t: "Automatic external content fetch discloses the recipient environment" }
    ]
  }
};

/* Deal fifteen distinct advisories for a session. The family comes from the
   deal too, so a brute-force story never arrives carrying a macro CVE. */
export function dealSession(seed) {
  var r = R(mulberry32(seed * 2654435761));
  var pool = [];
  Object.keys(FAMILIES).forEach(function (k) {
    FAMILIES[k].cvssPool.forEach(function (c) { pool.push({ fam: k, cvss: c }); });
  });
  return r.shuffle(pool).slice(0, 15);
}

const FAMILY_KEYS = Object.keys(FAMILIES);

/* ---------------- ATT&CK ---------------- */
/* Only the handful CS0-003 actually leans on, so students meet the same IDs
   repeatedly rather than a different obscure one every run. */
export const TECH = {
  spearphishLink: { id: "T1566.002", name: "Phishing: Spearphishing Link" },
  spearphishAttach: { id: "T1566.001", name: "Phishing: Spearphishing Attachment" },
  exploitPublic: { id: "T1190", name: "Exploit Public-Facing Application" },
  validAccounts: { id: "T1078", name: "Valid Accounts" },
  bruteForce: { id: "T1110", name: "Brute Force" },
  powershell: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" },
  wsh: { id: "T1059.005", name: "Command and Scripting Interpreter: Visual Basic" },
  webshell: { id: "T1505.003", name: "Server Software Component: Web Shell" },
  runKey: { id: "T1547.001", name: "Boot or Logon Autostart: Registry Run Keys" },
  schedTask: { id: "T1053.005", name: "Scheduled Task/Job: Scheduled Task" },
  c2: { id: "T1071.001", name: "Application Layer Protocol: Web Protocols" },
  exfil: { id: "T1041", name: "Exfiltration Over C2 Channel" },
  discovery: { id: "T1087", name: "Account Discovery" }
};

export const PHASES = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation",
  "Installation", "Command & Control", "Actions on Objectives"];

/* ---------------- helpers ---------------- */
function ip(r, a, b) { return a + "." + r.int(0, 255) + "." + r.int(0, 255) + "." + b; }
function pad(n) { return n < 10 ? "0" + n : "" + n; }
function hhmmss(sec) {
  var h = Math.floor(sec / 3600) % 24, m = Math.floor(sec / 60) % 60, s = sec % 60;
  return pad(h) + ":" + pad(m) + ":" + pad(s);
}
function hexId(r, n) {
  var s = "", d = "0123456789abcdef";
  for (var i = 0; i < n; i++) s += d[r.int(0, 15)];
  return s;
}

/* ---------------- CVSS 3.1 ---------------- */
const CVSS_W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PRu: { N: 0.85, L: 0.62, H: 0.27 },
  PRc: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
  RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 }
};
export const CVSS_LABEL = {
  AV: { label: "Attack Vector", vals: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { label: "Attack Complexity", vals: { L: "Low", H: "High" } },
  PR: { label: "Privileges Required", vals: { N: "None", L: "Low", H: "High" } },
  UI: { label: "User Interaction", vals: { N: "None", R: "Required" } },
  S: { label: "Scope", vals: { U: "Unchanged", C: "Changed" } },
  C: { label: "Confidentiality", vals: { H: "High", L: "Low", N: "None" } },
  I: { label: "Integrity", vals: { H: "High", L: "Low", N: "None" } },
  A: { label: "Availability", vals: { H: "High", L: "Low", N: "None" } },
  E: { label: "Exploit Code Maturity", vals: { X: "Not Defined", U: "Unproven", P: "PoC", F: "Functional", H: "High" } },
  RL: { label: "Remediation Level", vals: { X: "Not Defined", O: "Official Fix", T: "Temporary Fix", W: "Workaround", U: "Unavailable" } }
};

export function parseVector(v) {
  var out = {};
  v.split("/").forEach(function (part) {
    var kv = part.split(":");
    if (kv.length === 2 && kv[0] !== "CVSS") out[kv[0]] = kv[1];
  });
  return out;
}

function roundUp1(x) {
  var i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvssBase(m) {
  var iss = 1 - (1 - CVSS_W.CIA[m.C]) * (1 - CVSS_W.CIA[m.I]) * (1 - CVSS_W.CIA[m.A]);
  var changed = m.S === "C";
  var impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  var expl = 8.22 * CVSS_W.AV[m.AV] * CVSS_W.AC[m.AC]
    * (changed ? CVSS_W.PRc : CVSS_W.PRu)[m.PR] * CVSS_W.UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp1(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

export function cvssTemporal(base, m) {
  if (!m.E && !m.RL) return null;
  return roundUp1(base * CVSS_W.E[m.E || "X"] * CVSS_W.RL[m.RL || "X"] * 1);
}

export function severityOf(score) {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

/* ---------------- the generator ---------------- */

/* ---------------- SIEM correlation ----------------
   A correlation rule fires when N events from one source land inside a
   rolling window of M seconds, and then suppresses until the window clears.
   Without that reset a single burst would fire once per event and the alert
   count would just be the raw count again — which is the failure mode the
   whole tile is about. */
export function correlateAlerts(times, n, windowSec) {
  n = Number(n); windowSec = Number(windowSec);
  if (!isFinite(n) || !isFinite(windowSec) || n < 1 || windowSec < 1) return null;
  var sorted = times.slice().sort(function (a, b) { return a - b; });
  var out = [], start = 0;
  for (var i = 0; i < sorted.length; i++) {
    while (sorted[i] - sorted[start] > windowSec) start++;
    if (i - start + 1 >= n) {
      /* the alert is stamped at the event that tripped it, and carries the
         span it covers so the row can say what it collapsed */
      out.push({ t: sorted[i], from: sorted[start], events: i - start + 1 });
      start = i + 1;
    }
  }
  return out;
}

export function correlate(times, n, windowSec) {
  var a = correlateAlerts(times, n, windowSec);
  return a === null ? null : a.length;
}

/* What a given alert count means for the person holding the queue. */
export function ruleVerdict(alerts, rawCount) {
  if (alerts === null) return { key: "invalid", label: "Not a rule" };
  if (alerts === 0) return { key: "blind", label: "Attack invisible \u2014 nothing fires" };
  if (alerts < 10) return { key: "coarse", label: "Fires, but collapses the attack into too few alerts to scope" };
  if (alerts <= 20) return { key: "tuned", label: "Workable queue \u2014 attack visible, analyst not buried" };
  if (alerts < rawCount * 0.6) return { key: "noisy", label: "Alert fatigue \u2014 too many to triage" };
  return { key: "raw", label: "No better than the raw log" };
}

export function buildIncident(seed, slot) {
  var rng = mulberry32(seed * 7919 + slot * 104729);
  var r = R(rng);

  var hand = dealSession(seed)[(slot - 1) % 15];
  var fam = FAMILIES[hand.fam];
  var org = r.pick(ORGS);

  // staff
  var names = r.some(FIRST, 12);
  var takenUser = {};
  var staff = names.map(function (f, i) {
    var l = r.pick(LAST);
    var user = (f[0] + l).toLowerCase();
    // Usernames must be unique or a per-user count has no single answer.
    if (takenUser[user]) {
      var n2 = 2;
      while (takenUser[user + n2]) n2++;
      user = user + n2;
    }
    takenUser[user] = true;
    return {
      user: user,
      name: f + " " + l,
      dept: r.pick(DEPTS),
      host: "WS-" + r.pick(["FIN", "HR", "LEG", "SLS", "ENG", "OPS"]) + "-" + r.int(100, 999),
      ip: "10." + r.int(10, 60) + "." + r.int(1, 40) + "." + r.int(20, 240),
      email: user + "@" + org.domain
    };
  });

  // adversary infrastructure
  var badHost = r.pick(BAD_DOMAINS) + "-" + hexId(r, 3);
  var badDomain = badHost + "[.]" + r.pick(BAD_TLD);
  var c2ip = ip(r, r.pick([185, 194, 45, 91]), r.int(2, 250));
  var c2port = r.pick([443, 8443, 8080, 4443]);
  var country = r.pick(COUNTRIES);
  var payloadHash = hexId(r, 64);
  var t0 = r.int(8, 15) * 3600 + r.int(0, 59) * 60;   // start of day, seconds

  /* ---- the ground truth every tile and answer derives from ---- */
  var G = {
    slot: slot,
    family: fam.key,
    familyLabel: fam.label,
    brief: fam.brief,
    org: org,
    staff: staff,
    adversary: { domain: badDomain, host: badHost, c2ip: c2ip, c2port: c2port, country: country, hash: payloadHash },
    t0: t0
  };

  /* ---- FIREWALL / PROXY ----------------------------------------------
     Two shapes, because the hunt is not the same one. A link-borne intrusion
     is counted from the client side (who requested, who then posted); a
     server-side intrusion is counted from the inbound side (how many
     attempts, how many landed). Giving every family the click-count data
     would have put phishing victims in a web-exploit story. */
  var clientBorne = fam.key === "phish" || fam.key === "macro";
  var victim, reached = [], submitted = [], blockedUser = null;

  if (clientBorne) {
    var reachCount = r.int(6, 10);
    reached = r.some(staff, reachCount);              // requested the page (GET)
    var submitCount = r.int(2, Math.max(2, reachCount - 4));
    submitted = r.some(reached, submitCount);          // posted credentials (POST)
    blockedUser = r.some(staff.filter(function (s) { return reached.indexOf(s) === -1; }), 1)[0];
    victim = submitted[0];
    G.fw = {
      shape: "client",
      reached: reached,
      submitted: submitted,
      blocked: blockedUser
    };
  } else {
    var srcIp = ip(r, r.pick([203, 198, 89, 176]), r.int(2, 250));
    /* A brute force really is scores of attempts — shrinking it to something
       countable would teach the wrong shape for the attack. It stays realistic
       and is STATED rather than counted; the number the student works with is
       the alert count their correlation rule produces. Everything they are
       asked to count by hand is capped into the 10-20 band. */
    var attempts = fam.key === "bruteforce" ? r.int(60, 140) : r.int(12, 18);
    var landed = fam.key === "bruteforce" ? 1 : r.int(2, 4);
    var srvHost = fam.key === "webexploit"
      ? "SRV-WEB-" + pad(r.int(1, 9))
      : "SRV-VPN-" + pad(r.int(1, 9));
    // The compromised asset is the server, not a person who clicked one.
    victim = {
      user: fam.key === "bruteforce" ? r.pick(staff).user : "svc_web",
      name: fam.key === "bruteforce" ? "brute-forced account" : "web service account",
      dept: "IT",
      host: srvHost,
      ip: "10." + r.int(10, 60) + ".1." + r.int(5, 40),
      email: "-"
    };
    G.fw = {
      shape: "server",
      srcIp: srcIp,
      attempts: attempts,
      landed: landed,
      target: srvHost,
      targetIp: victim.ip,
      // a second scanner that is noisy but got nothing through
      noiseSrcIp: ip(r, r.pick([45, 167, 212]), r.int(2, 250)),
      noiseAttempts: r.int(8, 16)
    };
  }

  // shared across both shapes
  G.fw.decoyBeaconHost = r.pick(staff).host;
  G.fw.decoyBeaconDomain = r.pick(["updates.microsoft.com", "swscan.apple.com", "packages.ubuntu.com"]);
  G.fw.decoyInterval = r.pick([3600, 1800]);
  G.fw.beaconInterval = r.pick([60, 90, 120]);
  G.fw.beaconCount = r.int(8, 14);
  G.fw.beaconHost = victim.host;

  /* ---- SIEM : which identity actually got in ---- */
  var mfaFailed = clientBorne ? submitted.slice(1) : [];
  G.siem = {
    victim: victim,
    clientBorne: clientBorne,
    mfaFailed: mfaFailed,
    geoNormal: r.pick(["United States", "Canada", "United Kingdom"]),
    geoAnomaly: country,
    /* Who generates a failure stream worth correlating, and who does not.
       Brute force is obvious. A web exploit against an internet-facing box
       comes with admin-panel credential probing from the same source, so it
       carries a stream too — otherwise threshold tuning would be taught on
       one family in four and the skill would barely get practised. Phishing
       and macro intrusions deliberately do NOT: the adversary already has
       the password, there are a handful of failures at most, and no
       threshold can surface them. That is its own lesson and the tile
       teaches it rather than papering over it. */
    failedBefore: fam.key === "bruteforce" ? G.fw.attempts
      : fam.key === "webexploit" ? r.int(35, 70)
      : r.int(2, 5),
    noiseLogons: r.int(6, 10)
  };

  /* ---- SIEM CORRELATION : the failure stream and the rules over it ----
     A password attack is not a metronome. It arrives in bursts with pauses
     between them, and that shape is the whole reason threshold tuning is a
     skill: a window too short sits inside one pause and never fires, a
     threshold too low fires on every user who fat-fingers a password twice.
     Generating real timestamps here rather than asserting an alert count
     means the number the page shows is the number the algorithm produces,
     and a student who counts the alert rows by hand agrees with the grader. */
  var failTimes = [], tCur = t0 + r.int(120, 400);
  while (failTimes.length < G.siem.failedBefore) {
    var burst = Math.min(r.int(4, 11), G.siem.failedBefore - failTimes.length);
    for (var bi = 0; bi < burst; bi++) { failTimes.push(tCur); tCur += r.int(3, 14); }
    tCur += r.int(20, 70);
  }
  G.siem.failTimes = failTimes;
  G.siem.failSrc = clientBorne ? G.adversary.c2ip : G.fw.srcIp;

  /* The rule the student is asked to reach. Searched for rather than picked,
     so it is genuinely the threshold that lands the queue in the workable
     band on THIS stream — which is what tuning to your own environment
     actually means. On a stolen-credential intrusion there are only a
     handful of failures and no threshold can reach ten alerts; that returns
     null, and the tile teaches why a volume rule is the wrong detector. */
  var WINDOW = 60;
  var tuned = null;
  for (var n = 2; n <= 40; n++) {
    var a = correlate(failTimes, n, WINDOW);
    if (a >= 10 && a <= 20) { tuned = { n: n, window: WINDOW, alerts: a }; break; }
  }
  G.siem.tuned = tuned;
  G.siem.loose = (function () {
    var ln = r.int(22, 30);
    return { n: ln, window: WINDOW, alerts: correlate(failTimes, ln, WINDOW) };
  })();
  /* The over-sensitive rule has to actually flood, and "2 in 300s" only
     floods a long stream. On a 40-event stream it lands inside the workable
     band, which would have put a question on screen calling a reasonable
     rule unreasonable. Take the LEAST aggressive threshold that genuinely
     buries the analyst, so the lesson is about the cliff edge rather than
     about an absurd setting nobody would choose. */
  var tight = null;
  for (var tn = 3; tn >= 1; tn--) {
    var ta = correlate(failTimes, tn, 300);
    if (ta > 20) { tight = { n: tn, window: 300, alerts: ta }; break; }
  }
  G.siem.tight = tight || { n: 1, window: 300, alerts: correlate(failTimes, 1, 300) };
  /* SOAR collapses alerts to cases by grouping on the entity they share. */
  G.siem.cases = 1;

  /* ---- EDR : what ran on the victim host ---- */
  var persist = r.pick(["runkey", "schedtask"]);
  G.edr = {
    host: victim.host,
    chain: fam.key === "webexploit"
      ? ["w3wp.exe", "cmd.exe", "powershell.exe"]
      : fam.key === "macro"
        ? ["OUTLOOK.EXE", "WINWORD.EXE", "wscript.exe", "powershell.exe"]
        : ["OUTLOOK.EXE", "wscript.exe", "powershell.exe"],
    payload: "powershell.exe",
    encoded: true,
    hash: payloadHash,
    // BOTH are written; only one survives a reboot in the way the question means.
    persistence: persist,
    persistenceDetail: persist === "runkey"
      ? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync"
      : "\\Microsoft\\Windows\\Servicing\\UpdateOrchestrator",
    decoyPairs: r.some(BENIGN_PROC, 3),
    techniques: [
      fam.key === "webexploit" ? TECH.webshell : (fam.key === "macro" ? TECH.wsh : TECH.wsh),
      TECH.powershell,
      persist === "runkey" ? TECH.runKey : TECH.schedTask
    ]
  };

  /* ---- SOAR : what automation did, and where it fell over ---- */
  var contained = r.some(staff.filter(function (s) { return s !== victim; }), 1)[0];
  G.soar = {
    // succeeded on a host that was not the important one
    containedHost: contained.host,
    // failed on the host that mattered, for a reason the log states
    failedHost: victim.host,
    failReason: r.pick([
      "agent last check-in 4h12m ago — host unreachable",
      "isolation API returned 409: host already in a pending action",
      "credential vault lease expired — action not authorised"
    ]),
    // an enrichment verdict that is wrong because the feed is stale
    staleFeedAgeDays: r.int(11, 40),
    staleVerdict: "clean",
    ticket: "IR-" + r.int(4000, 8999)
  };

  /* ---- CVSS ---- */
  var pick = hand.cvss;
  var vec = pick.v;
  var mets = parseVector(vec);
  var base = cvssBase(mets);
  G.cvss = {
    cve: "CVE-2026-" + r.int(10000, 49999),
    title: pick.t,
    vector: vec,
    metrics: mets,
    base: base,
    severity: severityOf(base),
    // risk context — the part a raw score does not tell you
    exposure: r.pick(["Internet-facing", "Internal only", "Internal, reachable from VPN"]),
    dataClass: org.data,
    reg: org.reg,
    compensating: r.chance(0.5) ? r.pick(["WAF blocking the known exploit path", "MFA enforced on this app", "Segmented from the data tier"]) : null
  };

  /* ---- timeline: the answer key for kill chain + capstone ---- */
  var tl = [];
  function ev(offset, phase, tech, source, detail) {
    tl.push({ t: t0 + offset, phase: phase, tech: tech, source: source, detail: detail });
  }
  if (fam.key === "phish" || fam.key === "macro") {
    var isLink = fam.key === "phish";
    ev(0, "Delivery", isLink ? TECH.spearphishLink : TECH.spearphishAttach, "Email",
      isLink ? "Phishing message delivered to " + (reached.length + 2) + " mailboxes" : "Invoice attachment delivered");
    ev(r.int(300, 900), "Exploitation", isLink ? TECH.validAccounts : TECH.wsh, "Proxy",
      isLink ? reached.length + " users opened " + badDomain : "Macro executed on " + victim.host);
    ev(r.int(1000, 1600), "Installation", G.edr.persistence === "runkey" ? TECH.runKey : TECH.schedTask,
      "EDR", "Persistence written: " + G.edr.persistenceDetail);
  } else if (fam.key === "webexploit") {
    ev(0, "Reconnaissance", TECH.discovery, "Firewall", G.fw.attempts + " probes from " + G.fw.srcIp + " against " + G.fw.target);
    ev(r.int(200, 600), "Exploitation", TECH.exploitPublic, "Firewall", G.fw.landed + " traversal requests returned 200 — file written to the upload path");
    ev(r.int(700, 1200), "Installation", TECH.webshell, "EDR", "Web shell served from the upload directory");
  } else {
    ev(0, "Reconnaissance", TECH.discovery, "Firewall", "Service discovery from " + G.fw.srcIp + " against the exposed remote-access port");
    ev(r.int(200, 800), "Exploitation", TECH.bruteForce, "SIEM",
      G.siem.failedBefore + " failed authentications before success");
    ev(r.int(900, 1400), "Installation", G.edr.persistence === "runkey" ? TECH.runKey : TECH.schedTask,
      "EDR", "Persistence written: " + G.edr.persistenceDetail);
  }
  ev(r.int(1700, 2400), "Command & Control", TECH.c2,
    "Firewall", "Beacon to " + c2ip + ":" + c2port + " every ~" + G.fw.beaconInterval + "s");
  ev(r.int(2600, 3600), "Actions on Objectives", TECH.exfil, "Firewall",
    "Outbound transfer of " + r.int(40, 900) + " MB to " + c2ip);
  tl.sort(function (a, b) { return a.t - b.t; });
  G.timeline = tl;

  /* ---- IoCs students should be able to collect ---- */
  G.iocs = [
    { value: badDomain, type: "Domain", conf: "High", why: "Hosted the credential-capture page; not a known-good vendor domain." },
    { value: c2ip, type: "IP address", conf: "High", why: "Beacon destination on a fixed short interval, geolocated to " + country + "." },
    { value: payloadHash.slice(0, 32) + "…", type: "File hash", conf: "High", why: "SHA-256 of the payload written to " + victim.host + "." },
    { value: G.edr.persistenceDetail, type: "Registry/Task path", conf: "Medium", why: "Persistence location — a path, not an artefact, so it needs host context." },
    { value: G.fw.decoyBeaconDomain, type: "Domain", conf: "Not an IoC", why: "Regular interval, but a signed vendor update service. Periodicity alone is not malice." }
  ];

  return G;
}

export { hhmmss, pad };
