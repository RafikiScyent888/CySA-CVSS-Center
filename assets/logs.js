/* =====================================================================
   CySA CVSS Center — log renderers

   Each function turns the ground-truth incident into the rows one tool
   would actually have shown, with benign traffic mixed in. The malicious
   rows are never flagged in the output a student sees; the `_t` tag is
   there so instructor mode can highlight them and so the grader can
   count without a second source of truth.
   ===================================================================== */
import { mulberry32, hhmmss } from "./incident.js";

const GOOD = ["office365.com", "salesforce.com", "workday.com", "zoom.us", "slack.com",
  "github.com", "atlassian.net", "docusign.net", "adobe.com", "dropbox.com", "teams.microsoft.com"];
const GOOD_PATH = ["/", "/api/v2/sync", "/static/app.js", "/mail/inbox", "/files/recent", "/login"];

function R(seed) {
  var rng = mulberry32(seed);
  return {
    int: (a, b) => a + Math.floor(rng() * (b - a + 1)),
    pick: (a) => a[Math.floor(rng() * a.length)],
    f: rng
  };
}
function bytes(r) { return r.int(400, 90000); }

// Staff who are not the compromised asset. Decoys have to live here, or the
// student is asked to tell two identical-looking rows apart on no evidence.
function others(G) {
  var vh = G.siem.victim.host;
  var list = G.staff.filter(function (s) { return s.host !== vh; });
  return list.length ? list : G.staff;
}

/* ---------------- FIREWALL / PROXY ---------------- */
export function firewallRows(G) {
  var r = R(G.slot * 31 + 11);
  var rows = [];
  var t0 = G.t0;

  if (G.fw.shape === "client") {
    // every user who requested the page
    G.fw.reached.forEach(function (u, i) {
      rows.push({
        t: t0 + r.int(120, 900) + i * r.int(20, 90),
        src: u.ip, user: u.user, method: "GET",
        url: G.adversary.domain + "/auth/signin", status: 200,
        bytes: bytes(r), action: "ALLOW", _t: "click"
      });
    });
    // the subset who then posted credentials
    G.fw.submitted.forEach(function (u, i) {
      rows.push({
        t: t0 + r.int(950, 1500) + i * r.int(30, 120),
        src: u.ip, user: u.user, method: "POST",
        url: G.adversary.domain + "/auth/submit", status: 302,
        bytes: r.int(280, 640), action: "ALLOW", _t: "submit"
      });
    });
    // one user whose request was categorised and dropped
    rows.push({
      t: t0 + r.int(200, 1400), src: G.fw.blocked.ip, user: G.fw.blocked.user,
      method: "GET", url: G.adversary.domain + "/auth/signin", status: 403,
      bytes: 0, action: "DROP", _t: "blocked"
    });
  } else {
    // the attacker's probes; most rejected, a few land
    // Distinct indices. Drawing them independently let two picks collide, so
    // ~15% of server-shape scenarios rendered fewer 200s than the ground truth
    // said had landed — the count in the table then disagreed with the answer.
    var landedAt = [];
    while (landedAt.length < G.fw.landed) {
      var idx = r.int(0, G.fw.attempts - 1);
      if (landedAt.indexOf(idx) === -1) landedAt.push(idx);
    }
    for (var a = 0; a < G.fw.attempts; a++) {
      var landed = landedAt.indexOf(a) !== -1;
      rows.push({
        t: t0 + r.int(60, 700) + a * r.int(3, 14),
        src: G.fw.srcIp, user: "-",
        method: G.family === "bruteforce" ? "AUTH" : "GET",
        url: G.family === "bruteforce"
          ? G.fw.target + ":443/remote/logincheck"
          : G.fw.target + "/upload/..%2f..%2fetc/" + r.pick(["passwd", "shadow", "hosts"]),
        status: landed ? 200 : r.pick([403, 404, 401]),
        bytes: landed ? bytes(r) : r.int(0, 300),
        action: landed ? "ALLOW" : "DENY",
        _t: landed ? "landed" : "attempt"
      });
    }
    // a second scanner: noisy, nothing gets through
    for (var b = 0; b < G.fw.noiseAttempts; b++) {
      rows.push({
        t: t0 + r.int(60, 2200), src: G.fw.noiseSrcIp, user: "-", method: "GET",
        url: G.fw.target + r.pick(["/admin", "/.env", "/wp-login.php", "/phpmyadmin"]),
        status: 404, bytes: r.int(0, 200), action: "DENY", _t: "noise-scan"
      });
    }
  }

  // the real beacon — short fixed interval with jitter, to the C2
  var bstart = t0 + r.int(1800, 2400);
  for (var k = 0; k < G.fw.beaconCount; k++) {
    rows.push({
      t: bstart + k * G.fw.beaconInterval + r.int(-4, 4),
      src: G.siem.victim.ip, user: G.fw.shape === "client" ? G.siem.victim.user : "-",
      method: "POST", url: G.adversary.c2ip + ":" + G.adversary.c2port + "/api/v1/ping",
      status: 200, bytes: r.int(180, 420), action: "ALLOW", _t: "beacon"
    });
  }
  // the decoy: also perfectly regular, but a signed vendor update service.
  // Deliberately on a host that is NOT the compromised one, so "regular
  // interval" alone cannot be used to pick the answer.
  var decoyHost = others(G)[0];
  for (var d = 0; d < 4; d++) {
    rows.push({
      t: t0 + d * G.fw.decoyInterval + r.int(-30, 30),
      src: decoyHost.ip, user: decoyHost.user, method: "GET",
      url: G.fw.decoyBeaconDomain + "/v1/manifest", status: 200,
      bytes: r.int(1200, 4000), action: "ALLOW", _t: "decoy-beacon"
    });
  }
  // ordinary business traffic
  for (var n = 0; n < 16; n++) {
    var u = G.staff[r.int(0, G.staff.length - 1)];
    rows.push({
      t: t0 + r.int(0, 3600), src: u.ip, user: u.user, method: r.pick(["GET", "GET", "POST"]),
      url: r.pick(GOOD) + r.pick(GOOD_PATH), status: r.pick([200, 200, 200, 304]),
      bytes: bytes(r), action: "ALLOW", _t: "benign"
    });
  }
  rows.sort((a, b) => a.t - b.t);
  return rows;
}

/* ---------------- SIEM ---------------- */
export function siemRows(G) {
  var r = R(G.slot * 47 + 5);
  var rows = [];
  var t0 = G.t0;
  var v = G.siem.victim;

  if (G.siem.clientBorne) {
    // MFA stopped everyone except one
    G.siem.mfaFailed.forEach(function (u, i) {
      rows.push({
        t: t0 + r.int(1500, 1900) + i * r.int(20, 80), eid: 4776, account: u.user,
        host: u.host, src: G.adversary.c2ip, geo: G.siem.geoAnomaly,
        result: "MFA DENIED", _t: "mfa-fail"
      });
    });
    for (var f = 0; f < G.siem.failedBefore; f++) {
      rows.push({
        t: t0 + r.int(1500, 2000), eid: 4625, account: v.user, host: v.host,
        src: G.adversary.c2ip, geo: G.siem.geoAnomaly, result: "FAILED (bad password)", _t: "fail"
      });
    }
  } else {
    for (var q = 0; q < Math.min(G.siem.failedBefore, 60); q++) {
      rows.push({
        t: t0 + r.int(200, 1600), eid: 4625, account: r.pick([v.user, "administrator", "svc_backup", "guest"]),
        host: G.fw.target, src: G.fw.srcIp, geo: G.siem.geoAnomaly,
        result: "FAILED (bad password)", _t: "fail"
      });
    }
  }
  // the one that worked — this row is the answer
  rows.push({
    t: t0 + r.int(2000, 2200), eid: 4624, account: v.user, host: v.host,
    src: G.adversary.c2ip, geo: G.siem.geoAnomaly, result: "SUCCESS", _t: "success"
  });
  // the same account's normal session earlier the same day, from its usual country
  rows.push({
    t: t0 - r.int(600, 1800), eid: 4624, account: v.user, host: v.host,
    src: v.ip, geo: G.siem.geoNormal, result: "SUCCESS", _t: "baseline"
  });
  // everyday logon noise
  for (var n = 0; n < G.siem.noiseLogons; n++) {
    var u2 = G.staff[r.int(0, G.staff.length - 1)];
    rows.push({
      t: t0 + r.int(-1200, 3600), eid: r.pick([4624, 4624, 4634, 4625]),
      account: u2.user, host: u2.host, src: u2.ip, geo: G.siem.geoNormal,
      result: r.pick(["SUCCESS", "SUCCESS", "SUCCESS", "FAILED (bad password)"]), _t: "benign"
    });
  }
  rows.sort((a, b) => a.t - b.t);
  return rows;
}

/* ---------------- EDR ---------------- */
export function edrRows(G) {
  var r = R(G.slot * 59 + 3);
  var rows = [];
  var t0 = G.t0 + 900;
  var chain = G.edr.chain;
  for (var i = 1; i < chain.length; i++) {
    var isPayload = chain[i] === G.edr.payload;
    rows.push({
      t: t0 + i * r.int(2, 25), host: G.edr.host,
      parent: chain[i - 1], child: chain[i],
      cmd: isPayload
        ? "powershell.exe -nop -w hidden -enc " + btoaSafe(r)
        : chain[i] + " " + r.pick(["/c", "-embedding", ""]),
      hash: isPayload ? G.edr.hash.slice(0, 16) + "…" : "-",
      tech: isPayload ? "T1059.001" : (chain[i] === "wscript.exe" ? "T1059.005" : "-"),
      _t: isPayload ? "payload" : "chain"
    });
  }
  // persistence — the durable one
  rows.push({
    t: t0 + r.int(60, 200), host: G.edr.host, parent: G.edr.payload,
    child: G.edr.persistence === "runkey" ? "reg.exe" : "schtasks.exe",
    cmd: G.edr.persistence === "runkey"
      ? 'reg add "' + G.edr.persistenceDetail + '" /d "%APPDATA%\\sync.js"'
      : 'schtasks /create /tn "' + G.edr.persistenceDetail + '" /sc onlogon',
    hash: "-", tech: G.edr.persistence === "runkey" ? "T1547.001" : "T1053.005",
    _t: "persist"
  });
  // a decoy that looks like persistence but is a real app's own installer,
  // on a different host so the two are separable on evidence
  rows.push({
    t: t0 + r.int(200, 400), host: others(G)[1 % others(G).length].host, parent: "msiexec.exe", child: "reg.exe",
    cmd: 'reg add "HKLM\\...\\Run\\SlackUpdate" /d "%LOCALAPPDATA%\\slack\\update.exe"',
    hash: "-", tech: "T1547.001", _t: "decoy-persist"
  });
  // benign process activity elsewhere
  var oth = others(G);
  G.edr.decoyPairs.forEach(function (pr, i) {
    rows.push({
      t: t0 + r.int(-600, 900), host: oth[(i + 2) % oth.length].host,
      parent: pr[0], child: pr[1], cmd: pr[1], hash: "-", tech: "-", _t: "benign"
    });
  });
  rows.sort((a, b) => a.t - b.t);
  return rows;
}
function btoaSafe(r) {
  var s = "", d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (var i = 0; i < 44; i++) s += d[r.int(0, d.length - 1)];
  return s + "==";
}

/* ---------------- SOAR ---------------- */
export function soarRows(G) {
  var r = R(G.slot * 67 + 13);
  var t0 = G.t0 + 2400;
  var rows = [
    { t: t0 + r.int(5, 40), pb: "PB-014 Enrich Indicator", action: "reputation lookup",
      target: G.adversary.domain, result: "COMPLETED",
      detail: "verdict: " + G.soar.staleVerdict + " — feed last updated " + G.soar.staleFeedAgeDays + " days ago",
      _t: "stale" },
    { t: t0 + r.int(45, 90), pb: "PB-007 Isolate Endpoint", action: "network isolation",
      target: G.soar.containedHost, result: "SUCCESS", detail: "host isolated, ticket " + G.soar.ticket,
      _t: "contained" },
    { t: t0 + r.int(95, 150), pb: "PB-007 Isolate Endpoint", action: "network isolation",
      target: G.soar.failedHost, result: "FAILED", detail: G.soar.failReason, _t: "failed" },
    { t: t0 + r.int(160, 220), pb: "PB-022 Notify", action: "open incident",
      target: "SOC queue", result: "SUCCESS", detail: "ticket " + G.soar.ticket + " assigned to tier 2",
      _t: "benign" },
    { t: t0 + r.int(230, 300), pb: "PB-031 Block Indicator", action: "add to blocklist",
      target: G.adversary.c2ip, result: "SUCCESS", detail: "edge deny rule pushed", _t: "benign" },
    { t: t0 + r.int(310, 380), pb: "PB-009 Disable Account", action: "disable user",
      target: G.siem.victim.user, result: "PENDING APPROVAL",
      detail: "awaiting manager approval — no action taken yet", _t: "pending" }
  ];
  rows.sort((a, b) => a.t - b.t);
  return rows;
}

export { hhmmss };
