/* =====================================================================
   CySA CVSS Center — page wiring

   Every question's `answer` is a function of the incident object, never a
   literal typed alongside the rows. That is what keeps a count honest
   when the scenario regenerates.
   ===================================================================== */
import { buildIncident, PHASES, CVSS_LABEL, parseVector, cvssBase, cvssTemporal, severityOf, hhmmss,
  correlate, correlateAlerts, ruleVerdict }
  from "./incident.js";
import { firewallRows, siemRows, edrRows, soarRows } from "./logs.js";

const PIN = "3693";
const SLOTS = 15;

let sessionSeed = Math.floor(Math.random() * 100000) + 1;
let slot = 1;
let G = null;
let instructor = false;
const graded = {};           // qid -> true/false

/* ---------------- small helpers ---------------- */
const el = (t, c, h) => { const n = document.createElement(t); if (c) n.className = c; if (h !== undefined) n.innerHTML = h; return n; };
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const norm = (s) => String(s).trim().toLowerCase().replace(/\s+/g, " ");

function table(cols, rows, cell) {
  const w = el("div", "logwrap");
  const t = el("table", "log");
  t.innerHTML = "<thead><tr>" + cols.map((c) => `<th>${esc(c)}</th>`).join("") + "</tr></thead>";
  const tb = el("tbody");
  rows.forEach((r) => {
    const tr = el("tr");
    if (r._bad) tr.setAttribute("data-bad", "1");
    tr.innerHTML = cell(r);
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  w.appendChild(t);
  return w;
}

/* ---------------- question engine ---------------- */
/* q = {id, ask, kind:'text'|'choice', answer:()=>value, accept?:(v)=>bool,
        choices?:[], why:()=>string} */
function renderQuestions(host, qs, onGraded) {
  const box = el("div", "qs");
  qs.forEach((q) => {
    const card = el("div", "q");
    card.appendChild(el("p", "q__ask", esc(q.ask)));
    // An aside on how to get at the answer, for questions where the method
    // matters as much as the number. Not a hint at the answer itself.
    if (q.note) card.appendChild(el("p", "q__note", esc(q.note)));
    const row = el("div", "q__row");
    let input;
    if (q.kind === "choice") {
      input = el("select", "ans");
      input.innerHTML = '<option value="">— select —</option>' +
        q.choices().map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
    } else {
      input = el("input");
      input.type = "text";
      input.setAttribute("aria-label", q.ask);
      if (q.placeholder) input.placeholder = q.placeholder;
    }
    const btn = el("button", "btn", "Check");
    btn.type = "button";
    row.appendChild(input); row.appendChild(btn);
    card.appendChild(row);
    const fb = el("p", "fb");
    fb.style.display = "none";
    card.appendChild(fb);

    function check() {
      const val = input.value;
      if (!norm(val)) return;
      const want = q.answer();
      const ok = q.accept ? q.accept(val) : norm(val) === norm(want);
      graded[q.id] = ok;
      if (q._answered) q._answered();
      if (onGraded) onGraded();
      fb.style.display = "";
      fb.className = "fb " + (ok ? "fb--ok" : "fb--no");
      fb.innerHTML = (ok ? "Correct" : "Not yet") +
        '<span class="fb__why">' + esc(q.why()) + "</span>";
      updateScore();
    }
    btn.addEventListener("click", check);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); check(); } });

    /* Instructor mode paints the answer over whatever the card was showing.
       Turning it off has to put that back — blanking the card would delete a
       student's own graded answer along with the key, which is worse than
       leaving the key up. So remember what was underneath. */
    let revealed = false, beneath = null;
    q._reveal = () => {
      if (!revealed) beneath = { html: fb.innerHTML, cls: fb.className, disp: fb.style.display };
      revealed = true;
      fb.style.display = "";
      fb.className = "fb fb--ok";
      fb.innerHTML = "Answer: " + esc(q.answer()) +
        '<span class="fb__why">' + esc(q.why()) + "</span>";
    };
    q._unreveal = () => {
      if (!revealed) return;
      revealed = false;
      fb.innerHTML = beneath ? beneath.html : "";
      fb.className = beneath ? beneath.cls : "fb";
      fb.style.display = beneath ? beneath.disp : "none";
      beneath = null;
    };
    // Answering while the key is up makes the student's own result the state
    // the card falls back to, not the empty card it started as.
    q._answered = () => { revealed = false; beneath = null; };
    box.appendChild(card);
  });
  host.appendChild(box);
  return qs;
}

let allQs = [];

/* A deliberate read-only hook for the verification walkers. Without it a
   browser walk can see the rendered rows but not the incident behind them,
   and a harness that cannot reach ground truth ends up asserting whatever
   the page happens to say — which is exactly the bug it is supposed to
   catch. Nothing here mutates state. */
window.__cv = () => {
  if (!G) return null;
  const S = G.siem;
  /* a second threshold that also lands in the workable band, so a walker
     can prove the grader rewards the outcome rather than one number */
  let alt = null;
  if (S.tuned) {
    for (let n = 2; n <= 60; n++) {
      if (n === S.tuned.n) continue;
      const a = correlate(S.failTimes, n, S.tuned.window);
      if (a >= 10 && a <= 20) { alt = n; break; }
    }
  }
  return { slot, raw: S.failTimes.length, tuned: S.tuned, loose: S.loose,
    tight: S.tight, cases: S.cases, altTuned: alt, clientBorne: S.clientBorne };
};
window.__cvAccept = (id, val) => {
  const q = allQs.find((x) => x.id === id);
  if (!q) return null;
  return q.accept ? !!q.accept(val) : norm(val) === norm(String(q.answer()));
};

function updateScore() {
  const done = Object.keys(graded).length;
  const right = Object.keys(graded).filter((k) => graded[k]).length;
  const bar = document.getElementById("scorebar");
  bar.innerHTML =
    `<span>Answered <b>${done}</b> of <b>${allQs.length}</b></span>` +
    `<span>Correct <b>${right}</b></span>` +
    `<span>Accuracy <b>${done ? Math.round((right / done) * 100) : 0}%</b></span>` +
    `<span>Scenario <b>${slot}</b> of ${SLOTS}</span>`;
}

/* ---------------- tiles ---------------- */
function tile(hue, num, title, intro, wide) {
  const s = el("section", "tile" + (wide ? " tile--wide" : ""));
  s.setAttribute("data-hue", hue);
  const h = el("div", "tile__head");
  h.appendChild(el("span", "tile__num", num));
  h.appendChild(el("h2", null, esc(title)));
  s.appendChild(h);
  const b = el("div", "tile__body");
  if (intro) b.appendChild(el("p", "tile__intro", intro));
  s.appendChild(b);
  return { section: s, body: b };
}

/* ---- 0 · CVSS ---- */
function tileCVSS() {
  const t = tile("crimson", "Tile 0", "CVSS — read the vector",
    "The advisory below is the vulnerability that made this intrusion possible. Decode the shorthand, then decide what it means <em>here</em> — a base score describes the flaw, not your risk.", true);
  const c = G.cvss;
  t.body.appendChild(el("p", null,
    `<strong>${esc(c.cve)}</strong> — ${esc(c.title)}`));
  t.body.appendChild(el("p", "vec", esc(c.vector)));

  /* Two different things, deliberately kept apart:

     The KEY is the full CVSS 3.1 reference: each metric and every value it
     can take. It is a momentary control — held down to read, gone on
     release — so it cannot sit open beside the questions while a student
     works. Deliberately a lookup they have to keep reaching for, not a
     panel they leave pinned.

     The DECODE grid does say what this vector's values mean, so it stays
     shut until the questions are answered (or instructor mode is on). */
  const peekBtn = el("button", "btn btn--peek", "Hold for the CVSS key");
  peekBtn.type = "button";
  peekBtn.setAttribute("aria-expanded", "false");
  peekBtn.setAttribute("aria-controls", "cvssGlossary");
  const gloss = el("div", "gloss");
  gloss.id = "cvssGlossary";
  gloss.hidden = true;
  gloss.innerHTML = Object.keys(CVSS_LABEL).map((k) => {
    const vals = Object.keys(CVSS_LABEL[k].vals)
      .map((v) => `<em>${v}</em>\u2009${esc(CVSS_LABEL[k].vals[v])}`).join(" &middot; ");
    return `<div><b>${k}</b><span>${esc(CVSS_LABEL[k].label)}<i>${vals}</i></span></div>`;
  }).join("");
  let held = false;
  const show = (e) => { if (e) e.preventDefault(); held = true; gloss.hidden = false; peekBtn.setAttribute("aria-expanded", "true"); };
  const hide = () => { if (!held) return; held = false; gloss.hidden = true; peekBtn.setAttribute("aria-expanded", "false"); };
  peekBtn.addEventListener("mousedown", show);
  peekBtn.addEventListener("touchstart", show, { passive: false });
  ["mouseup", "mouseleave", "touchend", "touchcancel", "blur"].forEach((ev) => peekBtn.addEventListener(ev, hide));
  // Keyboard: hold Space or Enter. Repeat events fire while held, so guard.
  peekBtn.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !held) show(e); });
  peekBtn.addEventListener("keyup", (e) => { if (e.key === " " || e.key === "Enter") hide(); });
  t.body.appendChild(peekBtn);
  t.body.appendChild(gloss);

  const m = el("div", "metrics");
  m.id = "cvssDecode";
  m.hidden = true;
  Object.keys(c.metrics).forEach((k) => {
    if (!CVSS_LABEL[k]) return;
    m.innerHTML += `<div class="metric"><b>${k}:${esc(c.metrics[k])}</b><span>${esc(CVSS_LABEL[k].label)} — ${esc(CVSS_LABEL[k].vals[c.metrics[k]])}</span></div>`;
  });
  t.body.appendChild(m);

  // Exposure stays visible — it is asset context they are meant to reason
  // with, not something to recall. Base, severity and temporal are answers.
  const temporal = cvssTemporal(c.base, c.metrics);
  const sc = el("div", "score");
  sc.id = "cvssScores";
  sc.hidden = true;
  sc.innerHTML = `<div><b>${c.base.toFixed(1)}</b><span>Base</span></div>` +
    `<div><b>${esc(c.severity)}</b><span>Severity</span></div>` +
    (temporal ? `<div><b>${temporal.toFixed(1)}</b><span>Temporal</span></div>` : "");
  const exp = el("div", "score");
  exp.innerHTML = `<div><b>${esc(c.exposure)}</b><span>Exposure</span></div>`;
  t.body.appendChild(exp);
  t.body.appendChild(sc);
  t.body.appendChild(el("p", "count",
    `Asset context — data at risk: ${esc(c.dataClass)} · regime: ${esc(c.reg)}` +
    (c.compensating ? ` · compensating control: ${esc(c.compensating)}` : " · no compensating control recorded")));

  const qs = [
    {
      id: "cvss-av", kind: "choice", ask: "What does the AV metric tell you about where an attacker must be?",
      choices: () => ["Network — reachable across the internet", "Adjacent — same broadcast domain", "Local — already on the host", "Physical — hands on the device"],
      answer: () => ({ N: "Network — reachable across the internet", A: "Adjacent — same broadcast domain", L: "Local — already on the host", P: "Physical — hands on the device" })[G.cvss.metrics.AV],
      why: () => `AV:${G.cvss.metrics.AV} is ${CVSS_LABEL.AV.vals[G.cvss.metrics.AV]}. It is the single biggest lever on the score — it is why this one is ${G.cvss.base.toFixed(1)}.`
    },
    {
      id: "cvss-ui", kind: "choice", ask: "Does exploiting this need a human to do something?",
      choices: () => ["Yes — a user must interact", "No — it fires unaided"],
      answer: () => G.cvss.metrics.UI === "R" ? "Yes — a user must interact" : "No — it fires unaided",
      why: () => G.cvss.metrics.UI === "R"
        ? "UI:R. Someone had to click, open or approve — which is exactly what the firewall tile lets you count."
        : "UI:N. Nobody had to help; that is why the logs show it starting without any user action."
    },
    {
      id: "cvss-scope", kind: "choice", ask: "Scope: does the impact stay inside the vulnerable component?",
      choices: () => ["Unchanged — impact stays in the component", "Changed — it reaches beyond it"],
      answer: () => G.cvss.metrics.S === "C" ? "Changed — it reaches beyond it" : "Unchanged — impact stays in the component",
      why: () => G.cvss.metrics.S === "C"
        ? "S:C. A changed scope is the only way a 3.1 score can exceed 9.9, and it raises the exploitability term too."
        : "S:U. Everything the flaw touches lives inside the same security authority."
    },
    {
      id: "cvss-sev", kind: "text", placeholder: "e.g. 7.5",
      ask: "What is the base score?",
      note: "Identify AV first. The score is computed from the metrics in the vector, "
        + "and attack vector is the single biggest lever on it — work out where the attacker "
        + "has to be, then the rest, then the number. Hold the CVSS key above if you need it.",
      answer: () => G.cvss.base.toFixed(1),
      accept: (v) => Math.abs(parseFloat(v) - G.cvss.base) < 0.051,
      why: () => `${G.cvss.base.toFixed(1)} — ${G.cvss.severity}. Impact and exploitability are computed separately, then combined; ${G.cvss.metrics.S === "C" ? "the changed scope adds the 1.08 multiplier." : "with scope unchanged they are simply summed and capped at 10."}`
    },
    {
      id: "cvss-risk", kind: "choice",
      ask: "Severity vs risk: given the asset context above, how would you actually queue this?",
      choices: () => ["Emergency — patch out of cycle", "Next scheduled maintenance window", "Accept and monitor — the compensating control holds"],
      answer: () => {
        const c2 = G.cvss;
        if (c2.exposure === "Internet-facing" && c2.base >= 7) return "Emergency — patch out of cycle";
        if (c2.compensating && c2.base < 9) return "Accept and monitor — the compensating control holds";
        return "Next scheduled maintenance window";
      },
      why: () => {
        const c2 = G.cvss;
        return `Base ${c2.base.toFixed(1)} is only half of it. This asset is ${c2.exposure.toLowerCase()}, holds ${c2.dataClass}, and ${c2.compensating ? "has a compensating control (" + c2.compensating + ")" : "has no compensating control"}. Risk is severity plus exposure plus what the asset holds — a 9.8 on a segmented lab box outranks nothing.`;
      }
    }
  ];
  const ids = qs.map((q) => q.id);
  function maybeReveal() {
    const done = ids.every((i) => graded[i] !== undefined);
    if (done) revealCvss(true);
    else if (instructor) revealCvss(false);
  }
  allQs = allQs.concat(renderQuestions(t.body, qs, maybeReveal));
  return t.section;
}

/* Opening up the decode is the same action whether the student earned it or
   an instructor asked for it, so both routes go through here. */
function revealCvss(earned) {
  ["cvssDecode", "cvssScores"].forEach((id) => {
    const n = document.getElementById(id);
    if (!n) return;
    n.hidden = false;
    if (earned) n.dataset.earned = "1";
  });
}
/* ...and closing it again when instructor mode goes off, unless the student
   had already worked the questions and opened it themselves. */
function hideCvss() {
  ["cvssDecode", "cvssScores"].forEach((id) => {
    const n = document.getElementById(id);
    if (n && n.dataset.earned !== "1") n.hidden = true;
  });
}

/* ---- 1 · Firewall ---- */
function tileFirewall() {
  const rows = firewallRows(G);
  const client = G.fw.shape === "client";
  const t = tile("cyan", "Tile 1", "Firewall / proxy",
    client
      ? "Perimeter log for the working day. Somewhere in here is who saw the page, who actually handed over credentials, and who never got there at all."
      : "Perimeter log for the working day. Two different sources probed the estate. Only one of them got anything through.", true);

  rows.forEach((r) => { r._bad = /^(click|submit|landed|beacon)$/.test(r._t); });

  /* A proxy report opens with per-source totals, and so does this. It is not
     decoration: it is where the student is meant to READ a number in the
     hundreds instead of counting it. The tile only asks for a count where
     the count is small enough to be worth making by hand. */
  if (!client) {
    const agg = [
      { src: G.fw.srcIp, req: G.fw.attempts, ok: G.fw.landed },
      { src: G.fw.noiseSrcIp, req: G.fw.noiseAttempts, ok: 0 }
    ];
    t.body.appendChild(el("p", "count", "Proxy summary for this window \u2014 totals, not rows to count:"));
    t.body.appendChild(table(
      ["Source", "Requests", "Allowed", "Denied"], agg,
      (a) => `<td>${esc(a.src)}</td><td class="num">${a.req}</td>` +
        `<td class="num">${a.ok}</td><td class="num">${a.req - a.ok}</td>`));
  }

  const shown = [];
  let folded = 0;
  rows.forEach((r) => {
    if (r._stream) { folded++; if (folded > STREAM_SHOWN) return; }
    shown.push(r);
  });
  const hiddenFw = Math.max(0, folded - STREAM_SHOWN);
  t.body.appendChild(table(
    ["Time", "Source", "User", "Method", "Destination", "Status", "Bytes", "Action"],
    shown,
    (r) => `<td>${hhmmss(r.t)}</td><td>${esc(r.src)}</td><td>${esc(r.user)}</td>` +
      `<td>${esc(r.method)}</td><td>${esc(r.url)}</td><td class="num">${r.status}</td>` +
      `<td class="num">${r.bytes}</td><td>${esc(r.action)}</td>`));
  t.body.appendChild(el("p", "count", `${shown.length} rows shown` +
    (hiddenFw ? `, ${hiddenFw} more denied requests from ${esc(G.fw.srcIp)} folded away. Every ALLOW is shown.` : ".")));

  const qs = client ? [
    {
      id: "fw-clicks", kind: "text", placeholder: "a number",
      ask: `How many distinct users requested ${G.adversary.domain}? (any response code)`,
      answer: () => String(G.fw.reached.length + 1),
      why: () => `${G.fw.reached.length} were allowed through and 1 more (${G.fw.blocked.user}) was dropped — ${G.fw.reached.length + 1} people clicked. The dropped request still counts as a click; the proxy stopped it, the user did not.`
    },
    {
      id: "fw-posts", kind: "text", placeholder: "a number",
      ask: "How many of them actually submitted credentials?",
      answer: () => String(G.fw.submitted.length),
      why: () => `${G.fw.submitted.length} POST requests to /auth/submit. A GET is a visit; the POST is the credential leaving the building. That difference is the whole containment scope.`
    },
    {
      id: "fw-blocked", kind: "text", placeholder: "a username",
      ask: "Which user's request never reached the site?",
      answer: () => G.fw.blocked.user,
      why: () => `${G.fw.blocked.user} — status 403, action DROP. Categorisation caught that one request. They still clicked, so they still belong in the awareness follow-up.`
    },
    {
      id: "fw-beacon", kind: "text", placeholder: "a destination",
      ask: "Two destinations are contacted on a regular interval. Which one is the C2?",
      answer: () => G.adversary.c2ip,
      accept: (v) => norm(v).indexOf(norm(G.adversary.c2ip)) !== -1,
      why: () => `${G.adversary.c2ip}:${G.adversary.c2port}, every ~${G.fw.beaconInterval}s. ${G.fw.decoyBeaconDomain} is just as regular but it is a signed vendor update service on a ${G.fw.decoyInterval / 60}-minute cycle from a different host. Periodicity is not malice — destination, interval and payload size together are.`
    }
  ] : [
    {
      id: "fw-attempts", kind: "choice",
      /* This used to ask for the attacking source's total, which on a brute
         force is scores of rows — nobody counts those, in a classroom or a
         SOC. The volume you are given; the volume you COUNT is the small
         one you are ruling out. That is the actual habit: aggregate the
         loud source, hand-verify the quiet one before you dismiss it. */
      ask: `The summary shows ${G.fw.attempts} requests from ${G.fw.srcIp} with ${G.fw.landed} allowed, and ${G.fw.noiseAttempts} from ${G.fw.noiseSrcIp} with 0 allowed. Which number tells you that you were breached?`,
      choices: () => [
        `The ${G.fw.landed} allowed \u2014 requests that returned 200 with a real response`,
        `The ${G.fw.attempts} requests \u2014 the biggest number in the table`,
        `The ${G.fw.noiseAttempts} from the second source \u2014 two attackers is worse than one`,
        `The total of both sources added together`],
      answer: () => `The ${G.fw.landed} allowed \u2014 requests that returned 200 with a real response`,
      why: () => `Counting attempts tells you that you were attacked. Counting what was ALLOWED tells you that you were breached, and only the second one changes what you do next. Note also what you did NOT do here: you read ${G.fw.attempts} off a summary rather than counting ${G.fw.attempts} rows. Past a couple of dozen, aggregation is the tool \u2014 an analyst who is counting has already lost the afternoon.`
    },
    {
      id: "fw-landed", kind: "text", placeholder: "a number",
      ask: "How many of those actually succeeded?",
      answer: () => String(G.fw.landed),
      why: () => `${G.fw.landed} returned 200 with a real response size. Everything else is 401/403/404. Counting attempts tells you that you were attacked; counting 200s tells you that you were breached.`
    },
    {
      id: "fw-noise", kind: "text", placeholder: "an IP",
      ask: "Which source can you rule out, and on what evidence?",
      answer: () => G.fw.noiseSrcIp,
      accept: (v) => norm(v).indexOf(norm(G.fw.noiseSrcIp)) !== -1,
      why: () => `${G.fw.noiseSrcIp} — every request 404/DENY, all against paths that do not exist here (/.env, /wp-login.php). That is background internet scanning, not your incident.`
    },
    {
      id: "fw-beacon", kind: "text", placeholder: "a destination",
      ask: "Two destinations are contacted on a regular interval. Which one is the C2?",
      answer: () => G.adversary.c2ip,
      accept: (v) => norm(v).indexOf(norm(G.adversary.c2ip)) !== -1,
      why: () => `${G.adversary.c2ip}:${G.adversary.c2port}, every ~${G.fw.beaconInterval}s. ${G.fw.decoyBeaconDomain} is equally regular and entirely legitimate. Periodicity alone proves nothing.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 2 · SIEM ---- */
/* THRESHOLD TUNING LIVES HERE, not in a tile of its own.
   An analyst tunes the rule in the same console, against the same events,
   usually minutes after triaging the alert it produced — and CS0-003 puts
   tuning and false-positive reduction inside alerting and monitoring rather
   than treating detection engineering as a separate discipline. Splitting it
   out would have taught a boundary neither the job nor the exam has.

   The rule the student types is run over the real event timestamps, so the
   alert count on screen is the count the algorithm produced and the count
   the grader checks. Nobody is asked to count ninety-three of anything: the
   raw total is stated, the raw rows are collapsed for display, and the only
   number worth counting is the one good tuning produces. */
const STREAM_SHOWN = 8;

function siemRuleBoard(host, rows) {
  const S = G.siem, raw = S.failTimes.length;
  const board = el("div", "rulebox");
  board.appendChild(el("p", "rulebox__raw",
    `<b>${raw}</b> failed-logon (4625) events from <b>${esc(S.failSrc)}</b> in this window. ` +
    `You are not going to read them one at a time \u2014 that is what the correlation rule is for.`));

  const ctl = el("div", "rulebox__ctl");
  ctl.innerHTML =
    `<label>Fire an alert after <input type="number" id="ruleN" min="1" max="200" value="${S.loose.n}" ` +
    `aria-label="failure threshold"> failures</label>` +
    `<label>within <input type="number" id="ruleW" min="1" max="3600" value="${S.loose.window}" ` +
    `aria-label="window in seconds"> seconds</label>` +
    `<button type="button" id="ruleRun">Apply rule</button>`;
  board.appendChild(ctl);

  const out = el("p", "rulebox__out");
  board.appendChild(out);

  /* The table swaps between raw events and the alerts the rule produced,
     so the collapse is something the student watches happen. */
  const view = el("div", "rulebox__view");
  board.appendChild(view);

  const shown = [];
  let streamSeen = 0;
  rows.forEach((r) => {
    if (r._stream) { streamSeen++; if (streamSeen > STREAM_SHOWN) return; }
    shown.push(r);
  });
  const hidden = streamSeen - Math.min(streamSeen, STREAM_SHOWN);

  function drawRaw() {
    view.innerHTML = "";
    view.appendChild(table(
      ["Time", "Event", "Account", "Host", "Source IP", "Geo", "Result"],
      shown,
      (r) => `<td>${hhmmss(r.t)}</td><td class="num">${r.eid}</td><td>${esc(r.account)}</td>` +
        `<td>${esc(r.host)}</td><td>${esc(r.src)}</td><td>${esc(r.geo)}</td><td>${esc(r.result)}</td>`));
    view.appendChild(el("p", "count",
      `${shown.length} rows shown` +
      (hidden ? `, ${hidden} more 4625 events from ${esc(S.failSrc)} folded away \u2014 ${raw} in total` : "") +
      `. 4624 = logon success, 4625 = failure, 4776 = credential validation.`));
  }

  function drawAlerts(n, w, alerts) {
    view.innerHTML = "";
    if (!alerts.length) {
      view.appendChild(el("p", "count",
        `No alerts. ${raw} events happened and your rule surfaced none of them.`));
      return;
    }
    /* No "events per alert" column: the rule fires the instant the Nth event
       lands in the window, so that number is N on every row by construction.
       A column that can only ever hold one value looks like data and is not. */
    view.appendChild(table(
      ["Alert", "Fired at", "Covering", "Source IP", "Rule"],
      alerts.map((a, i) => Object.assign({}, a, { i: i + 1 })),
      (a) => `<td class="num">${a.i}</td><td>${hhmmss(a.t)}</td>` +
        `<td>${hhmmss(a.from)}\u2013${hhmmss(a.t)}</td>` +
        `<td>${esc(S.failSrc)}</td><td>${n} in ${w}s</td>`));
    view.appendChild(el("p", "count",
      `${alerts.length} alert${alerts.length === 1 ? "" : "s"} from ${raw} raw events.`));
  }

  function run() {
    const n = board.querySelector("#ruleN").value, w = board.querySelector("#ruleW").value;
    const alerts = correlateAlerts(S.failTimes, n, w);
    if (alerts === null) {
      out.className = "rulebox__out is-invalid";
      out.textContent = "A rule needs a threshold of at least 1 and a window of at least 1 second.";
      drawRaw();
      return;
    }
    const v = ruleVerdict(alerts.length, raw);
    out.className = "rulebox__out is-" + v.key;
    out.innerHTML = `<b>${raw}</b> raw events &rarr; <b>${alerts.length}</b> alert` +
      `${alerts.length === 1 ? "" : "s"}. ${esc(v.label)}`;
    drawAlerts(n, w, alerts);
  }

  board.querySelector("#ruleRun").addEventListener("click", run);
  ["ruleN", "ruleW"].forEach((id) => {
    board.querySelector("#" + id).addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  });
  drawRaw();
  host.appendChild(board);
}

function tileSIEM() {
  const rows = siemRows(G);
  const t = tile("amber", "Tile 2", "SIEM — authentication and detection tuning",
    "Correlated logon events. Several identities were attacked, exactly one session succeeded that should not have — and the rule that surfaces it is yours to set.", true);
  rows.forEach((r) => { r._bad = r._t === "success" || r._t === "mfa-fail"; });
  siemRuleBoard(t.body, rows);

  const qs = [
    {
      id: "siem-acct", kind: "text", placeholder: "a username",
      ask: "Which account is compromised?",
      answer: () => G.siem.victim.user,
      why: () => `${G.siem.victim.user} — the one 4624 SUCCESS from ${G.adversary.c2ip}. ${G.siem.clientBorne ? "The other submitters show 4776 MFA DENIED: they gave up credentials but the second factor held." : "Everything before it is 4625."}`
    },
    {
      id: "siem-proof", kind: "choice",
      ask: "Which single field proves that session was not the real user?",
      choices: () => ["Geo — a country this account never logs in from", "Event ID — 4624 is inherently suspicious", "Host — the account used its usual workstation", "Time — it happened during business hours"],
      answer: () => "Geo — a country this account never logs in from",
      why: () => `The same account has a 4624 earlier the same day from ${G.siem.geoNormal} on its own IP. The suspicious one is from ${G.siem.geoAnomaly}. 4624 is the most common event in the log; the anomaly is the impossible travel, not the event ID.`
    },
    /* The volume question only makes sense when the volume is small enough
       to be read off the rows. Where it is not, the same underlying fact —
       how this attack is shaped — is asked through the rule instead. */
    G.siem.tuned ? {
      id: "siem-tune", kind: "text", placeholder: "a threshold, e.g. 8",
      ask: `Over a ${G.siem.tuned.window}-second window, what failure threshold brings ${G.siem.failTimes.length} raw events down to a queue of 10 to 20 alerts?`,
      note: "Set it in the rule box above and read the result. More than one threshold works — any of them counts.",
      answer: () => String(G.siem.tuned.n),
      /* Graded on the OUTCOME, not on matching one blessed number. Several
         thresholds land in the workable band and a student who found a
         different one tuned correctly. */
      accept: (v) => {
        const a = correlate(G.siem.failTimes, parseInt(v, 10), G.siem.tuned.window);
        return a !== null && a >= 10 && a <= 20;
      },
      why: () => `${G.siem.tuned.n} in ${G.siem.tuned.window}s gives ${G.siem.tuned.alerts} alerts. The queue now scales with the size of the attack instead of with the size of the log, which is the whole objective. Any threshold landing in that band is right; there is no single correct number, only a correct outcome. Tuning is to YOUR environment, not to a value from a textbook.`
    } : {
      id: "siem-tune", kind: "choice",
      ask: `Your ${G.siem.loose.n}-failures-in-${G.siem.loose.window}s rule produced 0 alerts on this incident. What does that tell you?`,
      choices: () => [
        "The credential was stolen, not guessed — a volume rule cannot see this",
        "The rule is broken and should be rewritten",
        "Nothing happened; 0 alerts means 0 attacks",
        "The threshold is too low and should be raised"],
      answer: () => "The credential was stolen, not guessed — a volume rule cannot see this",
      why: () => `There were only ${G.siem.failTimes.length} failures, because the adversary already had the password. No failure threshold reaches ten alerts here at any setting. Valid-credential abuse is caught by impossible travel and geo-anomaly, not by counting failures — which is why one detection rule is never enough and why 0 alerts is a fact about your coverage, not about your quiet night.`
    },
    {
      id: "siem-blind", kind: "text", placeholder: "a number",
      ask: `How many alerts does a rule of ${G.siem.loose.n} failures in ${G.siem.loose.window} seconds produce here?`,
      note: "Set it in the rule box and read the result.",
      answer: () => String(G.siem.loose.alerts),
      why: () => `${G.siem.loose.alerts}. The attack came in bursts with pauses between them, so ${G.siem.loose.n} failures never land inside one ${G.siem.loose.window}-second window. A threshold above the attacker's burst size is not a conservative rule — it is a blind one, and it fails silently.`
    },
    {
      id: "siem-flood", kind: "choice",
      ask: `A rule of ${G.siem.tight.n} failure${G.siem.tight.n === 1 ? "" : "s"} in ${G.siem.tight.window} seconds fires ${G.siem.tight.alerts} times on this same stream. What is wrong with it?`,
      choices: () => [
        `Every user who mistypes a password ${G.siem.tight.n === 1 ? "once" : G.siem.tight.n + " times"} generates an alert — the attack drowns in false positives`,
        "Nothing — more alerts always means better detection",
        "It will miss the attack entirely",
        "300 seconds is too short a window to be valid"],
      answer: () => `Every user who mistypes a password ${G.siem.tight.n === 1 ? "once" : G.siem.tight.n + " times"} generates an alert — the attack drowns in false positives`,
      why: () => `${G.siem.tight.alerts} alerts is not ${G.siem.tight.alerts} findings. A queue nobody can work is the same outcome as no detection at all, reached more expensively — and it is how real analysts learn to close alerts without reading them. Sensitivity you cannot triage is not sensitivity.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 3 · SOAR ---- */
function tileSOAR() {
  const rows = soarRows(G);
  const t = tile("violet", "Tile 3", "SOAR — what automation did",
    "Playbook execution log. Automation ran. Read carefully before assuming it worked — a SUCCESS line and a contained incident are not the same claim.", true);
  rows.forEach((r) => { r._bad = /^(failed|stale|pending)$/.test(r._t); });
  t.body.appendChild(table(
    ["Time", "Playbook", "Action", "Target", "Result", "Detail"],
    rows,
    (r) => `<td>${hhmmss(r.t)}</td><td>${esc(r.pb)}</td><td>${esc(r.action)}</td>` +
      `<td>${esc(r.target)}</td><td>${esc(r.result)}</td><td>${esc(r.detail)}</td>`));

  const qs = [
    {
      id: "soar-fail", kind: "text", placeholder: "a hostname",
      ask: "Which host did automation fail to contain?",
      answer: () => G.soar.failedHost,
      why: () => `${G.soar.failedHost} — the compromised one. Reason given: ${G.soar.failReason}. Isolation succeeded on ${G.soar.containedHost}, which was never the problem.`
    },
    {
      id: "soar-verdict", kind: "choice",
      ask: `PB-014 returned a "clean" verdict on ${G.adversary.domain}. Why is that wrong?`,
      choices: () => ["The threat feed it queried is stale", "The domain really is clean", "The playbook queried the wrong indicator", "Reputation lookups cannot assess domains"],
      answer: () => "The threat feed it queried is stale",
      why: () => `The detail field says the feed was last updated ${G.soar.staleFeedAgeDays} days ago. Newly registered attack infrastructure will not be in it yet. An automated verdict inherits the freshness of whatever it asked.`
    },
    {
      id: "soar-acct", kind: "choice",
      ask: `Has ${G.siem.victim.user}'s account actually been disabled?`,
      choices: () => ["No — the action is still awaiting approval", "Yes — PB-009 completed", "Yes — isolation disabled it implicitly", "No — the playbook errored"],
      answer: () => "No — the action is still awaiting approval",
      why: () => "PB-009 shows PENDING APPROVAL, not SUCCESS: no action taken yet. A playbook that ran is not a playbook that finished — the credential is still live."
    },
    /* The other half of the volume problem. Tuning in the SIEM tile took the
       raw log down to an alert queue; deduplication is what takes the queue
       down to the thing a human actually opens. Students meet SOAR as
       "automation that contains hosts" and miss that its first job most days
       is arithmetic on the queue. */
    {
      id: "soar-dedup", kind: "text", placeholder: "a number",
      ask: `PB-021 groups alerts into cases by the entity they share. With ${G.siem.tuned ? G.siem.tuned.alerts : G.siem.loose.alerts} alerts all naming ${G.siem.failSrc}, how many cases reach the analyst?`,
      answer: () => String(G.siem.cases),
      why: () => `1. Every one of those alerts is the same source hammering the same host — one incident, seen ${G.siem.tuned ? G.siem.tuned.alerts : G.siem.loose.alerts} times. Grouping on the shared entity is the last step of the funnel: ${G.siem.failTimes.length} raw events, ${G.siem.tuned ? G.siem.tuned.alerts : G.siem.loose.alerts} correlated alerts, 1 case to work. Deduplication is not a tidying feature — without it the analyst reopens the same investigation once per alert.`
    },
    {
      id: "soar-dedupcost", kind: "choice",
      ask: "What does deduplicating by source IP cost you, and why is it still worth it?",
      choices: () => [
        "A second attacker reusing the same infrastructure is folded into one case — worth it, because the alternative is an unworkable queue",
        "Nothing at all — deduplication is free",
        "It deletes the raw events permanently",
        "It slows the playbook down"],
      answer: () => "A second attacker reusing the same infrastructure is folded into one case — worth it, because the alternative is an unworkable queue",
      why: () => "Every grouping key hides something. Group on source IP and two campaigns from one bulletproof host become one case; group too finely and you are back to a queue per event. The judgement is which loss you can live with, and it is why the dedup key is a tuning decision, not a default to leave alone."
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 4 · EDR ---- */
function tileEDR() {
  const rows = edrRows(G);
  const t = tile("magenta", "Tile 4", "EDR — endpoint behaviour",
    "Process and persistence telemetry across several hosts. Two hosts wrote an autostart entry today. Only one of them is your incident.", true);
  rows.forEach((r) => { r._bad = /^(payload|persist|chain)$/.test(r._t); });
  t.body.appendChild(table(
    ["Time", "Host", "Parent", "Child", "Command line", "Hash", "Technique"],
    rows,
    (r) => `<td>${hhmmss(r.t)}</td><td>${esc(r.host)}</td><td>${esc(r.parent)}</td>` +
      `<td>${esc(r.child)}</td><td>${esc(r.cmd)}</td><td>${esc(r.hash)}</td><td>${esc(r.tech)}</td>`));

  const qs = [
    {
      id: "edr-payload", kind: "text", placeholder: "a process name",
      ask: "Which process is the payload?",
      answer: () => G.edr.payload,
      why: () => `${G.edr.payload}, launched by ${G.edr.chain[G.edr.chain.length - 2]} with -nop -w hidden -enc. The parent is what makes it obvious: ${G.edr.chain[0]} has no business ending up here.`
    },
    {
      id: "edr-persist", kind: "text", placeholder: "a hostname",
      ask: "Two hosts wrote an autostart entry. Which one is the intrusion?",
      answer: () => G.edr.host,
      why: () => `${G.edr.host}. The other write came from msiexec.exe — an application installer registering its own updater, on a host with none of the rest of the chain. Same technique ID, entirely different story.`
    },
    {
      id: "edr-tech", kind: "choice",
      ask: "Which ATT&CK technique covers the persistence you identified?",
      choices: () => ["T1547.001 — Registry Run Keys", "T1053.005 — Scheduled Task", "T1059.001 — PowerShell", "T1078 — Valid Accounts"],
      answer: () => G.edr.persistence === "runkey" ? "T1547.001 — Registry Run Keys" : "T1053.005 — Scheduled Task",
      why: () => `The write was to ${G.edr.persistenceDetail}, which is ${G.edr.persistence === "runkey" ? "a Run key — T1547.001" : "a scheduled task — T1053.005"}. T1059.001 is the execution that got there, not the persistence.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 5 · Kill chain ---- */
function tileChain() {
  const t = tile("green", "Tile 5", "Cyber Kill Chain",
    "Place what you found into phases. The evidence is in the four tiles above — this asks you to order it, not to recognise a definition.", true);
  const box = el("div", "chain");
  G.timeline.forEach((e, i) => {
    const row = el("div", "chain__row");
    row.innerHTML = `<b>${hhmmss(e.t)} · ${esc(e.source)}</b>`;
    const sel = el("select", "ans");
    sel.id = "chain-" + i;
    sel.innerHTML = '<option value="">— phase —</option>' +
      PHASES.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("");
    const wrap = el("div");
    wrap.appendChild(el("span", null, esc(e.detail) + " "));
    wrap.appendChild(sel);
    row.appendChild(wrap);
    box.appendChild(row);
  });
  t.body.appendChild(box);

  const qs = G.timeline.map((e, i) => ({
    id: "chain-q" + i, kind: "choice",
    ask: `${hhmmss(e.t)} — ${e.detail}`,
    choices: () => PHASES,
    answer: () => e.phase,
    why: () => `${e.phase}, ATT&CK ${e.tech.id} (${e.tech.name}). Seen in the ${e.source} tile.`
  }));
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- 6 · Diamond ---- */
function tileDiamond() {
  const t = tile("blue", "Tile 6", "Diamond Model",
    "Four vertices, filled from evidence rather than assumption. Every answer here should be something you can point at a log row for.", true);
  const d = el("div", "diamond");
  d.innerHTML =
    `<div class="dz"><b>Adversary</b><span>Who is operating. Rarely named from logs alone — infrastructure and capability are what you actually hold.</span></div>` +
    `<div class="dz"><b>Capability</b><span>The tooling: payload, persistence, technique.</span></div>` +
    `<div class="dz"><b>Infrastructure</b><span>What the adversary used to reach you and to keep talking.</span></div>` +
    `<div class="dz"><b>Victim</b><span>The asset and identity actually affected.</span></div>`;
  t.body.appendChild(d);

  const qs = [
    {
      id: "dm-infra", kind: "text", placeholder: "an IP or domain",
      ask: "Infrastructure — give one indicator the adversary controlled.",
      answer: () => G.adversary.c2ip,
      accept: (v) => {
        const n = norm(v);
        return n.indexOf(norm(G.adversary.c2ip)) !== -1 ||
          n.indexOf(norm(G.adversary.domain)) !== -1 ||
          n.indexOf(norm(G.adversary.domain.replace("[.]", "."))) !== -1;
      },
      why: () => `Either ${G.adversary.domain} (the staging/credential host) or ${G.adversary.c2ip} (the C2). Both are adversary-controlled infrastructure; the payload hash is capability, not infrastructure.`
    },
    {
      id: "dm-cap", kind: "choice",
      ask: "Capability — which of these belongs on that vertex?",
      choices: () => ["The encoded PowerShell payload and its persistence mechanism",
        "The compromised user account", "The country the logon came from", "The SOC ticket number"],
      answer: () => "The encoded PowerShell payload and its persistence mechanism",
      why: () => "Capability is what the adversary brought: tooling, payload, technique. The account is victim-side, geography is an attribute of infrastructure, and the ticket is yours."
    },
    {
      id: "dm-victim", kind: "text", placeholder: "a hostname",
      ask: "Victim — which asset carries the compromise?",
      answer: () => G.siem.victim.host,
      why: () => `${G.siem.victim.host}. Note it is also the host SOAR failed to isolate — the vertex and the containment gap are the same box.`
    },
    {
      id: "dm-adv", kind: "choice",
      ask: "Adversary — what can you honestly assert from this evidence?",
      choices: () => ["Only that infrastructure geolocates to " + G.adversary.country + " — attribution needs more",
        "It is a nation-state actor", "It is an insider", "The country of the IP is the country of the attacker"],
      answer: () => "Only that infrastructure geolocates to " + G.adversary.country + " — attribution needs more",
      why: () => `Geolocation of rented infrastructure is not attribution. The Diamond Model deliberately separates Adversary from Infrastructure so that a hosting country never gets mistaken for an identity.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));
  return t.section;
}

/* ---- capstone ---- */
function tileCapstone() {
  const t = tile("teal", "Capstone", "Tie it together",
    "One incident, six lenses. This is the write-up: what happened, what it cost you, and which of the indicators you collected are actually worth publishing.", true);

  const qs = [
    {
      id: "cap-entry", kind: "choice",
      ask: "What was the initial access vector?",
      choices: () => ["Phishing link — credentials captured", "Malicious attachment — code execution on open",
        "Exploitation of a public-facing application", "Brute force against an exposed service"],
      answer: () => ({
        phish: "Phishing link — credentials captured",
        macro: "Malicious attachment — code execution on open",
        webexploit: "Exploitation of a public-facing application",
        bruteforce: "Brute force against an exposed service"
      })[G.family],
      why: () => `${G.familyLabel}. The first timeline entry and the CVSS vector agree — ${G.cvss.metrics.UI === "R" ? "UI:R told you a human had to act before you read a single log row." : "UI:N told you no user action was needed."}`
    },
    {
      id: "cap-scope", kind: "text", placeholder: "a number",
      ask: "How many identities need a credential reset?",
      answer: () => String(G.fw.shape === "client" ? G.fw.submitted.length : 1),
      why: () => G.fw.shape === "client"
        ? `${G.fw.submitted.length} — everyone who POSTed. MFA stopped all but one from being used, but every submitted credential is burned. Users who only clicked (GET) did not give anything up.`
        : `1 — ${G.siem.victim.user}. A server-side intrusion does not burn user credentials wholesale; scope the reset to what was actually used.`
    },
    {
      id: "cap-gap", kind: "choice",
      ask: "What is the most urgent gap right now?",
      choices: () => [`${G.soar.failedHost} was never isolated and the account is still enabled`,
        "The threat feed needs updating", "Users need more awareness training", "The firewall rule set needs review"],
      answer: () => `${G.soar.failedHost} was never isolated and the account is still enabled`,
      why: () => `Isolation FAILED on ${G.soar.failedHost} (${G.soar.failReason}) and PB-009 is still PENDING APPROVAL. The others are real findings but none of them is live-adversary-on-the-box urgent.`
    },
    {
      id: "cap-ioc", kind: "choice",
      ask: `IoC triage — which of these should NOT go on the blocklist?`,
      choices: () => [G.fw.decoyBeaconDomain, G.adversary.domain, G.adversary.c2ip, "the payload SHA-256"],
      answer: () => G.fw.decoyBeaconDomain,
      why: () => `${G.fw.decoyBeaconDomain} is a signed vendor update service. It beacons on a fixed interval, which is exactly why it is in here — regular timing is a property of well-behaved software too. Block it and you break patching.`
    }
  ];
  allQs = allQs.concat(renderQuestions(t.body, qs));

  const ioc = el("div", "logwrap");
  ioc.style.marginTop = "1rem";
  const tb = el("table", "log");
  tb.innerHTML = "<thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Reasoning</th></tr></thead><tbody>" +
    G.iocs.map((i) => `<tr data-bad="${i.conf === "Not an IoC" ? 0 : 1}"><td>${esc(i.value)}</td><td>${esc(i.type)}</td><td>${esc(i.conf)}</td><td>${esc(i.why)}</td></tr>`).join("") +
    "</tbody>";
  ioc.appendChild(tb);
  const wrapIoc = el("div");
  wrapIoc.appendChild(el("p", "tile__intro", "<strong>Indicator sheet</strong> — revealed with instructor mode, or use it to check your own collection afterwards."));
  wrapIoc.appendChild(ioc);
  wrapIoc.id = "iocSheet";
  wrapIoc.style.display = "none";
  t.body.appendChild(wrapIoc);
  return t.section;
}

/* ---------------- render ---------------- */
function render() {
  G = buildIncident(sessionSeed, slot);
  allQs = [];
  Object.keys(graded).forEach((k) => delete graded[k]);

  document.getElementById("brief").innerHTML =
    `<strong>Scenario ${slot}</strong> · ${esc(G.org.name)} — ${esc(G.brief)}`;

  const host = document.getElementById("tiles");
  host.innerHTML = "";
  [tileCVSS(), tileFirewall(), tileSIEM(), tileSOAR(), tileEDR(), tileChain(), tileDiamond()]
    .forEach((s) => host.appendChild(s));
  const cap = document.getElementById("capstone");
  cap.innerHTML = "";
  cap.appendChild(tileCapstone());

  applyInstructor();
  updateScore();
}

function applyInstructor() {
  document.body.classList.toggle("reveal", instructor);
  const sheet = document.getElementById("iocSheet");
  if (sheet) sheet.style.display = instructor ? "" : "none";
  allQs.forEach((q) => {
    if (instructor) { if (q._reveal) q._reveal(); }
    else if (q._unreveal) q._unreveal();
  });
  if (instructor) revealCvss(false); else hideCvss();
}

/* ---------------- chrome ---------------- */
const sel = document.getElementById("slotSelect");
for (let i = 1; i <= SLOTS; i++) {
  const o = document.createElement("option");
  o.value = String(i); o.textContent = "Scenario " + i;
  sel.appendChild(o);
}
sel.addEventListener("change", () => { slot = parseInt(sel.value, 10); render(); });
document.getElementById("shuffleBtn").addEventListener("click", () => {
  sessionSeed = Math.floor(Math.random() * 100000) + 1;
  render();
});

/* instructor mode, PIN-gated, same PIN as the rest of the family */
const ov = document.getElementById("pinOverlay");
const pinInput = document.getElementById("pinInput");
const pinErr = document.getElementById("pinErr");
const insBtn = document.getElementById("instructorBtn");
function closePin() { ov.classList.add("hidden"); pinInput.value = ""; pinErr.style.display = "none"; }
insBtn.addEventListener("click", () => {
  if (instructor) { instructor = false; insBtn.textContent = "Instructor mode"; applyInstructor(); return; }
  ov.classList.remove("hidden"); pinInput.focus();
});
document.getElementById("pinCancel").addEventListener("click", closePin);
document.getElementById("pinOk").addEventListener("click", tryPin);
pinInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); tryPin(); } });
ov.addEventListener("click", (e) => { if (e.target === ov) closePin(); });
function tryPin() {
  if (pinInput.value.trim() === PIN) {
    instructor = true; insBtn.textContent = "Instructor mode: on";
    closePin(); applyInstructor();
  } else {
    pinErr.style.display = ""; pinErr.textContent = "Wrong PIN.";
  }
}

/* theme toggle — same contract as Patch Bay and the IPv6 drills */
(function () {
  const root = document.documentElement;
  const btn = document.getElementById("themeBtn");
  const KEY = "cysacvss-theme";
  const sys = () => window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  function apply(th) {
    root.setAttribute("data-theme", th);
    btn.textContent = th === "light" ? "Light" : "Dark";
    btn.setAttribute("aria-pressed", th === "light" ? "true" : "false");
    try { localStorage.setItem(KEY, th); } catch (e) { /* storage unavailable */ }
  }
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) { /* storage unavailable */ }
  apply(saved === "light" || saved === "dark" ? saved : (root.getAttribute("data-theme") || sys()));
  btn.addEventListener("click", () => apply(root.getAttribute("data-theme") === "light" ? "dark" : "light"));
})();

render();
