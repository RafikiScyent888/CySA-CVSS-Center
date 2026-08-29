# CySA CVSS Center

Fifteen generated intrusions for CySA+ students. Each one is a **single incident seen through seven
tools** — you read the logs, work out what actually happened, and account for it at the bottom.

**Live site:** https://rafikiscyent888.github.io/CySA-CVSS-Center/

Built to sit alongside [Patch Bay](https://rafikiscyent888.github.io/Patch-Bay/) — same tile system,
same palette, same instructor PIN.

## What's inside

| | Tile | What you do there |
|---|---|---|
| 0 | **CVSS** | Read the shorthand vector, decode each metric, compute the base score — then decide how you'd actually queue it given what the asset is and what it holds |
| 1 | **Firewall / proxy** | Count who reached the malicious host, who actually submitted credentials, who was dropped, and which of two regular-interval destinations is really the C2 |
| 2 | **SIEM** | Find the one identity that got in among dozens of ordinary logons, name the field that proves it — then tune the correlation rule that surfaces the attack without burying you |
| 3 | **SOAR** | Work out which containment actually worked, which failed and why, which automated verdict is wrong, and how deduplication turns an alert queue into cases |
| 4 | **EDR** | Pick the payload out of the process tree, and tell the real persistence from an installer doing the same thing on another host |
| 5 | **Kill chain** | Place what you found into the seven phases |
| 6 | **Diamond Model** | Fill the four vertices from evidence, and say what you can *honestly* assert about the adversary |
| — | **Capstone** | Scope the credential reset, name the most urgent gap, and triage the indicators |

Thirty-one questions per scenario. ATT&CK technique IDs run through the EDR, kill chain and diamond
tiles so a log row connects to a phase connects to a capability.

## Why it's generated

There is no answer bank. Every scenario is built when the page loads — users, hosts, addresses,
timestamps, row counts and the CVSS advisory are all fresh, and **Shuffle** rebuilds all fifteen.
Two students side by side are not working the same incident.

The reason is the same one behind [the IPv6 drills](https://rafikiscyent888.github.io/IPv6-Drills/):
a fixed bank quietly becomes the lesson. Students stop reading logs and start remembering that the
answer to number 7 was `4`. Here the only way through is to actually read the logs.

## Nobody counts to ninety-three

A brute force really is scores of attempts, and an early version asked students to count them.
That is not analysis, it is patience — and it is not what an analyst does with a loud source.

The attack volume stays realistic. What changed is that **it is stated, never counted**: the proxy
tile opens with per-source totals the way a real proxy report does, the long runs of denied requests
and failed logons are folded away behind a line saying how many there are, and every ALLOW stays on
screen because the rows that prove a breach must never be the ones aggregation hides.

The number a student *works with* is the one their own rule produces. In the SIEM tile they set a
correlation rule — N failures within M seconds — and watch the raw stream collapse into alerts:

| Rule | Result | Lesson |
| --- | --- | --- |
| Threshold above the attacker's burst size | **0 alerts** | A rule that is too conservative does not fail safe. It fails silently. |
| Tuned to the stream | **10–20 alerts** | The queue scales with the attack instead of with the log. |
| Threshold of one or two | **dozens of alerts** | Every user who mistypes a password is an alert. A queue nobody can work is no detection at all, reached expensively. |

Then the SOAR tile deduplicates those alerts by the entity they share, and the funnel closes:
**93 raw events → 14 correlated alerts → 1 case**.

The tuning question is **graded on the outcome, not on one blessed number**. Several thresholds land
in the workable band; any of them is marked correct, because tuning is to your environment rather
than to a value from a book.

Roughly half the scenarios have no stream worth correlating — phishing and macro intrusions, where
the adversary already had the password and there are a handful of failures at most. Those teach the
other half of the lesson: no failure threshold reaches ten alerts at any setting, and **0 alerts is a
fact about your coverage, not about your quiet night**. Valid-credential abuse is caught by
impossible travel, not by counting failures.

One consequence worth knowing: **every answer is computed from the rows actually rendered.** The
firewall tile asks how many users clicked, and the grader counts the same GET requests you can see.
Nothing is hand-matched, so nothing drifts when it regenerates.

## Every tile has decoys

The point is sifting, not recognition. In every scenario there is:

- a destination that beacons on a perfect fixed interval and is a **signed vendor update service**
- a second scanner hammering the perimeter that **never got anything through**
- an autostart entry written by a **real application's installer**, on a different host
- an automated reputation verdict of "clean" from a **feed that is weeks stale**
- a containment playbook that reports **SUCCESS on the wrong host**

A student who pattern-matches "regular interval = C2" or "SUCCESS = contained" gets it wrong, which
is the lesson.

## When a student is genuinely stuck

Nothing appears for the first two wrong answers. Somebody one guess away should be
allowed to get there on their own, and a page that starts helping the moment
anyone is wrong teaches them to guess and wait for it.

From the third wrong answer, **one rung per attempt, escalating** — and never the
answer:

| Rung | What it does |
| --- | --- |
| 1 | Sends them back to the panel that actually settles it. |
| 2 | The reasoning move for that kind of question — how to eliminate, what to compare. |
| 3 | Names the trap this tile was built around, and why it is a trap. Still not the answer. |

When the ladder is spent the page marks **`LOOK HERE`** on the evidence in the
question's own tile and **`CHANGE THIS`** on the control, and offers to clear the
answer — the commonest reason a stuck student stays stuck is their own wrong pick
sitting in the box they are staring at. **The reset keeps the hints and the
wrong-count**: nothing earned is taken away, and nobody can farm a fresh ladder by
failing on purpose.

Two things are deliberate:

- **The hints are generated, not tabulated.** A table of hand-written hints stops
  growing the moment a question is added. These key off the question id, so a new
  question inherits a working ladder the day it is written.
- **Sometimes nothing is marked, and it says so.** Judgement questions — what you
  can honestly assert, how to treat a risk, what to report — are answered from what
  you already have, not by finding another row. Marking the nearest table anyway
  would be a lie dressed as help.

The mark is a printed word on a plate, not a glow: colour alone says nothing to a
student who cannot separate it from the panel behind it. Motion reinforces it and
is dropped under `prefers-reduced-motion`.

## Instructor mode

PIN **3693**, same as the rest of the toolkit. Reveals every answer with its reasoning, highlights
the malicious rows in each log, and shows the indicator sheet at the bottom.

## How it's built

Plain HTML, CSS and ES modules — no build step, no framework, no external requests. Serve the folder
or open `index.html`.

```
index.html          page shell
assets/incident.js  the generator — one ground-truth incident per scenario
assets/logs.js      renders that incident as firewall / SIEM / EDR / SOAR rows, with noise
assets/app.js       tiles, questions, grading, chrome
assets/style.css    Patch Bay's tile palette
```

Follows the system light/dark theme with an in-page override. Text is held to **WCAG AAA (7:1)** in
both themes rather than the 4.5:1 AA floor — verified across every rendered node at 1300/820/390px.

Addresses, domains and file hashes are synthetic and defanged (`example[.]com` style). For
educational purposes only. Not affiliated with, endorsed by, or sponsored by CompTIA®.
