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
| 2 | **SIEM** | Find the one identity that got in among dozens of ordinary logons, and name the single field that proves it |
| 3 | **SOAR** | Work out which containment actually worked, which failed and why, and which automated verdict is wrong |
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
answer to number 7 was `4`. Here the only way through is to actually count the rows.

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
