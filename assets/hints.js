/* =====================================================================
   Guided hints

   Nothing appears for the first two wrong answers. A student who is one
   guess from it should be allowed to get there on their own, and a page
   that starts helping the moment somebody is wrong teaches them to guess
   and wait for the help.

   From the third wrong answer, one rung per attempt, escalating. The rule
   every rung obeys: NEVER the answer, and never a shortlist so narrow that
   the answer falls out of it. What they give instead is what a good analyst
   sitting beside them would give — which panel actually settles it, how to
   reason over it, and which tempting reading to rule out and why.

   Generated rather than tabulated. A table of thirty-four hand-written
   hints is a table that stops growing the moment a question is added, and
   this build has been bitten by that three times. Everything below keys off
   the question id, so a new question inherits a working ladder on the day
   it is written.
   ===================================================================== */

/* Which tile a question belongs to, and therefore which evidence settles
   it. Read off the id prefix, which is how the ids were already named. */
function tileOf(id) {
  const p = String(id).split("-")[0];
  return ["cvss", "fw", "siem", "soar", "edr", "chain", "dm", "cap"].indexOf(p) === -1 ? "cap" : p;
}

/* Where the evidence for this tile physically lives. Rung one is almost
   always "go and read the right instrument", because most wrong answers on
   this build are answers given before the panel was read. */
const WHERE = {
  cvss: "the vector string itself, one metric at a time, against the glossary printed beside it",
  fw: "the proxy summary at the top of the tile, and then the rows underneath it",
  siem: "the logon table — and the rule box above it, which changes what the table is showing you",
  soar: "the playbook log, where every row has a result AND a detail, and the detail is the part that matters",
  edr: "the process tree, and the autostart entries underneath it",
  chain: "what you have already established in the tiles above — this phase question is not new evidence",
  dm: "the four vertices, and which of them you can actually evidence from this incident",
  cap: "your own answers in the tiles above. This is the accounting, not a fresh investigation"
};

/* The reasoning move, per kind of question. */
const HOW = {
  metric: "Take the metric letter by letter. Each one is a question about the attack, not about the " +
    "software — who has to be where, what they need already, and whether a person has to do anything.",
  score: "The number falls out of the metrics; it is not remembered. If your figure disagrees with your " +
    "vector, one of the two is wrong, and it is usually a metric you skimmed.",
  triage: "Severity is not priority. Ask what the asset actually is and what it holds, then ask what that " +
    "does to the order of your queue — a high score on something nobody can reach can wait.",
  count: "Count from the rows, not from memory, and be precise about what is being counted: requests are " +
    "not sessions, attempts are not successes, and people are not connections.",
  identify: "Do not scan for something that looks bad. Take each candidate and look for the one field that " +
    "makes it ordinary. What survives that is your answer.",
  rule: "A detection rule is judged by what reaches the analyst, not by whether it fired. Ask what this " +
    "setting would do on a quiet week as well as on this one.",
  verdict: "Automation reports what it did, not whether it worked. Read the target and the detail on every " +
    "row and ask whether the thing it succeeded at was the thing that needed doing.",
  phase: "Work from the evidence you already named to the phase it belongs to, not the other way round. " +
    "Phases are the story you can prove, not the story that sounds complete.",
  assert: "Separate what the evidence supports from what it merely suggests. Ask what a defence lawyer " +
    "would do with each claim before you write it down.",
  scope: "Scope is who is affected, not who is interesting. Work outward from the confirmed compromise " +
    "and stop where the evidence stops."
};

/* The kind of reasoning a question asks for, from its id. Unrecognised ids
   fall to a general elimination move rather than to nothing. */
function askKind(id) {
  if (/cvss-(av|ui|scope)/.test(id)) return "metric";
  if (/cvss-sev/.test(id)) return "score";
  if (/cvss-risk/.test(id)) return "triage";
  if (/fw-(attempts|clicks|posts|landed|blocked)/.test(id)) return "count";
  if (/fw-(beacon|noise)|siem-acct|siem-proof|edr-/.test(id)) return "identify";
  if (/siem-(tune|blind|flood)|soar-dedupcost/.test(id)) return "rule";
  if (/soar-/.test(id)) return "verdict";
  if (/chain-/.test(id)) return "phase";
  if (/dm-/.test(id)) return "assert";
  if (/cap-scope|cap-entry/.test(id)) return "scope";
  if (/cap-/.test(id)) return "assert";
  return "identify";
}

/* WHERE TO LOOK, once the hints are spent.

   Two cases, and the second is the one worth being honest about. Most
   questions here are settled by a panel in their own tile. Some are not:
   the Diamond Model's honesty question, the capstone's judgement calls and
   the tuning trade-off are answered by reasoning about what you already
   know, not by finding another row. Marking a table anyway would be a lie
   dressed as help, and a student who followed it would hunt for something
   that is not there. */
export function lookTarget(id) {
  const kind = askKind(id);
  if (kind === "assert" || kind === "triage" || kind === "phase") return "none";
  return "evidence";
}

export const LOOK_LABEL = {
  evidence: "The answer is in what is marked, not in the options. Read it again before you pick.",
  none: "Nothing new on this page will settle this one — that is why nothing is marked. " +
    "It is answered from what you have already established, by deciding what you can honestly claim."
};

/* The escalating ladder for one question. */
export function questionHints(id, G) {
  const kind = askKind(id);
  const tile = tileOf(id);
  const out = [];

  out.push(kind === "assert" || kind === "triage"
    ? "Re-reading the logs will not settle this one. It is a judgement about what you already have, " +
      "so go back over what you have established rather than hunting for another row."
    : "Go back and read " + WHERE[tile] + ". Almost every wrong answer here is one given before the " +
      "panel was read properly.");

  out.push(HOW[kind] || HOW.identify);

  /* The strongest rung: the decoy this tile was built around. Every one of
     these is a thing the page deliberately put in front of them, so naming
     the trap is fair guidance rather than a giveaway — it still does not
     say which option is right. */
  const TRAP = {
    fw: "Rule one thing out first: a destination that beacons on a perfect fixed interval is not " +
      "automatically hostile. One of the regular ones is a signed vendor update service. Periodicity " +
      "is not malice — destination, interval and payload size together are.",
    siem: G && G.siem && G.siem.clientBorne
      ? "Rule one thing out: volume. This intrusion used a credential somebody handed over, so counting " +
        "failures will not find it. Ask what is impossible about the session that succeeded."
      : "Rule one thing out: the event ID. 4624 is the most common line in the log and proves nothing on " +
        "its own. The anomaly is a property of the session, not of the event type.",
    soar: "Rule one thing out: SUCCESS. A playbook that ran is not a playbook that worked — check what " +
      "each row was aimed AT, and whether any row is still waiting on a human.",
    edr: "Rule one thing out: the autostart entry that looks like persistence. A real application's " +
      "installer writes one too, and it is on a different host. Check whose host each entry is on.",
    cvss: "Rule one thing out: the assumption that a high score means act first. Read the metrics for " +
      "what they say about reachability, not for how alarming they sound.",
    chain: "Rule one thing out: the phase that sounds like it should be there. Only include what this " +
      "incident actually evidenced.",
    dm: "Rule one thing out: geography. Where infrastructure is hosted is not who is behind it, which is " +
      "exactly why the model keeps Adversary and Infrastructure apart.",
    cap: "Rule one thing out: the tidy answer. Scope is who is affected, and the honest number is usually " +
      "larger than the number of machines you touched."
  };
  if (TRAP[tile]) out.push(TRAP[tile]);
  return out;
}
