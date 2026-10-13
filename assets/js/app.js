const SCENARIOS = [
  {
    label: "normal.py (safe)",
    detail: "ordinary file with no secret",
    old: { found: 1, scanned: 1, skipped: 0, findings: 0, exitCode: 0, status: "checked", note: "Checked and allowed." },
    new: { found: 1, scanned: 1, skipped: 0, findings: 0, exitCode: 0, status: "checked", note: "Checked and allowed." },
  },
  {
    label: "café.py (non-ASCII filename with secret)",
    detail: "contains a secret pattern",
    old: { found: 1, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "git listed it quoted and escaped, so it could not be opened: skipped and still reported clean (false green)." },
    new: { found: 1, scanned: 1, skipped: 0, findings: 1, exitCode: 1, status: "blocked", note: "Scanned correctly and blocked." },
  },
  {
    label: "locked.py (unreadable/unscannable)",
    detail: "cannot be opened",
    old: { found: 1, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "Unreadable file was ignored and still looked clean." },
    new: { found: 1, scanned: 0, skipped: 1, findings: 1, exitCode: 1, status: "blocked", note: "Present but unreadable is now a finding: push blocked." },
  },
  {
    label: "notes.html (seed beside a <code> tag)",
    detail: "a real seed on the same line as a placeholder-shaped tag",
    old: { found: 1, scanned: 1, skipped: 0, findings: 0, exitCode: 0, status: "skipped", note: "The tag matched the allow list, which excused the whole line: the seed went out." },
    new: { found: 1, scanned: 1, skipped: 0, findings: 1, exitCode: 1, status: "blocked", note: "A placeholder must BE the match now; the seed beside it is refused." },
  },
  {
    label: "deleted.py (tracked, removed from the working tree)",
    detail: "no working-tree content to read",
    old: { found: 1, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "Missing file skipped in silence." },
    new: { found: 1, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "Still allowed (nothing on disk to read), but named on stderr as NOT SCANNED." },
  },
  {
    label: "git listing failed",
    detail: "scanner cannot enumerate files",
    old: { found: 0, scanned: 0, skipped: 0, findings: 0, exitCode: 0, status: "skipped", note: "git ls-files failed, the list came back empty, and the old gate exited 0 having read nothing." },
    new: { found: 0, scanned: 0, skipped: 0, findings: 0, exitCode: 2, status: "failed", note: "File list unavailable: scan failed closed." },
  },
];

const lane = document.getElementById("lane");
const narration = document.getElementById("narration");
const verdictPanel = document.getElementById("verdictPanel");
const verdictText = document.getElementById("verdictText");
const runBtn = document.getElementById("runBtn");
const stepBtn = document.getElementById("stepBtn");
const resetBtn = document.getElementById("resetBtn");
const CARD_TRAVEL_PADDING = 20;
const counters = {
  filesFound: document.getElementById("filesFound"),
  filesScanned: document.getElementById("filesScanned"),
  filesSkipped: document.getElementById("filesSkipped"),
  findings: document.getElementById("findings"),
  exitCode: document.getElementById("exitCode"),
};

let mode = "old";
let pointer = 0;
let running = false;
let autoRunning = false;
let runToken = 0;
const totals = { found: 0, scanned: 0, skipped: 0, findings: 0, exitCode: 0 };

function renderCards() {
  lane.innerHTML = "";
  SCENARIOS.forEach((scenario, index) => {
    const card = document.createElement("article");
    card.className = "card";
    card.id = `card-${index}`;
    card.setAttribute("role", "listitem");

    const left = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = scenario.label;
    const detail = document.createElement("div");
    detail.className = "meta";
    detail.textContent = scenario.detail;
    left.append(title, detail);

    const status = document.createElement("div");
    status.className = "meta";
    status.id = `status-${index}`;
    status.textContent = "⏳ waiting";

    card.append(left, status);
    lane.appendChild(card);
  });
}

function updateCounters() {
  counters.filesFound.textContent = String(totals.found);
  counters.filesScanned.textContent = String(totals.scanned);
  counters.filesSkipped.textContent = String(totals.skipped);
  counters.findings.textContent = String(totals.findings);
  counters.exitCode.textContent = String(totals.exitCode);
}

function iconFor(status) {
  if (status === "checked") return "✅ checked";
  if (status === "blocked") return "⛔ blocked";
  if (status === "failed") return "⚠️ scan failed";
  return "🙈 skipped";
}

function updateVerdict() {
  if (pointer < SCENARIOS.length) {
    verdictPanel.dataset.state = "idle";
    verdictText.textContent = pointer === 0 ? "Ready to run." : "SCANNING...";
    return;
  }
  if (totals.exitCode === 2) {
    verdictPanel.dataset.state = "failed";
    verdictText.textContent = "SCAN FAILED (fails closed)";
    return;
  }
  if (totals.findings > 0) {
    verdictPanel.dataset.state = "blocked";
    verdictText.textContent = "BLOCKED";
    return;
  }
  verdictPanel.dataset.state = "allowed";
  verdictText.textContent = "PUSH ALLOWED";
}

function applyResult(index) {
  const result = SCENARIOS[index][mode];
  totals.found += result.found;
  totals.scanned += result.scanned;
  totals.skipped += result.skipped;
  totals.findings += result.findings;
  totals.exitCode = Math.max(totals.exitCode, result.exitCode);

  const card = document.getElementById(`card-${index}`);
  const status = document.getElementById(`status-${index}`);
  card.classList.remove("moving");
  card.dataset.status = result.status;
  status.textContent = iconFor(result.status);

  updateCounters();
  narration.textContent = `${SCENARIOS[index].label}: ${result.note}`;
}

function setModeDisabled(disabled) {
  document.querySelectorAll('input[name="mode"]').forEach((input) => {
    input.disabled = disabled;
  });
}

function syncModeDisabled() {
  setModeDisabled(running || autoRunning);
}

function resetState() {
  runToken += 1;
  pointer = 0;
  running = false;
  autoRunning = false;
  totals.found = 0;
  totals.scanned = 0;
  totals.skipped = 0;
  totals.findings = 0;
  totals.exitCode = 0;
  narration.textContent = mode === "old"
    ? "OLD GATE mode: this can show green even when some files were not scanned."
    : "NEW GATE mode: blocks a file it cannot read, fails when it cannot list files, and names what it skipped.";
  syncModeDisabled();
  updateCounters();
  updateVerdict();
  renderCards();
}

async function runOneStep() {
  if (running || pointer >= SCENARIOS.length) return;
  running = true;
  syncModeDisabled();
  const localToken = runToken;
  const index = pointer;
  updateVerdict();
  const card = document.getElementById(`card-${index}`);
  const availableTravel = Math.max(0, lane.clientWidth - card.clientWidth - CARD_TRAVEL_PADDING);
  card.style.setProperty("--travel", `${availableTravel}px`);
  card.classList.add("moving");
  await new Promise((resolve) => setTimeout(resolve, 820));
  if (localToken !== runToken) {
    running = false;
    syncModeDisabled();
    return;
  }
  pointer = index + 1;
  applyResult(index);
  updateVerdict();
  running = false;
  syncModeDisabled();
}

async function runAll() {
  // `running`, not only `autoRunning`. runOneStep returns at once while a step is still animating,
  // so with a step in flight this loop called it, got an already-resolved promise back, and awaited
  // that -- a microtask. The event loop drains every microtask before it runs a timer, so the step's
  // own 820ms setTimeout could never fire, `pointer` could never advance, and the loop spun forever:
  // clicking Step and then Run inside the animation froze the tab, permanently and every time.
  if (autoRunning || running) return;
  autoRunning = true;
  syncModeDisabled();
  const localToken = runToken;
  try {
    while (pointer < SCENARIOS.length && localToken === runToken) {
      await runOneStep();
    }
  } finally {
    autoRunning = false;
    syncModeDisabled();
  }
}

document.querySelectorAll('input[name="mode"]').forEach((input) => {
  input.addEventListener("change", () => {
    if (running || autoRunning) return;
    mode = input.value;
    resetState();
  });
});

runBtn.addEventListener("click", runAll);
stepBtn.addEventListener("click", runOneStep);
resetBtn.addEventListener("click", resetState);

resetState();
