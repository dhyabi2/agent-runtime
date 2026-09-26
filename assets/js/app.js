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
    old: { found: 0, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "Skipped and still reported clean (false green)." },
    new: { found: 1, scanned: 1, skipped: 0, findings: 1, exitCode: 1, status: "blocked", note: "Scanned correctly and blocked." },
  },
  {
    label: "locked.py (unreadable/unscannable)",
    detail: "cannot be opened",
    old: { found: 1, scanned: 0, skipped: 1, findings: 0, exitCode: 0, status: "skipped", note: "Unreadable file was ignored and still looked clean." },
    new: { found: 1, scanned: 0, skipped: 1, findings: 1, exitCode: 1, status: "blocked", note: "Unscannable file now blocks push." },
  },
  {
    label: "git listing failed",
    detail: "scanner cannot enumerate files",
    old: { found: 0, scanned: 0, skipped: 0, findings: 0, exitCode: 0, status: "skipped", note: "Listing failed but old gate could still show clean." },
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
const totals = { found: 0, scanned: 0, skipped: 0, findings: 0, exitCode: 0 };

function renderCards() {
  lane.innerHTML = "";
  SCENARIOS.forEach((scenario, index) => {
    const card = document.createElement("article");
    card.className = "card";
    card.id = `card-${index}`;
    card.setAttribute("role", "listitem");
    card.innerHTML = `<div><strong>${scenario.label}</strong><div class="meta">${scenario.detail}</div></div><div class="meta" id="status-${index}">⏳ waiting</div>`;
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
  updateVerdict();
  narration.textContent = `${SCENARIOS[index].label}: ${result.note}`;
}

function resetState() {
  pointer = 0;
  running = false;
  totals.found = 0;
  totals.scanned = 0;
  totals.skipped = 0;
  totals.findings = 0;
  totals.exitCode = 0;
  verdictPanel.dataset.state = "idle";
  verdictText.textContent = "Ready to run.";
  narration.textContent = mode === "old"
    ? "OLD GATE mode: this can show green even when some files were not scanned."
    : "NEW GATE mode: blocks or fails whenever scanning is incomplete.";
  updateCounters();
  renderCards();
}

async function runOneStep() {
  if (running || pointer >= SCENARIOS.length) return;
  running = true;
  const card = document.getElementById(`card-${pointer}`);
  card.classList.add("moving");
  await new Promise((resolve) => setTimeout(resolve, 820));
  applyResult(pointer);
  pointer += 1;
  running = false;
}

async function runAll() {
  while (pointer < SCENARIOS.length) {
    await runOneStep();
  }
}

document.querySelectorAll('input[name="mode"]').forEach((input) => {
  input.addEventListener("change", (event) => {
    mode = event.target.value;
    resetState();
  });
});

runBtn.addEventListener("click", runAll);
stepBtn.addEventListener("click", runOneStep);
resetBtn.addEventListener("click", resetState);

resetState();
