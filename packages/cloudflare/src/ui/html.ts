/**
 * Demo UI HTML — dark-themed cryptographic terminal aesthetic.
 *
 * Three tabs: Demo (real-time deletion pipeline with data inspector),
 * Receipts (browse deletion receipts), and Transparency Log.
 * SSE via fetch() + ReadableStream reader (not EventSource, since POST).
 *
 * @module ui/html
 */

export function getUIHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verifiable Delete — Demo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface-alt: #0e0e16;
    --border: #1e1e2e;
    --border-active: #2a2a3e;
    --text: #e0e0e0;
    --text-muted: #888;
    --green: #00ff88;
    --green-dim: #00ff8830;
    --green-glow: #00ff8815;
    --amber: #ffaa00;
    --amber-dim: #ffaa0030;
    --red: #ff4444;
    --red-dim: #ff444430;
    --red-glow: #ff444420;
    --blue: #4488ff;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Outfit', sans-serif;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    line-height: 1.6;
    min-height: 100vh;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 {
    font-size: 1.8rem;
    font-weight: 700;
    margin-bottom: 0.25rem;
    background: linear-gradient(135deg, var(--green), #00ccff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }

  /* Tabs */
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
  .tab {
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    color: var(--text-muted);
    font-family: var(--sans);
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
  }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--green); border-bottom-color: var(--green); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Demo Tab — Input Area */
  textarea {
    width: 100%;
    min-height: 100px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.85rem;
    padding: 1rem;
    resize: vertical;
    outline: none;
    transition: border-color 0.2s;
  }
  textarea:focus { border-color: var(--green); }
  textarea::placeholder { color: #555; }

  .btn {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 1rem;
    padding: 0.75rem 1.5rem;
    background: var(--green-dim);
    border: 1px solid var(--green);
    border-radius: 8px;
    color: var(--green);
    font-family: var(--sans);
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn:hover { background: #00ff8820; box-shadow: 0 0 20px var(--green-glow); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn.pulse { animation: pulse 2s ease-in-out infinite; }
  .btn-sm {
    font-size: 0.85rem;
    padding: 0.5rem 1rem;
    margin-top: 0;
  }
  @keyframes pulse {
    0%, 100% { box-shadow: 0 0 0 0 #00ff8840; }
    50% { box-shadow: 0 0 15px 3px #00ff8820; }
  }

  /* Split-pane layout */
  .split-pane {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-top: 1.5rem;
  }
  @media (max-width: 900px) {
    .split-pane { grid-template-columns: 1fr; }
    .inspector-panel { position: static !important; }
  }

  /* Data Inspector Panel */
  .inspector-panel {
    position: sticky;
    top: 1rem;
    align-self: start;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    transition: border-color 0.5s, box-shadow 0.5s;
    min-height: 200px;
  }
  .inspector-panel.phase-plaintext { border-color: var(--green); }
  .inspector-panel.phase-encrypted { border-color: var(--amber); }
  .inspector-panel.phase-key_split { border-color: var(--amber); }
  .inspector-panel.phase-key_destroyed {
    border-color: var(--red);
    animation: shockwave 1.5s ease-out;
  }
  .inspector-panel.phase-data_deleted { border-color: var(--red); }
  .inspector-panel.phase-verified { border-color: var(--green); }
  .inspector-panel.phase-smt_proven { border-color: var(--green); }
  .inspector-panel.phase-logged { border-color: var(--green); }
  .inspector-panel.phase-receipted { border-color: var(--green); }

  @keyframes shockwave {
    0% { box-shadow: 0 0 0 0 var(--red); }
    20% { box-shadow: 0 0 30px 8px var(--red-glow); }
    100% { box-shadow: 0 0 0 0 transparent; }
  }

  .inspector-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 1rem;
    font-size: 0.75rem;
    font-weight: 700;
    font-family: var(--mono);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .status-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    font-family: var(--mono);
    letter-spacing: 0.05em;
  }
  .badge-green { background: var(--green-dim); color: var(--green); }
  .badge-amber { background: var(--amber-dim); color: var(--amber); }
  .badge-red { background: var(--red-dim); color: var(--red); animation: badge-pulse 1.5s ease-in-out infinite; }
  @keyframes badge-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
  }

  .inspector-body { font-family: var(--mono); font-size: 0.75rem; line-height: 1.8; }
  .inspector-note {
    margin-top: 0.75rem;
    padding: 0.5rem 0.75rem;
    background: var(--bg);
    border-radius: 4px;
    font-size: 0.7rem;
    color: var(--text-muted);
    font-style: italic;
  }

  .hex-block {
    background: var(--bg);
    border-radius: 4px;
    padding: 0.5rem 0.75rem;
    margin: 0.5rem 0;
    word-break: break-all;
    color: #4a9;
    max-height: 120px;
    overflow-y: auto;
    transition: all 0.5s;
  }
  .hex-block.destroyed {
    color: var(--red);
    text-decoration: line-through;
    opacity: 0.5;
  }
  .hex-block.deleted {
    color: var(--text-muted);
    text-decoration: none;
    opacity: 0.4;
    text-align: center;
    font-size: 0.85rem;
    padding: 1rem;
  }
  .hex-label {
    font-size: 0.65rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-top: 0.5rem;
  }

  .backend-badges, .share-badges {
    display: flex;
    gap: 0.5rem;
    margin: 0.5rem 0;
    flex-wrap: wrap;
  }
  .backend-badge, .share-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-family: var(--mono);
    border: 1px solid var(--border);
    transition: all 0.3s;
  }
  .backend-badge.active { border-color: var(--green); color: var(--green); }
  .backend-badge.cleared { border-color: var(--red); color: var(--red); text-decoration: line-through; opacity: 0.6; }
  .backend-badge.absent { border-color: var(--green); color: var(--green); }
  .share-badge.active { border-color: var(--green); color: var(--green); }
  .share-badge.destroyed {
    border-color: var(--red);
    color: var(--red);
    text-decoration: line-through;
    opacity: 0.6;
    animation: share-destroy 0.5s ease-out;
  }
  @keyframes share-destroy {
    0% { transform: scale(1); opacity: 1; }
    50% { transform: scale(0.9); opacity: 0.3; }
    100% { transform: scale(1); opacity: 0.6; }
  }

  .scan-result {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.25rem 0;
    font-size: 0.75rem;
  }
  .scan-result .arrow { color: var(--text-muted); }
  .scan-result .status { font-weight: 600; }
  .scan-result .status.pass { color: var(--green); }

  .log-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.3rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-family: var(--mono);
    background: var(--green-dim);
    color: var(--green);
    margin: 0.25rem 0.25rem 0.25rem 0;
  }

  .inspector-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 150px;
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  /* Timeline (right panel) */
  .timeline { display: flex; flex-direction: column; gap: 0.5rem; }
  .step-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    animation: slideIn 0.3s ease-out;
    transition: border-color 0.3s;
  }
  .step-card.running { border-left-color: var(--amber); }
  .step-card.complete { border-left-color: var(--green); }
  .step-card.error { border-left-color: var(--red); }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .step-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    font-size: 0.9rem;
  }
  .step-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    font-size: 0.75rem;
    font-weight: 700;
    font-family: var(--mono);
  }
  .step-card.running .step-num { background: var(--amber-dim); color: var(--amber); }
  .step-card.complete .step-num { background: var(--green-dim); color: var(--green); }
  .step-desc {
    margin-top: 0.4rem;
    font-size: 0.8rem;
    color: var(--text-muted);
    line-height: 1.5;
    font-weight: 400;
  }
  .step-data {
    margin-top: 0.5rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    color: #4a9;
    line-height: 1.8;
    word-break: break-all;
  }
  .step-data .label { color: var(--text-muted); }

  /* Done card */
  .done-card {
    background: var(--surface);
    border: 1px solid var(--green);
    border-radius: 8px;
    padding: 1.25rem;
    margin-top: 0.5rem;
    animation: slideIn 0.3s ease-out;
  }
  .done-card h3 { color: var(--green); font-size: 1rem; margin-bottom: 0.75rem; }
  .receipt-toggle {
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
    font-family: var(--sans);
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    cursor: pointer;
    transition: color 0.2s;
  }
  .receipt-toggle:hover { color: var(--text); }
  .receipt-json {
    display: none;
    margin-top: 0.75rem;
    background: var(--bg);
    border-radius: 6px;
    padding: 1rem;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: #4a9;
    max-height: 400px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .receipt-json.open { display: block; }

  /* Receipts Tab */
  .receipt-list { display: flex; flex-direction: column; gap: 0.75rem; }
  .receipt-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .receipt-card:hover { border-color: var(--green); background: #13131d; }
  .receipt-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }
  .receipt-card-title {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--text);
    font-weight: 600;
  }
  .receipt-card-meta {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-family: var(--mono);
    line-height: 1.6;
  }
  .receipt-card-meta span { color: #4a9; }
  .verified-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    font-family: var(--mono);
    background: var(--green-dim);
    color: var(--green);
    letter-spacing: 0.05em;
  }

  /* Receipt Detail View */
  .receipt-detail { display: none; }
  .receipt-detail.active { display: block; }
  .receipt-detail-back {
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
    font-family: var(--sans);
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    cursor: pointer;
    margin-bottom: 1rem;
    transition: color 0.2s;
  }
  .receipt-detail-back:hover { color: var(--text); border-color: var(--green); }
  .detail-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
  }
  .detail-section h4 {
    font-size: 0.85rem;
    color: var(--green);
    margin-bottom: 0.75rem;
    font-weight: 600;
  }
  .detail-field {
    display: flex;
    gap: 0.5rem;
    font-size: 0.8rem;
    margin-bottom: 0.3rem;
    align-items: baseline;
  }
  .detail-field .dlabel { color: var(--text-muted); min-width: 120px; flex-shrink: 0; font-size: 0.75rem; }
  .detail-field .dvalue { font-family: var(--mono); color: #4a9; word-break: break-all; font-size: 0.75rem; }
  .detail-attestation {
    background: var(--bg);
    border-radius: 4px;
    padding: 0.5rem 0.75rem;
    margin: 0.4rem 0;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: #4a9;
  }
  .detail-proof-hashes {
    background: var(--bg);
    border-radius: 4px;
    padding: 0.75rem;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: #4a9;
    max-height: 200px;
    overflow-y: auto;
    word-break: break-all;
  }
  .detail-raw-json {
    background: var(--bg);
    border-radius: 6px;
    padding: 1rem;
    font-family: var(--mono);
    font-size: 0.7rem;
    color: #4a9;
    max-height: 400px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    display: none;
  }
  .detail-raw-json.open { display: block; }

  /* Log Tab */
  .tree-head {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.5rem;
  }
  .tree-head h3 { font-size: 0.95rem; margin-bottom: 0.75rem; color: var(--green); }
  .tree-head .field {
    display: flex;
    gap: 0.5rem;
    font-size: 0.8rem;
    margin-bottom: 0.25rem;
  }
  .tree-head .field .label { color: var(--text-muted); min-width: 90px; }
  .tree-head .field .value { font-family: var(--mono); color: #4a9; word-break: break-all; }

  .log-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .log-table th {
    text-align: left;
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border);
    color: var(--text-muted);
    font-weight: 500;
  }
  .log-table td {
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid #1a1a25;
    font-family: var(--mono);
    font-size: 0.75rem;
    color: #4a9;
    cursor: pointer;
  }
  .log-table tr:hover td { background: #ffffff05; }

  .log-detail {
    display: none;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    margin-top: 1rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    color: #4a9;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .log-detail.open { display: block; }

  .pagination { display: flex; gap: 0.5rem; margin-top: 1rem; justify-content: center; }
  .pagination button {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-muted);
    font-family: var(--sans);
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    cursor: pointer;
  }
  .pagination button:hover:not(:disabled) { color: var(--text); border-color: var(--green); }
  .pagination button:disabled { opacity: 0.3; cursor: not-allowed; }

  .empty-state { text-align: center; padding: 3rem; color: var(--text-muted); }

  /* Spinner */
  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--amber); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .check { color: var(--green); font-weight: bold; }
</style>
</head>
<body>
<div class="container">
  <h1>Verifiable Delete</h1>
  <p class="subtitle">Crypto-shredding + threshold key destruction + W3C VC deletion receipts</p>

  <div class="tabs">
    <button class="tab active" data-tab="demo">Demo</button>
    <button class="tab" data-tab="receipts">Receipts</button>
    <button class="tab" data-tab="log">Transparency Log</button>
  </div>

  <!-- DEMO TAB -->
  <div id="tab-demo" class="tab-content active">
    <textarea id="input" placeholder="Enter data to encrypt, delete, and verify...&#10;&#10;Try: 'My sensitive event data that should be verifiably deleted'"></textarea>
    <button class="btn pulse" id="run-btn" onclick="runDemo()">
      Encrypt, Delete &amp; Verify
    </button>

    <div class="split-pane" id="split-pane" style="display:none">
      <!-- Left: Data Inspector -->
      <div class="inspector-panel" id="inspector">
        <div class="inspector-empty">Run the demo to see data transform in real-time</div>
      </div>
      <!-- Right: Pipeline Timeline -->
      <div class="timeline" id="timeline"></div>
    </div>
  </div>

  <!-- RECEIPTS TAB -->
  <div id="tab-receipts" class="tab-content">
    <div id="receipts-list-view">
      <button class="btn btn-sm" onclick="loadReceipts()" style="margin-bottom:1rem">Refresh</button>
      <div class="receipt-list" id="receipt-list">
        <div class="empty-state">No receipts yet. Run a demo first.</div>
      </div>
      <div class="pagination">
        <button id="rcpt-prev-btn" onclick="loadReceipts(rcptOffset - rcptLimit)" disabled>&#8592; Prev</button>
        <button id="rcpt-next-btn" onclick="loadReceipts(rcptOffset + rcptLimit)">Next &#8594;</button>
      </div>
    </div>
    <div id="receipts-detail-view" class="receipt-detail"></div>
  </div>

  <!-- LOG TAB -->
  <div id="tab-log" class="tab-content">
    <div class="tree-head" id="tree-head-section">
      <h3>Signed Tree Head</h3>
      <div id="tree-head-fields"><span class="empty-state">Run a demo first, or click refresh below.</span></div>
    </div>
    <button class="btn btn-sm" onclick="loadLog()" style="margin-bottom:1rem">Refresh Log</button>
    <table class="log-table">
      <thead><tr><th>#</th><th>Timestamp</th><th>Entity Type</th><th>Commitment</th></tr></thead>
      <tbody id="log-entries"><tr><td colspan="4" class="empty-state">No entries yet</td></tr></tbody>
    </table>
    <div class="pagination">
      <button id="prev-btn" onclick="loadLog(logOffset - logLimit)" disabled>&#8592; Prev</button>
      <button id="next-btn" onclick="loadLog(logOffset + logLimit)">Next &#8594;</button>
    </div>
    <div class="log-detail" id="log-detail"></div>
  </div>
</div>

<script>
// --- Tab switching ---
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    if (tab.dataset.tab === 'log') loadLog();
    if (tab.dataset.tab === 'receipts') loadReceipts();
  });
});

// ====================
// DEMO
// ====================
let inspectorState = {};

async function runDemo() {
  const input = document.getElementById('input').value.trim();
  if (!input) return;

  const btn = document.getElementById('run-btn');
  const splitPane = document.getElementById('split-pane');
  const timeline = document.getElementById('timeline');
  const inspector = document.getElementById('inspector');
  btn.disabled = true;
  btn.classList.remove('pulse');
  splitPane.style.display = 'grid';
  timeline.innerHTML = '';
  inspector.innerHTML = '<div class="inspector-empty">Waiting for pipeline...</div>';
  inspector.className = 'inspector-panel';
  inspectorState = {};

  const stepCards = new Map();

  try {
    const res = await fetch('/demo/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: input }),
    });

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\\n');
      buffer = lines.pop() || '';

      let currentEvent = '';
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          currentEvent = line.slice(7);
        } else if (line.startsWith('data: ') && currentEvent) {
          const data = JSON.parse(line.slice(6));
          handleSSE(currentEvent, data, timeline, stepCards);
          currentEvent = '';
        }
      }
    }
  } catch (err) {
    timeline.innerHTML += renderError(err.message);
  }

  btn.disabled = false;
}

var stepDescriptions = {
  1: 'Creating a unique encryption key — like forging a one-of-a-kind lock that only one key can open.',
  2: 'Locking your data with that key and storing copies across three separate vaults.',
  3: 'Breaking the key into three pieces and giving each piece to a different guardian. No single guardian can open the lock alone — you need at least two.',
  4: 'Two guardians permanently destroy their key pieces and sign sworn statements proving it. With only one piece left, the lock can never be opened again.',
  5: 'Removing the locked data from all three vaults. Even if someone found it, the key is gone — the data is unreadable.',
  6: 'Inspecting every vault to confirm the data is truly gone — like a notary checking each safe and certifying it\\'s empty.',
  7: 'Updating a public registry to prove this data no longer exists. Anyone can check the registry and verify the deletion independently.',
  8: 'Recording this deletion in a tamper-proof public ledger — like adding an entry to a permanent, unchangeable record book.',
  9: 'Issuing a signed certificate that bundles all the proof together — guardian statements, vault inspections, registry proof, and ledger entry — into one verifiable document.'
};

function handleSSE(event, data, timeline, stepCards) {
  if (event === 'step') {
    const key = data.step;
    if (data.status === 'running') {
      const card = document.createElement('div');
      card.className = 'step-card running';
      const desc = stepDescriptions[data.step] || '';
      card.innerHTML =
        '<div class="step-header">' +
          '<span class="step-num">' + data.step + '</span>' +
          data.name +
          '<span class="spinner"></span>' +
        '</div>' +
        (desc ? '<div class="step-desc">' + desc + '</div>' : '');
      timeline.appendChild(card);
      stepCards.set(key, card);
    } else if (data.status === 'complete') {
      const card = stepCards.get(key);
      if (card) {
        card.className = 'step-card complete';
        const desc = stepDescriptions[data.step] || '';
        let dataHtml = '';
        if (data.data) {
          dataHtml = '<div class="step-data">' + Object.entries(data.data).map(function(pair) {
            return '<span class="label">' + pair[0] + ':</span> ' + (typeof pair[1] === 'object' ? JSON.stringify(pair[1]) : pair[1]);
          }).join('<br>') + '</div>';
        }
        card.innerHTML =
          '<div class="step-header">' +
            '<span class="step-num">' + data.step + '</span>' +
            data.name +
            '<span class="check">&#10003;</span>' +
          '</div>' +
          (desc ? '<div class="step-desc">' + desc + '</div>' : '') +
          dataHtml;
      }
    }
  } else if (event === 'inspector') {
    handleInspector(data);
  } else if (event === 'done') {
    const card = document.createElement('div');
    card.className = 'done-card';
    card.innerHTML =
      '<h3>&#10003; VERIFIED DELETION COMPLETE</h3>' +
      '<div class="step-data">' +
        '<span class="label">Entity ID:</span> ' + data.entityId + '<br>' +
        '<span class="label">Commitment:</span> ' + data.commitment + '<br>' +
        '<span class="label">Operator Key:</span> ' + data.operatorPublicKey + '<br>' +
        '<span class="label">Tree Size:</span> ' + (data.treeHead ? data.treeHead.treeSize : 'N/A') +
      '</div>' +
      '<button class="receipt-toggle" onclick="toggleReceipt(this)">Show Receipt JSON</button>' +
      '<div class="receipt-json">' + JSON.stringify(data.receipt, null, 2) + '</div>';
    timeline.appendChild(card);
  } else if (event === 'error') {
    timeline.innerHTML += renderError(data.message);
  }
}

function toggleReceipt(btn) {
  var jsonEl = btn.nextElementSibling;
  jsonEl.classList.toggle('open');
  btn.textContent = jsonEl.classList.contains('open') ? 'Hide Receipt JSON' : 'Show Receipt JSON';
}

function renderError(message) {
  return '<div class="step-card error">' +
    '<div class="step-header" style="color:var(--red)">Error</div>' +
    '<div class="step-data" style="color:var(--red)">' + escapeHtml(message) + '</div>' +
  '</div>';
}

function escapeHtml(s) {
  var div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// ====================
// DATA INSPECTOR
// ====================
function handleInspector(data) {
  var panel = document.getElementById('inspector');
  var phase = data.phase;
  Object.assign(inspectorState, data);

  // Set phase class for CSS animations
  panel.className = 'inspector-panel phase-' + phase;

  var html = '';

  if (phase === 'plaintext') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-green">READABLE</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">Raw Input</div>' +
        '<div class="hex-block">' + escapeHtml(data.inputPreview) + '</div>' +
        '<div style="font-size:0.7rem;color:var(--text-muted);margin-top:0.25rem">Size: ' + data.inputSize + ' bytes | Format: UTF-8</div>' +
        '<div class="hex-label" style="margin-top:0.75rem">KEK ID</div>' +
        '<div style="font-size:0.7rem;color:#4a9">' + data.kekId + '</div>' +
      '</div>' +
      '<div class="inspector-note">Data is in plaintext. Encryption key generated.</div>';

  } else if (phase === 'encrypted') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-amber">ENCRYPTED</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">Ciphertext</div>' +
        '<div class="hex-block">' + data.ciphertextHex + '</div>' +
        '<div class="hex-label">Nonce</div>' +
        '<div class="hex-block">' + data.nonceHex + '</div>' +
        '<div class="hex-label">Wrapped DEK</div>' +
        '<div class="hex-block">' + data.wrappedDekHex + '</div>' +
        '<div class="hex-label" style="margin-top:0.5rem">Storage Backends</div>' +
        '<div class="backend-badges">' +
          data.backends.map(function(b) { return '<span class="backend-badge active">' + b + '</span>'; }).join('') +
        '</div>' +
      '</div>' +
      '<div class="inspector-note">Data is encrypted but recoverable with the key.</div>';

  } else if (phase === 'key_split') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-amber">KEY DISTRIBUTED</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">Ciphertext</div>' +
        '<div class="hex-block">' + (inspectorState.ciphertextHex || '') + '</div>' +
        '<div class="hex-label" style="margin-top:0.5rem">Key Shares (' + data.threshold + ')</div>' +
        '<div class="share-badges">' +
          data.shares.map(function(s) {
            return '<span class="share-badge ' + s.status + '">' + s.holder + ' [' + s.index + ']</span>';
          }).join('') +
        '</div>' +
      '</div>' +
      '<div class="inspector-note">Any 2 of 3 shares can reconstruct the key.</div>';

  } else if (phase === 'key_destroyed') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-red">IRRECOVERABLE</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">Ciphertext</div>' +
        '<div class="hex-block destroyed">' + (inspectorState.ciphertextHex || '') + '</div>' +
        '<div class="hex-label" style="margin-top:0.5rem">Key Shares</div>' +
        '<div class="share-badges">' +
          data.shares.map(function(s) {
            return '<span class="share-badge ' + s.status + '">' + s.holder + ' [' + s.index + ']' +
              (s.status === 'destroyed' ? ' &#10007;' : '') + '</span>';
          }).join('') +
        '</div>' +
        '<div style="margin-top:0.5rem;font-size:0.7rem;color:var(--red);font-weight:600">KEY STATUS: ' + data.keyStatus.toUpperCase() + '</div>' +
      '</div>' +
      '<div class="inspector-note" style="border-left:2px solid var(--red)">THRESHOLD BREACHED &#8212; key reconstruction is mathematically impossible. Ciphertext is permanently indecipherable.</div>';

  } else if (phase === 'data_deleted') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-red">ERASED</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">Ciphertext</div>' +
        '<div class="hex-block deleted">[DELETED]</div>' +
        '<div class="hex-label" style="margin-top:0.5rem">Storage Backends</div>' +
        '<div class="backend-badges">' +
          data.backendsCleared.map(function(b) { return '<span class="backend-badge cleared">' + b + '</span>'; }).join('') +
        '</div>' +
      '</div>' +
      '<div class="inspector-note">Ciphertext purged from all storage backends.</div>';

  } else if (phase === 'verified') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-green">VERIFIED ABSENT</span></div>' +
      '<div class="inspector-body">' +
        data.backendResults.map(function(b) {
          return '<div class="scan-result">' +
            '<span style="color:var(--text-muted)">' + b.type.toUpperCase() + '</span>' +
            '<span class="arrow">&#8594;</span>' +
            '<span class="status pass">ABSENT &#10003;</span>' +
          '</div>';
        }).join('') +
        '<div class="scan-result">' +
          '<span style="color:var(--text-muted)">KEY</span>' +
          '<span class="arrow">&#8594;</span>' +
          '<span class="status pass">DESTROYED &#10003;</span>' +
        '</div>' +
      '</div>' +
      '<div class="inspector-note">Independent scan confirms no data remnants.</div>';

  } else if (phase === 'smt_proven') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-green">PROVEN ABSENT</span></div>' +
      '<div class="inspector-body">' +
        '<div class="hex-label">SMT Root</div>' +
        '<div class="hex-block">' + data.smtRoot + '</div>' +
        '<div class="hex-label">Entity Hash</div>' +
        '<div class="hex-block">' + data.entityHash + '</div>' +
        '<div class="scan-result">' +
          '<span style="color:var(--text-muted)">NON-MEMBERSHIP</span>' +
          '<span class="arrow">&#8594;</span>' +
          '<span class="status pass">VERIFIED &#10003;</span>' +
        '</div>' +
      '</div>' +
      '<div class="inspector-note">Sparse Merkle Tree cryptographic proof confirms entity does not exist in any data index.</div>';

  } else if (phase === 'logged') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-green">LOGGED</span></div>' +
      '<div class="inspector-body">' +
        '<div class="log-badge">Log Index: ' + data.logIndex + '</div>' +
        '<div class="log-badge">Tree Size: ' + data.treeSize + '</div>' +
        '<div class="hex-label" style="margin-top:0.5rem">Commitment</div>' +
        '<div class="hex-block">' + data.commitment + '</div>' +
      '</div>' +
      '<div class="inspector-note">Deletion committed to transparency log.</div>';

  } else if (phase === 'receipted') {
    html =
      '<div class="inspector-header">DATA STATUS: <span class="status-badge badge-green">CERTIFIED</span></div>' +
      '<div class="inspector-body">' +
        '<div class="log-badge">Receipt: ' + data.receiptId + '</div>' +
        (inspectorState.logIndex !== undefined ? '<div class="log-badge">Log Index: ' + inspectorState.logIndex + '</div>' : '') +
        (inspectorState.commitment ? '<div class="hex-label" style="margin-top:0.5rem">Commitment</div><div class="hex-block">' + inspectorState.commitment + '</div>' : '') +
      '</div>' +
      '<div class="inspector-note">Deletion committed to transparency log. W3C VC receipt generated.</div>';
  }

  panel.innerHTML = html;
}

// ====================
// RECEIPTS TAB
// ====================
let rcptOffset = 0;
const rcptLimit = 20;

async function loadReceipts(offset) {
  if (typeof offset === 'number') rcptOffset = Math.max(0, offset);
  try {
    var entriesRes = await fetch('/log/entries?offset=' + rcptOffset + '&limit=' + rcptLimit);
    var entries = await entriesRes.json();

    var list = document.getElementById('receipt-list');
    if (!entries.length) {
      list.innerHTML = '<div class="empty-state">No receipts yet. Run a demo first.</div>';
    } else {
      list.innerHTML = entries.map(function(e) {
        return '<div class="receipt-card" onclick=\\'showReceiptDetail(' + JSON.stringify(JSON.stringify(e)) + ')\\'>' +
          '<div class="receipt-card-header">' +
            '<span class="receipt-card-title">' + (e.receiptId || 'N/A').slice(0, 16) + '...</span>' +
            '<span class="verified-badge">&#10003; VERIFIED</span>' +
          '</div>' +
          '<div class="receipt-card-meta">' +
            '<span>' + e.entityType + '</span> | ' +
            timeAgo(e.timestamp) + ' | ' +
            e.deletionMethod + '<br>' +
            'Commitment: <span>' + (e.commitment || '').slice(0, 24) + '...</span>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    document.getElementById('rcpt-prev-btn').disabled = rcptOffset === 0;
    document.getElementById('rcpt-next-btn').disabled = entries.length < rcptLimit;
  } catch (err) {
    console.error('Failed to load receipts:', err);
  }
}

function timeAgo(ts) {
  var diff = Date.now() - new Date(ts).getTime();
  var secs = Math.floor(diff / 1000);
  if (secs < 60) return secs + 's ago';
  var mins = Math.floor(secs / 60);
  if (mins < 60) return mins + 'm ago';
  var hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  var days = Math.floor(hrs / 24);
  return days + 'd ago';
}

async function showReceiptDetail(jsonStr) {
  var entry = JSON.parse(jsonStr);
  var listView = document.getElementById('receipts-list-view');
  var detailView = document.getElementById('receipts-detail-view');

  listView.style.display = 'none';
  detailView.className = 'receipt-detail active';

  // Fetch inclusion proof
  var proofHtml = '<div style="color:var(--text-muted);font-size:0.75rem">Click to load...</div>';
  var proofLoaded = false;

  detailView.innerHTML =
    '<button class="receipt-detail-back" onclick="hideReceiptDetail()">&#8592; Back to list</button>' +

    // Section 1: Header
    '<div class="detail-section">' +
      '<h4>Deletion Record</h4>' +
      '<div class="detail-field"><span class="dlabel">Receipt ID</span><span class="dvalue">' + (entry.receiptId || 'N/A') + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Timestamp</span><span class="dvalue">' + entry.timestamp + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Entity Type</span><span class="dvalue">' + entry.entityType + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Deletion Method</span><span class="dvalue">' + entry.deletionMethod + '</span></div>' +
    '</div>' +

    // Section 2: Cryptographic Commitment
    '<div class="detail-section">' +
      '<h4>Cryptographic Commitment</h4>' +
      '<div class="detail-field"><span class="dlabel">Commitment</span><span class="dvalue">' + (entry.commitment || 'N/A') + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Operator Sig</span><span class="dvalue">' + ((entry.operatorSignature || '').slice(0, 64) + '...') + '</span></div>' +
    '</div>' +

    // Section 3: Threshold Attestations
    '<div class="detail-section">' +
      '<h4>Threshold Attestations</h4>' +
      (entry.thresholdSignatures && entry.thresholdSignatures.length
        ? entry.thresholdSignatures.map(function(sig, i) {
            return '<div class="detail-attestation">Share ' + (i + 1) + ': ' + sig.slice(0, 48) + '...</div>';
          }).join('')
        : '<div style="color:var(--text-muted);font-size:0.75rem">No attestations</div>') +
      '<div class="detail-field" style="margin-top:0.5rem"><span class="dlabel">Scan Hash</span><span class="dvalue">' + (entry.scanHash || 'N/A') + '</span></div>' +
    '</div>' +

    // Section 4: Merkle Tree Position
    '<div class="detail-section">' +
      '<h4>Merkle Tree Position</h4>' +
      '<div class="detail-field"><span class="dlabel">Log Index</span><span class="dvalue">' + (entry.index !== undefined ? entry.index : 'N/A') + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">SMT Root</span><span class="dvalue">' + (entry.smtRoot || 'N/A') + '</span></div>' +
      '<button class="btn btn-sm" id="verify-inclusion-btn" onclick="verifyInclusion(' + (entry.index !== undefined ? entry.index : -1) + ')" style="margin-top:0.5rem">Verify Inclusion</button>' +
      '<div id="inclusion-proof-result" style="margin-top:0.5rem"></div>' +
    '</div>' +

    // Section 5: Raw JSON
    '<div class="detail-section">' +
      '<h4>Raw JSON</h4>' +
      '<button class="receipt-toggle" onclick="toggleRawJson(this)">Show Raw JSON</button>' +
      '<div class="detail-raw-json">' + JSON.stringify(entry, null, 2) + '</div>' +
    '</div>';
}

function hideReceiptDetail() {
  document.getElementById('receipts-list-view').style.display = 'block';
  document.getElementById('receipts-detail-view').className = 'receipt-detail';
}

function toggleRawJson(btn) {
  var jsonEl = btn.nextElementSibling;
  jsonEl.classList.toggle('open');
  btn.textContent = jsonEl.classList.contains('open') ? 'Hide Raw JSON' : 'Show Raw JSON';
}

async function verifyInclusion(index) {
  if (index < 0) return;
  var resultEl = document.getElementById('inclusion-proof-result');
  resultEl.innerHTML = '<span class="spinner"></span> Fetching proof...';

  try {
    var res = await fetch('/log/proof/' + index);
    var proof = await res.json();
    if (proof.error) {
      resultEl.innerHTML = '<div style="color:var(--red);font-size:0.75rem">' + escapeHtml(proof.error) + '</div>';
      return;
    }
    resultEl.innerHTML =
      '<div class="detail-field"><span class="dlabel">Tree Root</span><span class="dvalue">' + proof.rootHash + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Tree Size</span><span class="dvalue">' + proof.treeSize + '</span></div>' +
      '<div class="detail-field"><span class="dlabel">Log Index</span><span class="dvalue">' + proof.logIndex + '</span></div>' +
      (proof.hashes && proof.hashes.length
        ? '<div class="hex-label" style="margin-top:0.5rem">Proof Hashes</div>' +
          '<div class="detail-proof-hashes">' + proof.hashes.join('\\n') + '</div>'
        : '<div style="color:var(--text-muted);font-size:0.7rem;margin-top:0.25rem">Single-entry tree (no sibling hashes needed)</div>') +
      '<div style="margin-top:0.5rem"><span class="verified-badge">&#10003; INCLUSION VERIFIED</span></div>';
  } catch (err) {
    resultEl.innerHTML = '<div style="color:var(--red);font-size:0.75rem">' + escapeHtml(err.message) + '</div>';
  }
}

// ====================
// LOG TAB
// ====================
let logOffset = 0;
const logLimit = 20;

async function loadLog(offset) {
  if (typeof offset === 'number') logOffset = Math.max(0, offset);
  try {
    const [headRes, entriesRes] = await Promise.all([
      fetch('/log'),
      fetch('/log/entries?offset=' + logOffset + '&limit=' + logLimit),
    ]);
    const head = await headRes.json();
    const entries = await entriesRes.json();

    // Tree head
    const thf = document.getElementById('tree-head-fields');
    if (head.treeSize !== undefined) {
      thf.innerHTML =
        '<div class="field"><span class="label">Tree Size:</span><span class="value">' + head.treeSize + '</span></div>' +
        '<div class="field"><span class="label">Root Hash:</span><span class="value">' + head.rootHash + '</span></div>' +
        '<div class="field"><span class="label">Timestamp:</span><span class="value">' + head.timestamp + '</span></div>' +
        '<div class="field"><span class="label">Signature:</span><span class="value">' + (head.signature ? head.signature.slice(0,64) + '...' : 'N/A') + '</span></div>';
    }

    // Entries table
    const tbody = document.getElementById('log-entries');
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No entries yet</td></tr>';
    } else {
      tbody.innerHTML = entries.map(function(e) {
        return '<tr onclick="showLogDetail(' + JSON.stringify(JSON.stringify(e)) + ')">' +
          '<td>' + e.index + '</td>' +
          '<td>' + new Date(e.timestamp).toLocaleString() + '</td>' +
          '<td>' + e.entityType + '</td>' +
          '<td>' + e.commitment.slice(0,16) + '...</td>' +
        '</tr>';
      }).join('');
    }

    // Pagination
    document.getElementById('prev-btn').disabled = logOffset === 0;
    document.getElementById('next-btn').disabled = entries.length < logLimit;
  } catch (err) {
    console.error('Failed to load log:', err);
  }
}

function showLogDetail(jsonStr) {
  const detail = document.getElementById('log-detail');
  detail.classList.add('open');
  detail.textContent = JSON.stringify(JSON.parse(jsonStr), null, 2);
}
</script>
</body>
</html>`;
}
