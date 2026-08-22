from __future__ import annotations


def dashboard_html() -> str:
    return """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Norinth</title>
    <style>
      :root {
        --bg: #ffffff;
        --surface: #fafafa;
        --surface-hover: #f3f4f6;
        --border: #e5e7eb;
        --text-main: #111827;
        --text-muted: #6b7280;
        --primary: #000000;
        --success: #059669;
        --success-bg: #d1fae5;
        --danger: #dc2626;
        --danger-bg: #fee2e2;
        --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
      }

      * { box-sizing: border-box; margin: 0; padding: 0; }
      
      body {
        font-family: var(--font-sans);
        color: var(--text-main);
        background-color: var(--bg);
        line-height: 1.5;
        -webkit-font-smoothing: antialiased;
      }

      a { color: inherit; text-decoration: none; }
      
      .layout {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
      }

      .navbar {
        position: sticky;
        top: 0;
        z-index: 10;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 32px;
        background: rgba(255, 255, 255, 0.8);
        backdrop-filter: blur(12px);
        border-bottom: 1px solid var(--border);
      }

      .brand {
        font-size: 18px;
        font-weight: 700;
        letter-spacing: -0.04em;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      main {
        flex: 1;
        padding: 48px 32px;
        max-width: 1200px;
        margin: 0 auto;
        width: 100%;
      }

      .page-header {
        margin-bottom: 48px;
      }

      .page-title {
        font-size: 32px;
        font-weight: 600;
        letter-spacing: -0.05em;
        margin-bottom: 12px;
      }

      .page-description {
        font-size: 16px;
        color: var(--text-muted);
        max-width: 600px;
      }

      .grid-2 {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 24px;
        margin-bottom: 48px;
      }

      .card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px;
        transition: border-color 0.2s ease;
      }

      .card:hover {
        border-color: #d1d5db;
      }

      .card-title {
        font-size: 14px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--text-muted);
        margin-bottom: 16px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .stat-value {
        font-size: 36px;
        font-weight: 600;
        letter-spacing: -0.04em;
        margin-bottom: 4px;
      }

      .stat-sub {
        font-size: 14px;
        color: var(--text-muted);
      }

      .verified-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: var(--success-bg);
        color: var(--success);
        padding: 4px 10px;
        border-radius: 99px;
        font-size: 12px;
        font-weight: 600;
      }

      .verified-badge::before {
        content: '';
        display: block;
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
      }

      .data-table-container {
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
      }

      th, td {
        padding: 16px 24px;
        border-bottom: 1px solid var(--border);
        font-size: 14px;
      }

      th {
        background: var(--surface);
        font-weight: 500;
        color: var(--text-muted);
      }

      tr:last-child td { border-bottom: none; }
      tbody tr:hover { background: var(--surface-hover); }

      .mono {
        font-family: var(--font-mono);
        font-size: 13px;
        color: var(--text-muted);
        background: var(--surface);
        padding: 2px 6px;
        border-radius: 4px;
        border: 1px solid var(--border);
      }

      .tags { display: flex; flex-wrap: wrap; gap: 8px; }
      .tag {
        font-size: 12px;
        font-weight: 500;
        padding: 4px 8px;
        background: white;
        border: 1px solid var(--border);
        border-radius: 6px;
        color: var(--text-main);
      }

      .empty-state {
        text-align: center;
        padding: 64px 24px;
        color: var(--text-muted);
      }

      .filter-bar {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
        align-items: center;
      }

      .filter-bar input {
        padding: 10px 16px;
        border: 1px solid var(--border);
        border-radius: 8px;
        font-size: 14px;
        outline: none;
        width: 300px;
        font-family: var(--font-sans);
        transition: border-color 0.2s;
      }

      .filter-bar input:focus {
        border-color: var(--primary);
      }

      .filter-bar button {
        padding: 10px 20px;
        background: var(--primary);
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: opacity 0.2s;
      }

      .filter-bar button:hover {
        opacity: 0.9;
      }

      .section { margin-bottom: 64px; }
      .section-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        margin-bottom: 24px;
      }

      .section-title {
        font-size: 20px;
        font-weight: 600;
        letter-spacing: -0.02em;
      }
    </style>
  </head>
  <body>
    <div class="layout">
      <nav class="navbar">
        <div class="brand">
          Norinth
            </div>
      </nav>

      <main>
        <header class="page-header">
          <h1 class="page-title">Vendors</h1>
          <p class="page-description">Review compliance and inventory data for your vendors.</p>
        </header>

        <div class="filter-bar">
          <input type="text" id="tenant-input" placeholder="Vendor ID (e.g., tenant-verify)" value="tenant-verify">
          <button onclick="loadAIBOM()">Load</button>
          </div>

        <div id="loading" class="empty-state" style="display: none;">
          Loading vendor data...
            </div>

        <div id="error" class="empty-state" style="display: none; color: var(--danger);">
          </div>

        <div id="content" style="display: none;">
          <div class="grid-2">
            <div class="card">
              <div class="card-title">
                Applications
                <span class="verified-badge">Verified</span>
              </div>
              <div class="stat-value" id="stat-systems">0</div>
              <div class="stat-sub">Active Applications</div>
            </div>
            
            <div class="card">
              <div class="card-title">Dependencies</div>
              <div class="stat-value" id="stat-providers">0</div>
              <div class="stat-sub">Models & Providers</div>
            </div>
          </div>

          <div class="section">
            <div class="section-header">
              <h2 class="section-title">Bill of Materials</h2>
            </div>
            <div class="data-table-container">
              <table>
                <thead>
                  <tr>
                    <th>Application</th>
                    <th>Use Case</th>
                    <th>Models & Providers</th>
                    <th>Guardrails</th>
                  </tr>
                </thead>
                <tbody id="aibom-tbody">
                </tbody>
              </table>
            </div>
            </div>
            </div>
      </main>
            </div>

    <script>
      async function loadAIBOM() {
        const tenantId = document.getElementById('tenant-input').value.trim();
        const loading = document.getElementById('loading');
        const content = document.getElementById('content');
        const error = document.getElementById('error');

        loading.style.display = 'block';
        content.style.display = 'none';
        error.style.display = 'none';

        try {
          const res = await fetch(`/api/compliance/aibom?tenant_id=${encodeURIComponent(tenantId)}`);
          if (!res.ok) throw new Error('Failed to load vendor data.');
          
          const data = await res.json();
          
          document.getElementById('stat-systems').textContent = data.ai_systems_inventory.length;
          document.getElementById('stat-providers').textContent = data.providers_in_use.length + data.models_in_use.length;
          
          const tbody = document.getElementById('aibom-tbody');
          
          if (data.ai_systems_inventory.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No applications found.</td></tr>`;
          } else {
            tbody.innerHTML = data.ai_systems_inventory.map(sys => `
              <tr>
                <td>
                  <div style="font-weight: 500; margin-bottom: 4px;">${escapeHtml(sys.application_name)}</div>
                  <div class="mono">${escapeHtml(sys.workflow_name)}</div>
                </td>
                <td>
                  <div style="color: var(--text-muted); font-size: 13px;">${escapeHtml(sys.use_case || 'None specified')}</div>
                </td>
                <td>
                  <div class="tags">
                    ${sys.components.providers.map(p => `<span class="tag">${escapeHtml(p)}</span>`).join('')}
                    ${sys.components.models.map(m => `<span class="tag" style="background: var(--surface);">${escapeHtml(m)}</span>`).join('')}
                  </div>
                </td>
                <td>
                  <div class="tags">
                    ${sys.components.guardrails.length ? sys.components.guardrails.map(g => `<span class="tag">${escapeHtml(g)}</span>`).join('') : '<span class="mono" style="color: var(--danger);">None detected</span>'}
                  </div>
                </td>
              </tr>
            `).join('');
          }
          
          loading.style.display = 'none';
          content.style.display = 'block';
          
        } catch (err) {
          loading.style.display = 'none';
          error.textContent = err.message;
          error.style.display = 'block';
        }
      }

      function escapeHtml(str) {
        if (!str) return '';
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      }
      
      window.onload = loadAIBOM;
    </script>
  </body>
</html>
"""
