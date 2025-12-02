function navMarkup(active) {
  const cls = (key) => (key === active ? "active" : "");
  return `
    <div class="brand">
      <div class="brand-icon">N</div>
      <span>NoClickOps</span>
    </div>
    <div class="nav-group">
      <div class="nav-label">Platform</div>
      <a class="nav-link ${cls("dashboard")}" href="/dashboard.html">Dashboard</a>
      <a class="nav-link ${cls("scanners")}" href="/scanners.html">Scanners</a>
      <a class="nav-link ${cls("findings")}" href="/findings.html">Findings</a>
      <a class="nav-link ${cls("trusts")}" href="/trusts.html">Trusts</a>
      <a class="nav-link ${cls("docs")}" href="/docs.html">Docs</a>
    </div>
  `;
}

function mountNav(active) {
  const el = document.getElementById("nav-container");
  if (!el) return;
  el.innerHTML = navMarkup(active);
}
