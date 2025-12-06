function navMarkup(active) {
  const cls = (key) => (key === active ? "active" : "");
  return `
    <div class="brand">
      <div class="brand-icon">N</div>
      <span>NoClickOps</span>
      <button id="nav-collapse-btn" class="nav-collapse-toggle" title="Collapse navigation">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M11 19l-7-7 7-7m8 14l-7-7 7-7"/>
        </svg>
      </button>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="dashboard">
        <div class="nav-label">Dashboard</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="dashboard">
        <a class="nav-link ${cls("dashboard")}" href="/dashboard.html">Overview</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="scanners">
        <div class="nav-label">Scanners</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="scanners">
        <a class="nav-link ${cls("scanners")}" href="/scanners.html">Scanner Management</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="findings">
        <div class="nav-label">Findings</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="findings">
        <a class="nav-link ${cls("findings")}" href="/findings.html">Security Findings</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="network">
        <div class="nav-label">Network</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="network">
        <a class="nav-link ${cls("network")}" href="/network.html">Network Traffic</a>
        <a class="nav-link ${cls("network-trusts")}" href="/network_trusts.html">Network Trusts</a>
        <a class="nav-link ${cls("portscans")}" href="/portscans.html">Port Scanning</a>
        <a class="nav-link ${cls("dns-exfil")}" href="/dns_exfil.html">DNS Exfil Detection</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="iam">
        <div class="nav-label">IAM</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="iam">
        <a class="nav-link ${cls("trusts")}" href="/trusts.html">IAM Trusts</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="security">
        <div class="nav-label">Security</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="security">
        <a class="nav-link ${cls("security")}" href="/security.html">Shell Executions</a>
      </div>
    </div>

    <div class="nav-group">
      <div class="nav-section-header" data-section="docs">
        <div class="nav-label">Documentation</div>
        <svg class="nav-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 12 15 18 9"></polyline>
        </svg>
      </div>
      <div class="nav-section-content" data-section-content="docs">
        <a class="nav-link ${cls("docs-aws-tf")}" href="/docs.html#aws-terraform">AWS (Terraform)</a>
        <a class="nav-link ${cls("docs-aws-cli")}" href="/docs.html#aws-cli">AWS (CLI)</a>
        <a class="nav-link ${cls("docs-gcp-tf")}" href="/docs.html#gcp-terraform">GCP (Terraform)</a>
        <a class="nav-link ${cls("docs-gcp-cli")}" href="/docs.html#gcp-cli">GCP (CLI)</a>
        <a class="nav-link ${cls("docs-azure-tf")}" href="/docs.html#azure-terraform">Azure (Terraform)</a>
        <a class="nav-link ${cls("docs-azure-cli")}" href="/docs.html#azure-cli">Azure (CLI)</a>
      </div>
    </div>
  `;
}

function mountNav(active) {
  const el = document.getElementById("nav-container");
  if (!el) return;
  el.innerHTML = navMarkup(active);

  // Handle sidebar collapse
  const collapseBtn = document.getElementById("nav-collapse-btn");
  const aside = document.querySelector("aside");

  // Restore collapse state from localStorage
  const isCollapsed = localStorage.getItem("nav-collapsed") === "true";
  if (isCollapsed && aside) {
    aside.classList.add("collapsed");
  }

  if (collapseBtn && aside) {
    collapseBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      aside.classList.toggle("collapsed");
      localStorage.setItem("nav-collapsed", aside.classList.contains("collapsed"));
    });
  }

  // Handle section expand/collapse for groups with section headers
  const sectionHeaders = document.querySelectorAll(".nav-section-header");
  sectionHeaders.forEach(header => {
    const sectionName = header.getAttribute("data-section");
    const content = document.querySelector(`[data-section-content="${sectionName}"]`);

    if (!content) return; // Skip if no content section

    // Restore section state from localStorage (default: collapsed)
    const isExpanded = localStorage.getItem(`nav-section-${sectionName}`) === "true";
    if (!isExpanded) {
      header.classList.add("collapsed");
      content.classList.add("collapsed");
    }

    header.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();

      const isCurrentlyCollapsed = header.classList.contains("collapsed");
      header.classList.toggle("collapsed");
      content.classList.toggle("collapsed");
      localStorage.setItem(`nav-section-${sectionName}`, isCurrentlyCollapsed ? "true" : "false");
    });
  });

  // For nav links inside section contents, prevent triggering parent handlers
  const contentLinks = document.querySelectorAll(".nav-section-content .nav-link");
  contentLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      e.stopPropagation();
      // Let the link navigate normally
    });
  });
}
