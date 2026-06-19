(function () {
  "use strict";

  const state = {
    rows: [],
    filteredRows: [],
    sortKey: "host",
    sortDirection: "asc",
    filters: {
      host: "",
      service: "",
      protocol: "",
      severity: "",
      finding: ""
    }
  };

  const adPorts = new Set(["53", "88", "135", "139", "389", "445", "464", "593", "636", "3268", "3269", "3389", "5985", "5986"]);

  const elements = {
    body: document.getElementById("findingsBody"),
    empty: document.getElementById("emptyState"),
    table: document.getElementById("findingsTable"),
    reset: document.getElementById("resetFilters"),
    filters: {
      host: document.getElementById("filterHost"),
      service: document.getElementById("filterService"),
      protocol: document.getElementById("filterProtocol"),
      severity: document.getElementById("filterSeverity"),
      finding: document.getElementById("filterFinding")
    },
    stats: {
      hosts: document.getElementById("statHosts"),
      ports: document.getElementById("statPorts"),
      high: document.getElementById("statHigh"),
      cves: document.getElementById("statCves"),
      creds: document.getElementById("statCreds"),
      asrep: document.getElementById("statAsrep")
    },
    summary: document.getElementById("executionSummary"),
    domain: document.getElementById("domainName"),
    dc: document.getElementById("dcIp")
  };

  function parseJsonScript(ids, fallback) {
    for (const id of ids) {
      const node = document.getElementById(id);
      if (!node) {
        continue;
      }
      const raw = node.textContent.trim();
      if (!raw) {
        continue;
      }
      try {
        return JSON.parse(raw);
      } catch (error) {
        console.error(`Could not parse JSON from #${id}:`, error);
      }
    }
    return fallback;
  }

  function escapeHtml(value) {
    return String(value === undefined || value === null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function normalizeSeverity(port) {
    if (Array.isArray(port.cves) && port.cves.length > 0) {
      return "high";
    }

    const portId = String(port.port || "");
    if (["21", "23", "445", "3389", "5985"].includes(portId)) {
      return "high";
    }
    if (["88", "139", "389", "636", "3268", "3269"].includes(portId)) {
      return "medium";
    }
    return String(port.severity || "low").toLowerCase();
  }

  function flattenHosts(hosts) {
    const rows = [];

    if (!Array.isArray(hosts)) {
      return rows;
    }

    hosts.forEach((host) => {
      const credentials = Array.isArray(host.credentials) ? host.credentials : [];
      const credentialsText = credentials
        .map((cred) => `${cred.service || "svc"}:${cred.user || ""}:${cred.pass || ""}`)
        .join(" | ");

      const ports = Array.isArray(host.ports) ? host.ports : [];
      ports.forEach((port) => {
        const cves = Array.isArray(port.cves) ? port.cves : [];
        rows.push({
          host: String(host.ip || "unknown"),
          port: String(port.port || "unknown"),
          portNumber: Number.parseInt(port.port, 10) || 0,
          protocol: String(port.protocol || "tcp").toLowerCase(),
          service: String(port.service || "unknown").toLowerCase(),
          version: String(port.version || "Unknown"),
          severity: normalizeSeverity(port),
          credentials,
          credentialsText,
          cves,
          cveText: cves.join(" "),
          isAdService: adPorts.has(String(port.port || ""))
        });
      });
    });

    return rows;
  }

  function uniqueSorted(values) {
    return Array.from(new Set(values.filter(Boolean))).sort((a, b) => String(a).localeCompare(String(b), undefined, { numeric: true }));
  }

  function populateSelect(select, values, placeholder) {
    const current = select.value;
    select.innerHTML = "";
    const first = document.createElement("option");
    first.value = "";
    first.textContent = placeholder;
    select.appendChild(first);

    values.forEach((value) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      select.appendChild(option);
    });

    select.value = values.includes(current) ? current : "";
  }

  function populateFilters() {
    populateSelect(elements.filters.host, uniqueSorted(state.rows.map((row) => row.host)), "All hosts");
    populateSelect(elements.filters.service, uniqueSorted(state.rows.map((row) => row.service)), "All services");
    populateSelect(elements.filters.protocol, uniqueSorted(state.rows.map((row) => row.protocol)), "All protocols");
    populateSelect(elements.filters.severity, uniqueSorted(state.rows.map((row) => row.severity)), "All severities");
  }

  function updateStats(summary) {
    const hosts = uniqueSorted(state.rows.map((row) => row.host));
    const cveSet = new Set();
    let high = 0;
    let creds = 0;

    state.rows.forEach((row) => {
      if (row.severity === "high") {
        high += 1;
      }
      row.cves.forEach((cve) => cveSet.add(cve));
      if (row.credentials.length > 0) {
        creds += row.credentials.length;
      }
    });

    elements.stats.hosts.textContent = hosts.length;
    elements.stats.ports.textContent = state.rows.length;
    elements.stats.high.textContent = high;
    elements.stats.cves.textContent = cveSet.size;
    elements.stats.creds.textContent = creds;
    elements.stats.asrep.textContent = Number(summary.asrep_hash_count || 0);
  }

  function updateSummary(summary) {
    const domain = summary.domain || "Unknown";
    const dcIp = summary.dc_ip || "Unknown";
    const scan = tierName(summary.scan_level);
    const enumeration = tierName(summary.enumeration_level);
    const exploitation = tierName(summary.exploitation_level);

    elements.domain.textContent = `Domain: ${domain}`;
    elements.dc.textContent = `DC: ${dcIp}`;
    elements.summary.textContent = `Scan tier: ${scan}. Enumeration tier: ${enumeration}. Exploitation tier: ${exploitation}. Output directory: ${summary.output_dir || "local scan directory"}.`;
  }

  function tierName(value) {
    const names = {
      "0": "None",
      "1": "Basic",
      "2": "Intermediate",
      "3": "Advanced"
    };
    return names[String(value)] || "Unknown";
  }

  function applyFilters() {
    state.filters.host = elements.filters.host.value;
    state.filters.service = elements.filters.service.value;
    state.filters.protocol = elements.filters.protocol.value;
    state.filters.severity = elements.filters.severity.value;
    state.filters.finding = elements.filters.finding.value;

    state.filteredRows = state.rows.filter((row) => {
      if (state.filters.host && row.host !== state.filters.host) {
        return false;
      }
      if (state.filters.service && row.service !== state.filters.service) {
        return false;
      }
      if (state.filters.protocol && row.protocol !== state.filters.protocol) {
        return false;
      }
      if (state.filters.severity && row.severity !== state.filters.severity) {
        return false;
      }
      if (state.filters.finding === "cve" && row.cves.length === 0) {
        return false;
      }
      if (state.filters.finding === "creds" && row.credentials.length === 0) {
        return false;
      }
      if (state.filters.finding === "ad" && !row.isAdService) {
        return false;
      }
      return true;
    });

    sortRows();
    renderTable();
  }

  function sortRows() {
    const direction = state.sortDirection === "asc" ? 1 : -1;
    const key = state.sortKey;

    state.filteredRows.sort((a, b) => {
      const av = a[key];
      const bv = b[key];
      if (typeof av === "number" && typeof bv === "number") {
        return (av - bv) * direction;
      }
      return String(av || "").localeCompare(String(bv || ""), undefined, { numeric: true }) * direction;
    });
  }

  function renderCredentials(row) {
    if (!row.credentials.length) {
      return '<span class="muted">None</span>';
    }
    return row.credentials
      .map((cred) => {
        const label = `${cred.service || "svc"} ${cred.user || ""}:${cred.pass || ""}`;
        return `<span class="badge badge-cred">${escapeHtml(label)}</span>`;
      })
      .join("");
  }

  function renderCves(row) {
    if (!row.cves.length) {
      if (row.isAdService) {
        return '<span class="muted">Review hardening</span>';
      }
      return '<span class="muted">None</span>';
    }

    return row.cves
      .map((cve) => {
        const safeCve = escapeHtml(cve);
        const href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
        return `<a class="badge cve-link" href="${href}" target="_blank" rel="noopener noreferrer">${safeCve}</a>`;
      })
      .join("");
  }

  function renderTable() {
    elements.body.innerHTML = "";

    elements.empty.hidden = state.filteredRows.length !== 0;
    elements.table.hidden = state.filteredRows.length === 0;

    const fragment = document.createDocumentFragment();
    state.filteredRows.forEach((row) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(row.host)}</td>
        <td>${escapeHtml(row.port)}</td>
        <td>${escapeHtml(row.protocol)}</td>
        <td>${escapeHtml(row.service)}</td>
        <td>${escapeHtml(row.version)}</td>
        <td><span class="badge badge-${escapeHtml(row.severity)}">${escapeHtml(row.severity)}</span></td>
        <td>${renderCredentials(row)}</td>
        <td>${renderCves(row)}</td>
      `;
      fragment.appendChild(tr);
    });

    elements.body.appendChild(fragment);
    updateSortClasses();
  }

  function updateSortClasses() {
    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.classList.remove("sort-asc", "sort-desc");
      if (th.dataset.sort === state.sortKey) {
        th.classList.add(state.sortDirection === "asc" ? "sort-asc" : "sort-desc");
      }
    });
  }

  function bindEvents() {
    Object.values(elements.filters).forEach((select) => {
      select.addEventListener("change", applyFilters);
    });

    elements.reset.addEventListener("click", () => {
      Object.values(elements.filters).forEach((select) => {
        select.value = "";
      });
      applyFilters();
    });

    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const nextKey = th.dataset.sort;
        if (state.sortKey === nextKey) {
          state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
        } else {
          state.sortKey = nextKey;
          state.sortDirection = "asc";
        }
        applyFilters();
      });
    });
  }

  function init() {
    const hosts = parseJsonScript(["domainMapperData", "vulnerData"], []);
    const summary = parseJsonScript(["domainMapperSummary"], {});

    state.rows = flattenHosts(hosts);
    state.filteredRows = state.rows.slice();

    updateStats(summary);
    updateSummary(summary);
    populateFilters();
    bindEvents();
    applyFilters();

    if (!state.rows.length) {
      console.warn("No valid Domain Mapper data was found in the report.");
    }
  }

  init();
})();
