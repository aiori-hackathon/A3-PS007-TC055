/**
 * dashboard.js - Main Application Controller & Telemetry State
 * PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
 */

const AppState = {
  currentTenant: "tenant-alpha",
  activeSection: "overview-section",
  autoRefreshInterval: 1500, // 1.5 seconds polling
  timerId: null,
  isAutoRefreshActive: true,
  charts: {
    trafficLine: null,
    icmpDoughnut: null,
    evaluationBar: null
  },
  rateHistory: []
};

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initTenantSelector();
  initRefreshControls();
  initCharts();
  fetchDashboardData();
  startAutoRefresh();
});

function initNavigation() {
  const links = document.querySelectorAll(".nav-link-custom");
  links.forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const targetId = link.getAttribute("data-target");
      switchSection(targetId);
      links.forEach(l => l.classList.remove("active"));
      link.classList.add("active");
    });
  });

  // Handle in-page view links
  document.querySelectorAll(".view-tab-link").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const targetId = btn.getAttribute("data-target");
      switchSection(targetId);
      document.querySelectorAll(".nav-link-custom").forEach(l => {
        l.classList.toggle("active", l.getAttribute("data-target") === targetId);
      });
    });
  });
}

function switchSection(targetId) {
  document.querySelectorAll(".dashboard-section").forEach(sec => {
    sec.classList.remove("active-section");
  });
  const target = document.getElementById(targetId);
  if (target) {
    target.classList.add("active-section");
    AppState.activeSection = targetId;

    // Update headings
    const headings = {
      "overview-section": ["System Overview", "Privacy-Preserving IPv6 IoT Security & Ephemeral Pseudonym Correlation"],
      "devices-section": ["IoT Devices Management", "Authenticated Device Sessions and RFC 4941 Temporary Address Monitoring"],
      "monitoring-section": ["Network Monitoring & DPI", "Scapy Deep Packet Inspection of ICMPv6 Router & Neighbor Discovery"],
      "rotation-section": ["IPv6 Address Rotation Engine", "RFC 4941 Address Generation, Rotation Handshake, and Pseudonym Persistence"],
      "alerts-section": ["Security Alerts & Intrusion Detection", "Rogue RA and Abnormal NDP Flooding Intrusion Telemetry"],
      "simulation-section": ["Attack & Traffic Simulator", "Isolated Virtual Network Security Injection Controls"],
      "privacy-section": ["Privacy Verification & Tenant Isolation", "Zero Hardware Fingerprinting & Ephemeral Pseudonym Invalidation"],
      "evaluation-section": ["Detection Evaluation Metrics", "Empirical Precision, Recall, False Positive Rate, and Latency Benchmarks"],
      "settings-section": ["Configuration & Settings", "Trusted Router Whitelist and Linux Virtual Network Setup"]
    };

    if (headings[targetId]) {
      document.getElementById("page-heading").innerText = headings[targetId][0];
      document.getElementById("page-subheading").innerText = headings[targetId][1];
    }

    // Refresh context if needed
    fetchDashboardData();
  }
}

function initTenantSelector() {
  const selector = document.getElementById("tenant-selector");
  if (selector) {
    selector.addEventListener("change", (e) => {
      AppState.currentTenant = e.target.value;
      const indicator = document.getElementById("active-tenant-indicator");
      if (indicator) indicator.innerText = AppState.currentTenant;
      fetchDashboardData();
    });
  }
}

function initRefreshControls() {
  const refreshBtn = document.getElementById("btn-refresh-now");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => fetchDashboardData());
  }

  const toggleBtn = document.getElementById("btn-toggle-auto-refresh");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      AppState.isAutoRefreshActive = !AppState.isAutoRefreshActive;
      if (AppState.isAutoRefreshActive) {
        startAutoRefresh();
        toggleBtn.innerHTML = '<i class="bi bi-play-fill"></i> Live Auto-Sync';
        toggleBtn.className = "btn btn-sm btn-primary-custom";
      } else {
        stopAutoRefresh();
        toggleBtn.innerHTML = '<i class="bi bi-pause-fill"></i> Paused';
        toggleBtn.className = "btn btn-sm btn-outline-custom";
      }
    });
  }
}

function startAutoRefresh() {
  stopAutoRefresh();
  AppState.timerId = setInterval(() => {
    fetchDashboardData();
  }, AppState.autoRefreshInterval);
}

function stopAutoRefresh() {
  if (AppState.timerId) {
    clearInterval(AppState.timerId);
    AppState.timerId = null;
  }
}

function initCharts() {
  // Traffic Line Chart
  const ctxTraffic = document.getElementById("trafficLineChart");
  if (ctxTraffic && window.Chart) {
    AppState.charts.trafficLine = new Chart(ctxTraffic, {
      type: "line",
      data: {
        labels: Array(15).fill(""),
        datasets: [{
          label: "ICMPv6 pkts/s",
          data: Array(15).fill(0),
          borderColor: "#0284c7",
          backgroundColor: "rgba(2, 132, 199, 0.08)",
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, grid: { color: "#f1f5f9" } },
          x: { grid: { display: false } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

async function fetchDashboardData() {
  try {
    const res = await fetch(`/api/dashboard?tenant_id=${AppState.currentTenant}`);
    const data = await res.json();
    if (data.status === "SUCCESS") {
      updateOverviewUI(data.data);
    }
  } catch (err) {
    console.error("Error fetching dashboard telemetry:", err);
  }

  // Trigger sub-module updates based on active section
  if (window.DevicesModule) DevicesModule.update(AppState.currentTenant);
  if (window.MonitoringModule) MonitoringModule.update(AppState.currentTenant);
  if (window.AlertsModule) AlertsModule.update(AppState.currentTenant);
}

function updateOverviewUI(summary) {
  // Metric Cards
  document.getElementById("card-total-devices").innerText = summary.total_devices || 5;
  document.getElementById("card-active-sessions").innerText = summary.active_sessions || 0;
  document.getElementById("card-rotations-count").innerText = summary.ipv6_rotations_count || 0;
  document.getElementById("card-total-alerts").innerText = summary.total_alerts || 0;
  document.getElementById("card-rogue-ra").innerText = summary.rogue_ra_detections || 0;
  document.getElementById("card-ndp-anomalies").innerText = summary.ndp_anomalies || 0;

  // Platform & Mode Badge
  const platBadge = document.getElementById("platform-badge");
  if (platBadge) {
    platBadge.innerText = summary.monitoring_mode === "LINUX_RAW_CAPTURE" ? "LINUX-RAW" : "SIM-PIPELINE";
  }

  // Mode label
  const modeLabel = document.getElementById("overview-mode-label");
  if (modeLabel) {
    modeLabel.innerText = summary.platform || "Safe Simulation Pipeline";
  }

  // Health Score Meter
  const score = summary.network_health_score || 100;
  document.getElementById("health-score-val").innerText = score;
  const bar = document.getElementById("health-bar");
  const tag = document.getElementById("health-tag");
  const desc = document.getElementById("health-desc");

  if (bar && tag) {
    bar.style.width = `${score}%`;
    bar.className = `progress-bar bg-${summary.network_health_color}`;
    tag.className = `badge bg-${summary.network_health_color} health-status-tag`;
    tag.innerText = summary.network_health_status;
  }

  if (desc) {
    if (score >= 85) {
      desc.innerText = "Network health pristine. Normal authenticated IoT telemetry without anomalous traffic spikes.";
    } else if (score >= 60) {
      desc.innerText = "Elevated network activity detected. NDP message rates or unauthorized advertisements under inspection.";
    } else {
      desc.innerText = "CRITICAL RISK: Active rogue router advertisement or abnormal NDP flood detected on IPv6 LAN!";
    }
  }

  // Rate Chart Update
  const pps = summary.packets_per_second || 0;
  const rateLabel = document.getElementById("chart-rate-label");
  if (rateLabel) rateLabel.innerText = `${pps} pkts/s`;

  if (AppState.charts.trafficLine) {
    const chart = AppState.charts.trafficLine;
    const currentData = chart.data.datasets[0].data;
    currentData.shift();
    currentData.push(pps);
    chart.update("none");
  }

  // Alerts sidebar badge
  const sidebarAlertBadge = document.getElementById("sidebar-alert-badge");
  if (sidebarAlertBadge) {
    if (summary.total_alerts > 0) {
      sidebarAlertBadge.style.display = "inline-block";
      sidebarAlertBadge.innerText = summary.total_alerts;
    } else {
      sidebarAlertBadge.style.display = "none";
    }
  }

  // Overview Recent Alerts
  const alertsContainer = document.getElementById("overview-alerts-list");
  if (alertsContainer && summary.recent_alerts) {
    if (summary.recent_alerts.length === 0) {
      alertsContainer.innerHTML = `
        <div class="text-center text-muted py-4 small">
          <i class="bi bi-shield-check text-success fs-3 d-block mb-1"></i>
          Zero active security violations. Network is safe.
        </div>`;
    } else {
      let html = '<div class="list-group list-group-flush small">';
      summary.recent_alerts.slice(0, 4).forEach(a => {
        const badgeClass = a.severity === "CRITICAL" ? "bg-danger" : "bg-warning text-dark";
        html += `
          <div class="list-group-item px-0 py-2">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="badge ${badgeClass}">${a.severity}</span>
              <span class="text-muted font-monospace" style="font-size:0.75rem;">${new Date(a.timestamp * 1000).toLocaleTimeString()}</span>
            </div>
            <strong class="d-block text-dark">${a.attack_type.replace(/_/g, ' ')}</strong>
            <span class="text-muted" style="font-size:0.8rem;">Source: <code class="text-dark">${a.src_ipv6}</code></span>
            ${a.pseudonym ? `<span class="badge badge-pseudonym ms-1">${a.pseudonym}</span>` : ''}
          </div>`;
      });
      html += '</div>';
      alertsContainer.innerHTML = html;
    }
  }

  // Overview Devices Table Preview
  if (window.DevicesModule && window.DevicesModule.latestDevices) {
    const tbody = document.querySelector("#overview-devices-table tbody");
    if (tbody) {
      tbody.innerHTML = "";
      window.DevicesModule.latestDevices.slice(0, 5).forEach(d => {
        const statusBadge = d.security_status === "ALERT" 
          ? '<span class="badge badge-alert">ALERT</span>'
          : d.security_status === "SECURE"
          ? '<span class="badge badge-secure">SECURE</span>'
          : '<span class="badge bg-secondary">IDLE</span>';
        
        const row = document.createElement("tr");
        row.innerHTML = `
          <td><strong>${d.name}</strong></td>
          <td><span class="badge badge-mono badge-pseudonym">${d.pseudonym || 'UNASSIGNED'}</span></td>
          <td><code class="mono-addr">${d.current_ipv6}</code></td>
          <td><span class="badge bg-light text-dark border">${d.ndp_message_rate || 0.0} pps</span></td>
          <td>${statusBadge}</td>
        `;
        tbody.appendChild(row);
      });
    }
  }
}

window.AppState = AppState;

