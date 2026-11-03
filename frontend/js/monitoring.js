/**
 * monitoring.js - Network Monitoring & Deep Packet Inspection (Scapy)
 * PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
 */

const MonitoringModule = {
  chart: null,

  init() {
    this.initChart();
  },

  initChart() {
    const ctx = document.getElementById("icmpDoughnutChart");
    if (ctx && window.Chart) {
      this.chart = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels: ["RA (134)", "RS (133)", "NS (135)", "NA (136)", "Echo Ping"],
          datasets: [{
            data: [1, 1, 1, 1, 1],
            backgroundColor: ["#0284c7", "#38bdf8", "#f59e0b", "#10b981", "#94a3b8"],
            borderWidth: 2,
            borderColor: "#ffffff"
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } }
          },
          cutout: "65%"
        }
      });
    }
  },

  async update(tenantId) {
    try {
      const res = await fetch(`/api/traffic?tenant_id=${tenantId}&limit=35`);
      const data = await res.json();
      if (data.status === "SUCCESS") {
        this.renderTelemetry(data.telemetry);
        this.renderPacketStream(data.data);
      }
    } catch (err) {
      console.error("Error fetching network traffic:", err);
    }
  },

  renderTelemetry(telemetry) {
    if (!telemetry) return;

    const counts = telemetry.type_distribution || {};
    document.getElementById("counter-ra").innerText = counts.RA || 0;
    document.getElementById("counter-rs").innerText = counts.RS || 0;
    document.getElementById("counter-ns").innerText = counts.NS || 0;
    document.getElementById("counter-na").innerText = counts.NA || 0;

    const totalBadge = document.getElementById("packet-total-badge");
    if (totalBadge) {
      totalBadge.innerText = `Total Packets: ${telemetry.total_packets_processed || 0}`;
    }

    if (this.chart) {
      this.chart.data.datasets[0].data = [
        counts.RA || 0,
        counts.RS || 0,
        counts.NS || 0,
        counts.NA || 0,
        counts.ECHO || 0
      ];
      this.chart.update("none");
    }
  },

  renderPacketStream(packets) {
    const tbody = document.getElementById("packet-stream-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!packets || packets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">Waiting for incoming ICMPv6 packets...</td></tr>`;
      return;
    }

    packets.forEach(p => {
      const timeStr = new Date(p.timestamp * 1000).toLocaleTimeString() + '.' + String(Math.floor((p.timestamp % 1) * 1000)).padStart(3, '0');
      const attackBadge = p.is_attack 
        ? '<span class="badge bg-danger">ATTACK</span>' 
        : '<span class="badge bg-light text-secondary border">NORMAL</span>';

      let typeBadge = '<span class="badge bg-secondary">OTHER</span>';
      if (p.icmpv6_type === 134) typeBadge = '<span class="badge bg-primary">RA (134)</span>';
      else if (p.icmpv6_type === 133) typeBadge = '<span class="badge bg-info text-dark">RS (133)</span>';
      else if (p.icmpv6_type === 135) typeBadge = '<span class="badge bg-warning text-dark">NS (135)</span>';
      else if (p.icmpv6_type === 136) typeBadge = '<span class="badge bg-success">NA (136)</span>';
      else if (p.icmpv6_type === 128 || p.icmpv6_type === 129) typeBadge = '<span class="badge bg-secondary">ECHO</span>';

      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="font-monospace text-muted small">${timeStr}</td>
        <td><code class="mono-addr ${p.is_attack ? 'text-danger fw-bold' : ''}">${p.src_ipv6}</code></td>
        <td><code class="mono-addr">${p.dst_ipv6}</code></td>
        <td>${typeBadge}</td>
        <td><span class="badge badge-mono badge-pseudonym">${p.pseudonym || 'N/A'}</span></td>
        <td class="font-monospace small text-muted">${p.length} B</td>
        <td>${attackBadge}</td>
      `;
      tbody.appendChild(row);
    });
  }
};

document.addEventListener("DOMContentLoaded", () => {
  MonitoringModule.init();
});

window.MonitoringModule = MonitoringModule;

