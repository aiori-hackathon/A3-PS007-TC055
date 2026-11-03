/**
 * devices.js - IoT Device Management & Address Rotation Controller
 * PS-007: Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation
 */

const DevicesModule = {
  latestDevices: [],
  latestRotations: [],

  init() {
    this.bindButtons();
  },

  bindButtons() {
    const btnAuthAll = document.getElementById("btn-auth-all-devices");
    if (btnAuthAll) {
      btnAuthAll.addEventListener("click", async () => {
        btnAuthAll.disabled = true;
        btnAuthAll.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Authenticating...';
        try {
          await fetch("/api/simulation/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: "devices" })
          });
          setTimeout(() => {
            DevicesModule.update(window.AppState.currentTenant);
            btnAuthAll.disabled = false;
            btnAuthAll.innerHTML = '<i class="bi bi-key-fill"></i> Authenticate All 5';
          }, 800);
        } catch (e) {
          btnAuthAll.disabled = false;
        }
      });
    }

    const btnRotateAll = document.getElementById("btn-rotate-all-devices");
    if (btnRotateAll) {
      btnRotateAll.addEventListener("click", async () => {
        btnRotateAll.disabled = true;
        btnRotateAll.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Rotating...';
        for (const dev of DevicesModule.latestDevices) {
          try {
            await fetch("/api/devices/rotate", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ device_id: dev.id, tenant_id: window.AppState.currentTenant })
            });
          } catch (e) {}
        }
        setTimeout(() => {
          DevicesModule.update(window.AppState.currentTenant);
          btnRotateAll.disabled = false;
          btnRotateAll.innerHTML = '<i class="bi bi-arrow-repeat"></i> Rotate All Addresses';
        }, 600);
      });
    }
  },

  async update(tenantId) {
    await this.fetchDevices(tenantId);
    await this.fetchRotations(tenantId);
  },

  async fetchDevices(tenantId) {
    try {
      const res = await fetch(`/api/devices?tenant_id=${tenantId}`);
      const data = await res.json();
      if (data.status === "SUCCESS") {
        this.latestDevices = data.data;
        this.renderFullDevicesTable(this.latestDevices);
        this.renderRotationDevicesTable(this.latestDevices);
      }
    } catch (err) {
      console.error("Error fetching devices:", err);
    }
  },

  async fetchRotations(tenantId) {
    try {
      const res = await fetch(`/api/rotations?tenant_id=${tenantId}&limit=20`);
      const data = await res.json();
      if (data.status === "SUCCESS") {
        this.latestRotations = data.data;
        this.renderRotationsTable(this.latestRotations);
      }
    } catch (err) {
      console.error("Error fetching rotations:", err);
    }
  },

  renderFullDevicesTable(devices) {
    const tbody = document.getElementById("full-devices-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    devices.forEach(d => {
      const statusBadge = d.security_status === "ALERT" 
        ? '<span class="badge badge-alert">ANOMALY ALERT</span>'
        : d.security_status === "SECURE"
        ? '<span class="badge badge-secure">AUTHENTICATED</span>'
        : '<span class="badge bg-secondary">IDLE</span>';

      const row = document.createElement("tr");
      row.innerHTML = `
        <td><strong>${d.name}</strong></td>
        <td><span class="text-muted small">${d.device_type}</span></td>
        <td><span class="badge badge-mono badge-pseudonym">${d.pseudonym || 'UNASSIGNED'}</span></td>
        <td><code class="mono-addr">${d.current_ipv6}</code></td>
        <td><span class="badge bg-light text-dark border">${d.status}</span></td>
        <td><span class="fw-bold font-monospace">${d.rotation_count}</span></td>
        <td><span class="badge bg-light text-dark border font-monospace">${d.ndp_message_rate || 0.0} pps</span></td>
        <td>${statusBadge}</td>
        <td class="text-end">
          <button class="btn btn-sm btn-outline-custom btn-rotate-single" data-id="${d.id}" title="Rotate IPv6 Address">
            <i class="bi bi-arrow-repeat"></i> Rotate
          </button>
          <button class="btn btn-sm btn-primary-custom ms-1 btn-auth-single" data-id="${d.id}" title="Re-authenticate">
            <i class="bi bi-key"></i> Re-auth
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });

    // Attach single rotation listeners
    tbody.querySelectorAll(".btn-rotate-single").forEach(b => {
      b.addEventListener("click", () => this.rotateSingleDevice(b.getAttribute("data-id")));
    });
    tbody.querySelectorAll(".btn-auth-single").forEach(b => {
      b.addEventListener("click", () => this.authSingleDevice(b.getAttribute("data-id")));
    });
  },

  renderRotationDevicesTable(devices) {
    const tbody = document.getElementById("rotation-devices-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    devices.forEach(d => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td><strong>${d.name}</strong></td>
        <td><span class="badge badge-mono badge-pseudonym">${d.pseudonym || 'UNASSIGNED'}</span></td>
        <td><code class="mono-addr">${d.current_ipv6}</code></td>
        <td><span class="badge bg-light text-dark border font-monospace">${d.rotation_count} rotations</span></td>
        <td><span class="badge badge-secure">ACTIVE SESSION</span></td>
        <td class="text-end">
          <button class="btn btn-sm btn-primary-custom btn-rotate-manual" data-id="${d.id}">
            <i class="bi bi-arrow-repeat"></i> Rotate Address Now
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });

    tbody.querySelectorAll(".btn-rotate-manual").forEach(b => {
      b.addEventListener("click", () => this.rotateSingleDevice(b.getAttribute("data-id")));
    });
  },

  renderRotationsTable(rotations) {
    const tbody = document.getElementById("rotations-history-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (rotations.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No rotation events logged yet. Click 'Rotate' above to trigger RFC 4941 address change.</td></tr>`;
      return;
    }

    rotations.forEach(r => {
      const dateStr = new Date(r.rotated_at * 1000).toLocaleTimeString();
      const row = document.createElement("tr");
      row.innerHTML = `
        <td class="text-muted font-monospace small">${dateStr}</td>
        <td><strong>${r.device_name}</strong></td>
        <td><span class="badge badge-mono badge-pseudonym">${r.pseudonym}</span></td>
        <td><code class="mono-addr text-secondary">${r.old_ipv6}</code></td>
        <td><code class="mono-addr text-primary">${r.new_ipv6}</code></td>
        <td><span class="badge badge-secure">${r.status}</span></td>
      `;
      tbody.appendChild(row);
    });
  },

  async rotateSingleDevice(deviceId) {
    try {
      const res = await fetch("/api/devices/rotate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, tenant_id: window.AppState.currentTenant })
      });
      const data = await res.json();
      if (data.status === "SUCCESS") {
        await this.update(window.AppState.currentTenant);
      }
    } catch (e) {
      console.error("Rotate error:", e);
    }
  },

  async authSingleDevice(deviceId) {
    try {
      const res = await fetch("/api/devices/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, tenant_id: window.AppState.currentTenant })
      });
      const data = await res.json();
      if (data.status === "SUCCESS") {
        await this.update(window.AppState.currentTenant);
      }
    } catch (e) {
      console.error("Auth error:", e);
    }
  }
};

document.addEventListener("DOMContentLoaded", () => {
  DevicesModule.init();
});

window.DevicesModule = DevicesModule;

