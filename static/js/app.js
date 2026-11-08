/* Issue #6.1: dashboard API client, JWT session, and scan polling. */
(function () {
  "use strict";

  const TOKEN_KEY = "dacn_jwt";
  const TERMINAL_STATUSES = new Set(["COMPLETED", "FAILED", "CANCELLED", "NO_MODULES"]);
  const POLL_INTERVAL_MS = 3000;
  let dashboardTimer = null;
  let detailTimer = null;
  let dashboardBusy = false;
  let detailBusy = false;
  let activeDetailId = null;

  function getToken() {
    return window.localStorage.getItem(TOKEN_KEY);
  }

  function showMessage(message, type) {
    const alert = document.getElementById("app-alert");
    if (!alert) return;
    alert.textContent = message;
    alert.className = "alert alert-" + (type || "danger");
    alert.classList.remove("d-none");
    window.clearTimeout(showMessage.timeout);
    showMessage.timeout = window.setTimeout(function () { alert.classList.add("d-none"); }, 7000);
  }

  async function apiRequest(path, options) {
    const requestOptions = Object.assign({ method: "GET", headers: {} }, options || {});
    requestOptions.headers = Object.assign({ Accept: "application/json" }, requestOptions.headers || {});
    const token = getToken();
    if (token) requestOptions.headers.Authorization = "Bearer " + token;
    if (requestOptions.body && typeof requestOptions.body !== "string") {
      requestOptions.headers["Content-Type"] = "application/json";
      requestOptions.body = JSON.stringify(requestOptions.body);
    }

    let response;
    try {
      response = await fetch(path, requestOptions);
    } catch (error) {
      throw new Error("Không thể kết nối API. Hãy kiểm tra máy chủ và thử lại.");
    }
    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      if (response.ok) throw new Error("API trả về dữ liệu không hợp lệ.");
    }
    if (response.status === 401 && token) {
      logout(false);
    }
    if (!response.ok) {
      const message = data && (data.message || data.error);
      throw new Error(message || ("Yêu cầu thất bại (HTTP " + response.status + ")."));
    }
    return data;
  }

  function logout(showNotice) {
    window.localStorage.removeItem(TOKEN_KEY);
    if (dashboardTimer) window.clearInterval(dashboardTimer);
    if (detailTimer) window.clearInterval(detailTimer);
    dashboardTimer = null;
    detailTimer = null;
    updateAuthState();
    if (showNotice) showMessage("Bạn đã đăng xuất.", "success");
  }

  function updateAuthState() {
    const authenticated = Boolean(getToken());
    const authPanel = document.getElementById("auth-panel");
    const dashboard = document.getElementById("dashboard-content");
    const logoutButton = document.getElementById("logout-button");
    const currentUser = document.getElementById("current-user");
    if (authPanel) authPanel.classList.toggle("d-none", authenticated);
    if (dashboard) dashboard.classList.toggle("d-none", !authenticated);
    if (logoutButton) logoutButton.classList.toggle("d-none", !authenticated);
    if (currentUser) currentUser.textContent = authenticated ? "Đã đăng nhập" : "";

    if (authenticated && dashboard && !dashboardTimer) {
      loadScans();
      dashboardTimer = window.setInterval(loadScans, 7000);
    }
    if (!authenticated && dashboardTimer) {
      window.clearInterval(dashboardTimer);
      dashboardTimer = null;
    }
  }

  async function checkHealth() {
    const indicator = document.getElementById("api-health");
    if (!indicator) return;
    try {
      await apiRequest("/api/health");
      const dot = document.createElement("span");
      dot.className = "health-dot health-dot-online";
      dot.setAttribute("aria-hidden", "true");
      indicator.replaceChildren(dot, document.createTextNode(" API đang hoạt động"));
      indicator.classList.add("health-online");
    } catch (error) {
      indicator.textContent = "API chưa kết nối";
      indicator.classList.remove("health-online");
    }
  }

  function normalizeScans(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.scans)) return data.scans;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  function displayDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("vi-VN");
  }

  function statusLabel(status) {
    const labels = {
      PENDING: "Chờ xử lý",
      RUNNING: "Đang chạy",
      CRAWLING: "Đang crawl",
      SCANNING: "Đang quét",
      COMPLETED: "Hoàn tất",
      FAILED: "Thất bại",
      CANCELLED: "Đã hủy",
      NO_MODULES: "Không có module"
    };
    const normalized = String(status || "PENDING").toUpperCase();
    return labels[normalized] || normalized;
  }

  function statusClass(status) {
    const normalized = String(status || "PENDING").toLowerCase();
    return "status-" + (["pending", "running", "crawling", "scanning", "completed", "failed", "cancelled", "no_modules"].includes(normalized) ? normalized : "pending");
  }

  function createCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = value == null || value === "" ? "—" : String(value);
    row.appendChild(cell);
    return cell;
  }

  function renderScanList(scans) {
    const body = document.getElementById("scan-list");
    const count = document.getElementById("scan-count");
    if (!body) return;
    body.replaceChildren();
    if (count) count.textContent = scans.length + " phiên";
    if (!scans.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 6;
      cell.className = "text-center text-secondary py-4";
      cell.textContent = "Chưa có phiên quét. Tạo tác vụ lab đầu tiên ở biểu mẫu bên cạnh.";
      return;
    }

    scans.forEach(function (scan) {
      const sessionId = scan.id || scan.session_id;
      const row = body.insertRow();
      createCell(row, "#" + (sessionId == null ? "—" : sessionId));
      createCell(row, scan.target_url || scan.url || ("Mục tiêu #" + scan.target_id), "target-cell");

      const statusCell = row.insertCell();
      const badge = document.createElement("span");
      badge.className = "status-badge " + statusClass(scan.status);
      badge.textContent = statusLabel(scan.status);
      statusCell.appendChild(badge);

      const progressCell = row.insertCell();
      progressCell.className = "progress-column";
      const progress = document.createElement("div");
      progress.className = "mini-progress";
      progress.setAttribute("role", "progressbar");
      const percent = Math.max(0, Math.min(100, Number(scan.progress) || 0));
      progress.setAttribute("aria-valuenow", String(percent));
      progress.setAttribute("aria-valuemin", "0");
      progress.setAttribute("aria-valuemax", "100");
      const bar = document.createElement("span");
      bar.style.width = percent + "%";
      progress.appendChild(bar);
      const progressLabel = document.createElement("span");
      progressLabel.className = "mini-progress-label";
      progressLabel.textContent = percent + "%";
      progressCell.append(progress, progressLabel);

      createCell(row, displayDate(scan.created_at || scan.start_time));
      const actionCell = row.insertCell();
      const link = document.createElement("a");
      link.className = "btn btn-sm btn-outline-primary";
      link.href = "/scans/" + encodeURIComponent(String(sessionId));
      link.textContent = "Chi tiết";
      link.setAttribute("aria-label", "Xem chi tiết phiên " + sessionId);
      actionCell.appendChild(link);
    });
  }

  async function loadScans() {
    if (dashboardBusy || !getToken()) return;
    dashboardBusy = true;
    try {
      const data = await apiRequest("/api/scans");
      const scans = normalizeScans(data);
      renderScanList(scans);
      if (window.DACNCharts) window.DACNCharts.renderOverview(scans);
    } catch (error) {
      showMessage(error.message);
    } finally {
      dashboardBusy = false;
    }
  }

  function isLoopbackTarget(value) {
    let parsed;
    try {
      parsed = new URL(value);
    } catch (error) {
      return false;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "[::1]" || hostname === "::1") {
      return true;
    }
    const ipv4 = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return Boolean(ipv4 && Number(ipv4[1]) === 127 && ipv4.slice(1).every(function (part) {
      return Number(part) >= 0 && Number(part) <= 255;
    }));
  }

  async function submitScan(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const url = form.elements.url.value.trim();
    if (!isLoopbackTarget(url)) {
      showMessage("Chỉ chấp nhận URL HTTP(S) trên localhost hoặc địa chỉ loopback.");
      return;
    }
    const modules = Array.from(form.querySelectorAll('input[name="modules"]:checked')).map(function (input) {
      return input.value;
    });
    if (!modules.length) {
      showMessage("Hãy chọn ít nhất một module kiểm tra.");
      return;
    }

    const button = document.getElementById("start-scan-button");
    const spinner = button && button.querySelector(".spinner-border");
    if (button) button.disabled = true;
    if (spinner) spinner.classList.remove("d-none");
    try {
      const result = await apiRequest("/api/scans", {
        method: "POST",
        body: { url: url, max_depth: Number(form.elements.max_depth.value), modules: modules }
      });
      showMessage("Đã đưa phiên #" + (result.session_id || result.id) + " vào hàng đợi.", "success");
      form.elements.url.value = "";
      await loadScans();
    } catch (error) {
      showMessage(error.message);
    } finally {
      if (button) button.disabled = false;
      if (spinner) spinner.classList.add("d-none");
    }
  }

  function normalizeScan(data) {
    if (data && data.scan && typeof data.scan === "object") return data.scan;
    if (data && data.session && typeof data.session === "object") return data.session;
    return data || {};
  }

  function normalizeFindings(data) {
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.findings)) return data.findings;
    if (data && data.data && Array.isArray(data.data)) return data.data;
    return [];
  }

  function renderScanDetails(scan) {
    const target = document.getElementById("detail-target");
    const status = document.getElementById("detail-status");
    const progressBar = document.getElementById("detail-progress");
    const progressLabel = document.getElementById("detail-progress-label");
    const progressContainer = document.querySelector(".progress-tall");
    const depth = document.getElementById("detail-depth");
    const modules = document.getElementById("detail-modules");
    const summary = scan.summary || scan.summary_stats || {};
    const progress = Math.max(0, Math.min(100, Number(scan.progress) || 0));
    const normalizedStatus = String(scan.status || "PENDING").toUpperCase();
    if (target) target.textContent = scan.target_url || scan.url || ("Mục tiêu #" + (scan.target_id || "—"));
    if (status) {
      status.textContent = statusLabel(normalizedStatus);
      status.className = "status-badge " + statusClass(normalizedStatus);
    }
    if (progressBar) {
      progressBar.style.width = progress + "%";
      progressBar.classList.toggle("progress-bar-animated", !TERMINAL_STATUSES.has(normalizedStatus));
    }
    if (progressLabel) progressLabel.textContent = progress + "%";
    if (progressContainer) progressContainer.setAttribute("aria-valuenow", String(progress));
    if (depth) depth.textContent = "Độ sâu: " + (scan.max_depth == null ? "—" : scan.max_depth);
    if (modules) {
      const selectedModules = scan.modules_enabled || scan.modules || [];
      modules.textContent = "Module: " + (Array.isArray(selectedModules) && selectedModules.length ? selectedModules.join(", ") : "—");
    }
    const findingsCount = document.getElementById("detail-findings-count");
    if (findingsCount) findingsCount.textContent = "Phát hiện: " + (summary.total_findings == null ? "—" : summary.total_findings);
    const error = document.getElementById("detail-error");
    if (error) {
      error.textContent = scan.error_message || "";
      error.classList.toggle("d-none", !scan.error_message);
    }
    return TERMINAL_STATUSES.has(normalizedStatus);
  }

  function renderFindingsTable(findings) {
    const body = document.getElementById("findings-list");
    const table = document.getElementById("findings-table");
    const empty = document.getElementById("findings-empty");
    const countBadge = document.getElementById("findings-count-badge");
    if (!body || !table || !empty) return;
    body.replaceChildren();
    if (countBadge) countBadge.textContent = findings.length + " phát hiện";
    if (!findings.length) {
      table.classList.add("d-none");
      empty.classList.remove("d-none");
      empty.textContent = "Chưa ghi nhận findings cho phiên quét này.";
      return;
    }
    empty.classList.add("d-none");
    table.classList.remove("d-none");
    findings.forEach(function (finding) {
      const row = body.insertRow();
      const severityCell = row.insertCell();
      const severity = String(finding.severity || "INFO").toUpperCase();
      const severityBadge = document.createElement("span");
      severityBadge.className = "severity-badge severity-" + severity.toLowerCase();
      severityBadge.textContent = severity;
      severityCell.appendChild(severityBadge);
      createCell(row, finding.vuln_name || finding.vuln_type || "Không xác định");
      createCell(row, finding.target_url || finding.url, "url-cell");
      createCell(row, finding.parameter || finding.param);
      createCell(row, finding.evidence, "evidence-cell");
      createCell(row, finding.remediation, "evidence-cell");
    });
  }

  async function loadScanDetail() {
    if (detailBusy || !getToken() || activeDetailId === null) return;
    detailBusy = true;
    try {
      const [scanData, findingData] = await Promise.all([
        apiRequest("/api/scans/" + encodeURIComponent(activeDetailId)),
        apiRequest("/api/scans/" + encodeURIComponent(activeDetailId) + "/findings")
      ]);
      const scan = normalizeScan(scanData);
      const findings = normalizeFindings(findingData);
      const complete = renderScanDetails(scan);
      renderFindingsTable(findings);
      if (window.DACNCharts) window.DACNCharts.renderFindings(findings);
      if (complete && detailTimer) {
        window.clearInterval(detailTimer);
        detailTimer = null;
      }
    } catch (error) {
      showMessage(error.message);
    } finally {
      detailBusy = false;
    }
  }

  function init() {
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const form = event.currentTarget;
        try {
          const result = await apiRequest("/api/auth/login", {
            method: "POST",
            body: { username: form.elements.username.value.trim(), password: form.elements.password.value }
          });
          const token = result.token || result.access_token;
          if (!token) throw new Error("API đăng nhập không trả về JWT.");
          window.localStorage.setItem(TOKEN_KEY, token);
          updateAuthState();
          showMessage("Đăng nhập thành công.", "success");
        } catch (error) {
          showMessage(error.message);
        }
      });
    }

    const registerForm = document.getElementById("register-form");
    if (registerForm) {
      registerForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        const form = event.currentTarget;
        try {
          await apiRequest("/api/auth/register", {
            method: "POST",
            body: {
              username: form.elements.username.value.trim(),
              email: form.elements.email.value.trim(),
              password: form.elements.password.value
            }
          });
          form.reset();
          const loginTab = document.getElementById("login-tab");
          if (loginTab && window.bootstrap) window.bootstrap.Tab.getOrCreateInstance(loginTab).show();
          showMessage("Tạo tài khoản thành công. Hãy đăng nhập.", "success");
        } catch (error) {
          showMessage(error.message);
        }
      });
    }

    const scanForm = document.getElementById("scan-form");
    if (scanForm) scanForm.addEventListener("submit", submitScan);
    const refresh = document.getElementById("refresh-scans");
    if (refresh) refresh.addEventListener("click", loadScans);
    const logoutButton = document.getElementById("logout-button");
    if (logoutButton) logoutButton.addEventListener("click", function () { logout(true); });

    const detailPage = document.getElementById("scan-detail-page");
    if (detailPage) {
      activeDetailId = detailPage.dataset.sessionId;
      if (getToken()) {
        loadScanDetail();
        detailTimer = window.setInterval(loadScanDetail, POLL_INTERVAL_MS);
      } else {
        const empty = document.getElementById("findings-empty");
        if (empty) empty.textContent = "Đăng nhập từ trang tổng quan để xem phiên quét này.";
        window.setTimeout(function () { window.location.assign("/"); }, 1200);
      }
    }
    checkHealth();
    updateAuthState();
  }

  document.addEventListener("DOMContentLoaded", init);
}());