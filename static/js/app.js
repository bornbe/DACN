<<<<<<< Updated upstream
=======
/**
 * Frontend logic cho OWASP Web Scanner Dashboard & Scan Detail - Issue #6.1/#6.2.
 *
 * Nguyên tắc bảo mật:
 * 1. Lưu JWT trong sessionStorage, gửi qua header `Authorization: Bearer <token>`.
 *    Tuyệt đối không đưa JWT vào URL query string hoặc nhật ký trình duyệt.
 * 2. Không chèn dữ liệu người dùng/finding qua innerHTML khi chưa escape;
 *    luôn tạo phần tử DOM và gán textContent để chống DOM-based XSS.
 */
(function (global) {
  "use strict";

  const TOKEN_STORAGE_KEY = "owasp_scanner_jwt";
  const USER_STORAGE_KEY = "owasp_scanner_user";
  const POLL_INTERVAL_MS = 2000;

  const ACTIVE_STATUSES = new Set(["PENDING", "RUNNING", "CRAWLING", "SCANNING"]);
  const FINISHED_STATUSES = new Set(["COMPLETED", "FAILED", "CANCELLED", "NO_MODULES"]);
  const SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  let dashboardPollTimer = null;
  let detailPollTimer = null;
  let currentDetailFindings = [];

  function escapeHtml(value) {
    const str = value === null || value === undefined ? "" : String(value);
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function getToken() {
    try {
      return global.sessionStorage.getItem(TOKEN_STORAGE_KEY) || "";
    } catch (_err) {
      return "";
    }
  }

  function getStoredUser() {
    try {
      const raw = global.sessionStorage.getItem(USER_STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_err) {
      return null;
    }
  }

  function setSession(token, user) {
    try {
      global.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
      if (user) {
        global.sessionStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
      }
    } catch (_err) {
      // Bỏ qua nếu trình duyệt chặn storage
    }
    updateNavbarAuth();
  }

  function clearSession() {
    try {
      global.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      global.sessionStorage.removeItem(USER_STORAGE_KEY);
    } catch (_err) {
      // Bỏ qua
    }
    stopAllPolling();
    updateNavbarAuth();
  }

  function stopAllPolling() {
    if (dashboardPollTimer !== null) {
      global.clearInterval(dashboardPollTimer);
      dashboardPollTimer = null;
    }
    if (detailPollTimer !== null) {
      global.clearInterval(detailPollTimer);
      detailPollTimer = null;
    }
  }

  function showAlert(elementId, message, level) {
    const el = document.getElementById(elementId);
    if (!el) {
      return;
    }
    el.className = "alert alert-" + (level || "danger");
    el.textContent = message;
  }

  function hideAlert(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
      el.className = "alert d-none";
      el.textContent = "";
    }
  }

  function updateNavbarAuth() {
    const badge = document.getElementById("navUserBadge");
    const logoutBtn = document.getElementById("navLogoutBtn");
    const token = getToken();
    const user = getStoredUser();

    if (badge) {
      if (token && user && user.username) {
        badge.textContent = user.username + " (" + (user.role || "pentester") + ")";
        badge.classList.remove("d-none");
      } else {
        badge.textContent = "";
        badge.classList.add("d-none");
      }
    }
    if (logoutBtn) {
      if (token) {
        logoutBtn.classList.remove("d-none");
      } else {
        logoutBtn.classList.add("d-none");
      }
    }
  }

  async function apiFetch(path, options) {
    const opts = Object.assign({}, options || {});
    const headers = Object.assign({}, opts.headers || {});
    const token = getToken();
    if (token) {
      headers["Authorization"] = "Bearer " + token;
    }
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    opts.headers = headers;
    return global.fetch(path, opts);
  }

  async function downloadReportFile(sessionId, format, alertElementId) {
    const fmt = String(format || "").toLowerCase();
    if (fmt !== "txt" && fmt !== "pdf") {
      showAlert(alertElementId || "globalAlertBox", "Định dạng báo cáo chỉ hỗ trợ TXT hoặc PDF.", "warning");
      return;
    }
    try {
      const response = await apiFetch(
        "/api/scans/" + encodeURIComponent(sessionId) + "/report?format=" + encodeURIComponent(fmt),
        { method: "GET" }
      );
      if (response.status === 401) {
        clearSession();
        showAlert(alertElementId || "globalAlertBox", "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.", "warning");
        return;
      }
      if (!response.ok) {
        let errMessage = "Không thể tải báo cáo (HTTP " + response.status + ").";
        try {
          const errJson = await response.json();
          if (errJson && errJson.message) {
            errMessage = errJson.message;
          }
        } catch (_e) {
          // Giữ thông báo mặc định
        }
        showAlert(alertElementId || "globalAlertBox", errMessage, "danger");
        return;
      }
      const blob = await response.blob();
      const objectUrl = global.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = "scan-report-" + sessionId + "." + fmt;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      global.setTimeout(function () {
        global.URL.revokeObjectURL(objectUrl);
      }, 1000);
    } catch (_err) {
      showAlert(alertElementId || "globalAlertBox", "Lỗi kết nối mạng khi tải báo cáo.", "danger");
    }
  }

  function formatDateTime(isoString) {
    if (!isoString) {
      return "-";
    }
    try {
      const d = new Date(isoString);
      if (Number.isNaN(d.getTime())) {
        return String(isoString);
      }
      return d.toLocaleString("vi-VN");
    } catch (_err) {
      return String(isoString);
    }
  }

  function createStatusBadge(status) {
    const normalized = String(status || "PENDING").toUpperCase();
    const span = document.createElement("span");
    span.className = "badge status-badge-" + normalized.toLowerCase();
    span.textContent = normalized;
    return span;
  }

  function createSeverityBadge(severity) {
    const normalized = String(severity || "INFO").toUpperCase();
    const span = document.createElement("span");
    span.className = "badge severity-badge-" + normalized.toLowerCase();
    span.textContent = normalized;
    return span;
  }

  /* ======================================================================
   * DASHBOARD VIEW
   * ====================================================================== */
  function toggleDashboardAuthView(isAuthenticated) {
    const authSection = document.getElementById("authSection");
    const dashboardContent = document.getElementById("dashboardContent");
    if (!authSection || !dashboardContent) {
      return;
    }
    if (isAuthenticated) {
      authSection.classList.add("d-none");
      dashboardContent.classList.remove("d-none");
    } else {
      authSection.classList.remove("d-none");
      dashboardContent.classList.add("d-none");
    }
  }

  function renderDashboardStatsAndChart(scans) {
    const list = Array.isArray(scans) ? scans : [];
    let activeCount = 0;
    let completedCount = 0;
    let totalFindings = 0;
    const aggSeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

    list.forEach(function (scan) {
      const status = String(scan.status || "").toUpperCase();
      if (ACTIVE_STATUSES.has(status)) {
        activeCount += 1;
      }
      if (status === "COMPLETED") {
        completedCount += 1;
      }
      const stats = scan.summary_stats && typeof scan.summary_stats === "object" ? scan.summary_stats : {};
      const counts = stats.severity_counts && typeof stats.severity_counts === "object" ? stats.severity_counts : {};
      SEVERITY_KEYS.forEach(function (key) {
        const val = Number(counts[key] || 0);
        if (Number.isFinite(val) && val > 0) {
          aggSeverity[key] += val;
          totalFindings += val;
        }
      });
    });

    const setText = function (id, val) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = String(val);
      }
    };
    setText("statTotalScans", list.length);
    setText("statActiveScans", activeCount);
    setText("statCompletedScans", completedCount);
    setText("statTotalFindings", totalFindings);

    setText("cntCritical", aggSeverity.CRITICAL);
    setText("cntHigh", aggSeverity.HIGH);
    setText("cntMedium", aggSeverity.MEDIUM);
    setText("cntLow", aggSeverity.LOW);
    setText("cntInfo", aggSeverity.INFO);

    if (global.ScannerCharts) {
      global.ScannerCharts.renderSeverityChart("severityChart", aggSeverity);
    }
  }

  function renderScansTable(scans) {
    const tbody = document.getElementById("scansTableBody");
    if (!tbody) {
      return;
    }
    tbody.textContent = "";
    const list = Array.isArray(scans) ? scans : [];
    if (list.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 8;
      td.className = "text-center text-muted py-4";
      td.textContent = "Chưa có phiên quét nào. Hãy tạo phiên quét đầu tiên ở biểu mẫu phía trên.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    list.forEach(function (scan) {
      const tr = document.createElement("tr");

      // 1. ID
      const tdId = document.createElement("td");
      tdId.className = "fw-bold";
      tdId.textContent = "#" + scan.id;
      tr.appendChild(tdId);

      // 2. Target URL
      const tdUrl = document.createElement("td");
      const codeUrl = document.createElement("code");
      codeUrl.textContent = scan.target_url || "-";
      tdUrl.appendChild(codeUrl);
      tr.appendChild(tdUrl);

      // 3. Modules & Depth
      const tdMod = document.createElement("td");
      tdMod.className = "small";
      const mods = Array.isArray(scan.modules_enabled) ? scan.modules_enabled.join(", ") : "-";
      tdMod.textContent = mods + " (depth=" + (scan.max_depth ?? 2) + ")";
      tr.appendChild(tdMod);

      // 4. Status
      const tdStatus = document.createElement("td");
      tdStatus.appendChild(createStatusBadge(scan.status));
      tr.appendChild(tdStatus);

      // 5. Progress bar
      const tdProgress = document.createElement("td");
      const pct = Math.min(Math.max(Number(scan.progress || 0), 0), 100);
      const progressWrap = document.createElement("div");
      progressWrap.className = "progress";
      progressWrap.style.height = "18px";
      const progressBar = document.createElement("div");
      progressBar.className =
        "progress-bar" + (ACTIVE_STATUSES.has(String(scan.status || "").toUpperCase()) ? " progress-bar-striped progress-bar-animated" : "");
      progressBar.style.width = pct + "%";
      progressBar.setAttribute("role", "progressbar");
      progressBar.setAttribute("aria-valuenow", String(pct));
      progressBar.setAttribute("aria-valuemin", "0");
      progressBar.setAttribute("aria-valuemax", "100");
      progressBar.textContent = pct + "%";
      progressWrap.appendChild(progressBar);
      tdProgress.appendChild(progressWrap);
      tr.appendChild(tdProgress);

      // 6. Time
      const tdTime = document.createElement("td");
      tdTime.className = "small text-muted";
      tdTime.textContent = formatDateTime(scan.start_time);
      tr.appendChild(tdTime);

      // 7. Severity summary
      const tdSev = document.createElement("td");
      const counts =
        scan.summary_stats && scan.summary_stats.severity_counts ? scan.summary_stats.severity_counts : {};
      let hasAnyFinding = false;
      SEVERITY_KEYS.forEach(function (sev) {
        const cnt = Number(counts[sev] || 0);
        if (cnt > 0) {
          hasAnyFinding = true;
          const badge = createSeverityBadge(sev);
          badge.textContent = sev + ": " + cnt;
          badge.classList.add("me-1");
          tdSev.appendChild(badge);
        }
      });
      if (!hasAnyFinding) {
        const zeroSpan = document.createElement("span");
        zeroSpan.className = "text-muted small";
        zeroSpan.textContent = "0 phát hiện";
        tdSev.appendChild(zeroSpan);
      }
      tr.appendChild(tdSev);

      // 8. Actions
      const tdActions = document.createElement("td");
      tdActions.className = "text-end";
      const btnGroup = document.createElement("div");
      btnGroup.className = "btn-group btn-group-sm";

      const detailLink = document.createElement("a");
      detailLink.href = "/scans/" + encodeURIComponent(scan.id);
      detailLink.className = "btn btn-outline-primary";
      detailLink.textContent = "Chi tiết";
      btnGroup.appendChild(detailLink);

      const txtBtn = document.createElement("button");
      txtBtn.type = "button";
      txtBtn.className = "btn btn-outline-secondary";
      txtBtn.textContent = "TXT";
      txtBtn.addEventListener("click", function () {
        downloadReportFile(scan.id, "txt", "scanFormAlert");
      });
      btnGroup.appendChild(txtBtn);

      const pdfBtn = document.createElement("button");
      pdfBtn.type = "button";
      pdfBtn.className = "btn btn-outline-dark";
      pdfBtn.textContent = "PDF";
      pdfBtn.addEventListener("click", function () {
        downloadReportFile(scan.id, "pdf", "scanFormAlert");
      });
      btnGroup.appendChild(pdfBtn);

      tdActions.appendChild(btnGroup);
      tr.appendChild(tdActions);

      tbody.appendChild(tr);
    });
  }

  async function loadDashboardScans() {
    if (!getToken()) {
      toggleDashboardAuthView(false);
      stopAllPolling();
      return;
    }
    toggleDashboardAuthView(true);
    try {
      const response = await apiFetch("/api/scans", { method: "GET" });
      if (response.status === 401) {
        clearSession();
        toggleDashboardAuthView(false);
        showAlert("authAlert", "Phiên đăng nhập không hợp lệ hoặc đã hết hạn.", "warning");
        return;
      }
      if (!response.ok) {
        showAlert("scanFormAlert", "Không thể tải danh sách phiên quét (HTTP " + response.status + ").", "danger");
        return;
      }
      const data = await response.json();
      const scans = Array.isArray(data.scans) ? data.scans : [];
      renderDashboardStatsAndChart(scans);
      renderScansTable(scans);

      const hasActive = scans.some(function (s) {
        return ACTIVE_STATUSES.has(String(s.status || "").toUpperCase());
      });
      if (hasActive && dashboardPollTimer === null) {
        dashboardPollTimer = global.setInterval(loadDashboardScans, POLL_INTERVAL_MS);
      } else if (!hasActive && dashboardPollTimer !== null) {
        global.clearInterval(dashboardPollTimer);
        dashboardPollTimer = null;
      }
    } catch (_err) {
      showAlert("scanFormAlert", "Lỗi kết nối tới máy chủ API.", "danger");
    }
  }

  function initDashboardView() {
    const tabLoginBtn = document.getElementById("tabLoginBtn");
    const tabRegisterBtn = document.getElementById("tabRegisterBtn");
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const newScanForm = document.getElementById("newScanForm");
    const refreshBtn = document.getElementById("refreshScansBtn");

    if (tabLoginBtn && tabRegisterBtn && loginForm && registerForm) {
      tabLoginBtn.addEventListener("click", function () {
        tabLoginBtn.className = "btn btn-light active";
        tabRegisterBtn.className = "btn btn-outline-light";
        loginForm.classList.remove("d-none");
        registerForm.classList.add("d-none");
        hideAlert("authAlert");
      });
      tabRegisterBtn.addEventListener("click", function () {
        tabRegisterBtn.className = "btn btn-light active";
        tabLoginBtn.className = "btn btn-outline-light";
        registerForm.classList.remove("d-none");
        loginForm.classList.add("d-none");
        hideAlert("authAlert");
      });
    }

    if (loginForm) {
      loginForm.addEventListener("submit", async function (evt) {
        evt.preventDefault();
        hideAlert("authAlert");
        const username = (document.getElementById("loginUsername").value || "").trim();
        const password = document.getElementById("loginPassword").value || "";
        if (!username || !password) {
          showAlert("authAlert", "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.", "warning");
          return;
        }
        const submitBtn = document.getElementById("loginSubmitBtn");
        if (submitBtn) {
          submitBtn.disabled = true;
        }
        try {
          const resp = await apiFetch("/api/auth/login", {
            method: "POST",
            body: { username: username, password: password },
          });
          const body = await resp.json();
          if (!resp.ok) {
            showAlert("authAlert", (body && body.message) || "Đăng nhập thất bại.", "danger");
            return;
          }
          setSession(body.access_token, body.user);
          loginForm.reset();
          await loadDashboardScans();
        } catch (_err) {
          showAlert("authAlert", "Không thể kết nối tới API đăng nhập.", "danger");
        } finally {
          if (submitBtn) {
            submitBtn.disabled = false;
          }
        }
      });
    }

    if (registerForm) {
      registerForm.addEventListener("submit", async function (evt) {
        evt.preventDefault();
        hideAlert("authAlert");
        const username = (document.getElementById("regUsername").value || "").trim();
        const email = (document.getElementById("regEmail").value || "").trim();
        const password = document.getElementById("regPassword").value || "";
        if (!username || !email || !password) {
          showAlert("authAlert", "Vui lòng điền đầy đủ thông tin đăng ký.", "warning");
          return;
        }
        const submitBtn = document.getElementById("registerSubmitBtn");
        if (submitBtn) {
          submitBtn.disabled = true;
        }
        try {
          const resp = await apiFetch("/api/auth/register", {
            method: "POST",
            body: { username: username, email: email, password: password },
          });
          const body = await resp.json();
          if (!resp.ok) {
            showAlert("authAlert", (body && body.message) || "Đăng ký tài khoản thất bại.", "danger");
            return;
          }
          showAlert("authAlert", "Đăng ký thành công! Vui lòng đăng nhập.", "success");
          registerForm.reset();
          if (tabLoginBtn) {
            tabLoginBtn.click();
          }
        } catch (_err) {
          showAlert("authAlert", "Không thể kết nối tới API đăng ký.", "danger");
        } finally {
          if (submitBtn) {
            submitBtn.disabled = false;
          }
        }
      });
    }

    if (newScanForm) {
      newScanForm.addEventListener("submit", async function (evt) {
        evt.preventDefault();
        hideAlert("scanFormAlert");
        const urlInput = document.getElementById("scanUrlInput");
        const depthInput = document.getElementById("scanDepthInput");
        const checkboxes = document.querySelectorAll(".scan-module-checkbox:checked");
        const createBtn = document.getElementById("createScanBtn");

        const targetUrl = urlInput ? urlInput.value.trim() : "";
        const maxDepth = depthInput ? Number.parseInt(depthInput.value, 10) : 2;
        const modules = Array.from(checkboxes).map(function (cb) {
          return cb.value;
        });

        if (!targetUrl) {
          showAlert("scanFormAlert", "Vui lòng nhập URL mục tiêu hợp lệ (ví dụ http://127.0.0.1:8080).", "warning");
          return;
        }
        if (Number.isNaN(maxDepth) || maxDepth < 0 || maxDepth > 5) {
          showAlert("scanFormAlert", "max_depth phải là số nguyên từ 0 đến 5.", "warning");
          return;
        }
        if (modules.length === 0) {
          showAlert("scanFormAlert", "Vui lòng chọn ít nhất một module quét.", "warning");
          return;
        }

        if (createBtn) {
          createBtn.disabled = true;
          createBtn.textContent = "Đang khởi tạo...";
        }
        try {
          const resp = await apiFetch("/api/scans", {
            method: "POST",
            body: { url: targetUrl, max_depth: maxDepth, modules: modules },
          });
          const data = await resp.json();
          if (!resp.ok) {
            showAlert("scanFormAlert", (data && data.message) || "Không thể tạo phiên quét.", "danger");
            return;
          }
          showAlert(
            "scanFormAlert",
            "Đã tạo phiên quét #" + data.session_id + " (trạng thái: " + data.status + ").",
            "success"
          );
          await loadDashboardScans();
        } catch (_err) {
          showAlert("scanFormAlert", "Lỗi kết nối mạng khi gửi yêu cầu tạo phiên quét.", "danger");
        } finally {
          if (createBtn) {
            createBtn.disabled = false;
            createBtn.textContent = "Bắt đầu quét";
          }
        }
      });
    }

    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        loadDashboardScans();
      });
    }

    loadDashboardScans();
  }

  /* ======================================================================
   * SCAN DETAIL VIEW, CLIENT-SIDE FILTERING & POLLING
   * ====================================================================== */
  function openFindingModal(finding) {
    const modal = document.getElementById("findingDetailModal");
    if (!modal || !finding) {
      return;
    }
    const sev = String(finding.severity || "INFO").toUpperCase();
    const badge = document.getElementById("modalSeverityBadge");
    if (badge) {
      badge.className = "badge me-2 severity-badge-" + sev.toLowerCase();
      badge.textContent = sev;
    }
    const setField = function (id, val) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = val ? String(val) : "-";
      }
    };
    setField("modalVulnTitle", finding.vuln_type || finding.vuln_name || "Vulnerability Finding");
    setField("modalTargetUrl", finding.target_url);
    setField("modalParameter", finding.param || finding.parameter || "-");
    setField(
      "modalCweOwasp",
      (finding.cwe_id || "-") + " / " + (finding.owasp_category || "-")
    );
    setField("modalPayload", finding.payload || "-");
    setField("modalEvidence", finding.evidence || "-");
    setField("modalRemediation", finding.remediation || "-");

    modal.classList.remove("d-none");
  }

  function closeFindingModal() {
    const modal = document.getElementById("findingDetailModal");
    if (modal) {
      modal.classList.add("d-none");
    }
  }

  function filterFindings(findings, severityFilter, keywordFilter) {
    const list = Array.isArray(findings) ? findings.slice() : [];
    const targetSev = String(severityFilter || "ALL").trim().toUpperCase();
    const keyword = String(keywordFilter || "").trim().toLowerCase();

    return list.filter(function (item) {
      if (!item || typeof item !== "object") {
        return false;
      }
      const itemSev = String(item.severity || "INFO").toUpperCase();
      if (targetSev && targetSev !== "ALL" && itemSev !== targetSev) {
        return false;
      }
      if (!keyword) {
        return true;
      }
      const haystack = [
        item.vuln_type,
        item.vuln_name,
        item.target_url,
        item.param,
        item.parameter,
        item.cwe_id,
        item.owasp_category,
        item.evidence,
      ]
        .map(function (v) {
          return v ? String(v).toLowerCase() : "";
        })
        .join(" ");
      return haystack.indexOf(keyword) !== -1;
    });
  }

  function getCurrentDetailFindings() {
    return currentDetailFindings.slice();
  }

  function renderFilteredFindingsTable() {
    const sevSelect = document.getElementById("findingSeverityFilter");
    const kwInput = document.getElementById("findingKeywordFilter");
    const sevValue = sevSelect ? sevSelect.value : "ALL";
    const kwValue = kwInput ? kwInput.value : "";

    const filtered = filterFindings(currentDetailFindings, sevValue, kwValue);
    const countBadge = document.getElementById("findingsCountBadge");
    if (countBadge) {
      if (
        (sevValue && sevValue !== "ALL") ||
        (kwValue && kwValue.trim() !== "")
      ) {
        countBadge.textContent = filtered.length + " / " + currentDetailFindings.length;
      } else {
        countBadge.textContent = String(currentDetailFindings.length);
      }
    }

    const tbody = document.getElementById("findingsTableBody");
    if (!tbody) {
      return filtered;
    }
    tbody.textContent = "";

    if (currentDetailFindings.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 7;
      td.className = "text-center text-muted py-4";
      td.textContent = "Không có lỗ hổng nào được ghi nhận cho phiên quét này.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return filtered;
    }

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 7;
      td.className = "text-center text-muted py-4";
      td.textContent = "Không tìm thấy lỗ hổng nào khớp với bộ lọc hiện tại.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return filtered;
    }

    filtered.forEach(function (item, idx) {
      const tr = document.createElement("tr");

      const tdIdx = document.createElement("td");
      tdIdx.textContent = String(idx + 1);
      tr.appendChild(tdIdx);

      const tdSev = document.createElement("td");
      tdSev.appendChild(createSeverityBadge(item.severity));
      tr.appendChild(tdSev);

      const tdType = document.createElement("td");
      tdType.className = "fw-semibold";
      tdType.textContent = item.vuln_type || item.vuln_name || "-";
      tr.appendChild(tdType);

      const tdUrl = document.createElement("td");
      const code = document.createElement("code");
      code.textContent = item.target_url || "-";
      tdUrl.appendChild(code);
      tr.appendChild(tdUrl);

      const tdParam = document.createElement("td");
      tdParam.textContent = item.param || item.parameter || "-";
      tr.appendChild(tdParam);

      const tdCwe = document.createElement("td");
      tdCwe.className = "small";
      tdCwe.textContent = (item.cwe_id || "-") + " / " + (item.owasp_category || "-");
      tr.appendChild(tdCwe);

      const tdAction = document.createElement("td");
      tdAction.className = "text-end";
      const detailBtn = document.createElement("button");
      detailBtn.type = "button";
      detailBtn.className = "btn btn-sm btn-outline-primary";
      detailBtn.textContent = "Xem chi tiết";
      detailBtn.addEventListener("click", function () {
        openFindingModal(item);
      });
      tdAction.appendChild(detailBtn);
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });

    return filtered;
  }

  function renderDetailFindings(findings) {
    currentDetailFindings = Array.isArray(findings) ? findings.slice() : [];

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    currentDetailFindings.forEach(function (f) {
      const sev = String(f.severity || "INFO").toUpperCase();
      if (counts[sev] !== undefined) {
        counts[sev] += 1;
      } else {
        counts.INFO += 1;
      }
    });

    const setCnt = function (id, val) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = String(val);
      }
    };
    setCnt("detailCntCritical", counts.CRITICAL);
    setCnt("detailCntHigh", counts.HIGH);
    setCnt("detailCntMedium", counts.MEDIUM);
    setCnt("detailCntLow", counts.LOW);
    setCnt("detailCntInfo", counts.INFO);

    if (global.ScannerCharts) {
      global.ScannerCharts.renderSeverityChart("detailSeverityChart", counts);
    }

    return renderFilteredFindingsTable();
  }

  function renderScanDetailMeta(scan) {
    const status = String(scan.status || "PENDING").toUpperCase();
    const statusBadge = document.getElementById("detailStatusBadge");
    if (statusBadge) {
      statusBadge.className = "badge ms-2 status-badge-" + status.toLowerCase();
      statusBadge.textContent = status;
    }

    const pct = Math.min(Math.max(Number(scan.progress || 0), 0), 100);
    const progressText = document.getElementById("detailProgressText");
    if (progressText) {
      progressText.textContent = pct + "%";
    }
    const progressBar = document.getElementById("detailProgressBar");
    if (progressBar) {
      progressBar.style.width = pct + "%";
      progressBar.setAttribute("aria-valuenow", String(pct));
      progressBar.textContent = pct + "%";
      if (FINISHED_STATUSES.has(status)) {
        progressBar.classList.remove("progress-bar-animated", "progress-bar-striped");
      } else {
        progressBar.classList.add("progress-bar-animated", "progress-bar-striped");
      }
    }

    const setField = function (id, val) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = val !== null && val !== undefined && val !== "" ? String(val) : "-";
      }
    };
    setField("detailTargetUrl", scan.target_url);
    setField("detailMaxDepth", scan.max_depth);
    setField(
      "detailModules",
      Array.isArray(scan.modules_enabled) ? scan.modules_enabled.join(", ") : "-"
    );
    setField("detailStartTime", formatDateTime(scan.start_time));
    setField("detailEndTime", formatDateTime(scan.end_time));

    const errorBox = document.getElementById("detailErrorBox");
    if (errorBox) {
      if (scan.error_message) {
        errorBox.textContent = "Thông báo phiên quét: " + scan.error_message;
        errorBox.classList.remove("d-none");
      } else {
        errorBox.textContent = "";
        errorBox.classList.add("d-none");
      }
    }

    const stopBtn = document.getElementById("stopScanBtn");
    if (stopBtn) {
      if (ACTIVE_STATUSES.has(status)) {
        stopBtn.classList.remove("d-none");
        stopBtn.disabled = false;
      } else {
        stopBtn.classList.add("d-none");
      }
    }

    const pollIndicator = document.getElementById("pollingIndicator");
    if (pollIndicator) {
      if (FINISHED_STATUSES.has(status)) {
        pollIndicator.className = "badge bg-secondary";
        pollIndicator.textContent = "Đã kết thúc (" + status + ")";
      } else {
        pollIndicator.className = "badge bg-info text-dark";
        pollIndicator.textContent = "Đang cập nhật trực tiếp...";
      }
    }
  }

  async function pollScanDetail(sessionId) {
    if (!getToken()) {
      stopAllPolling();
      showAlert(
        "detailAlert",
        "Bạn cần đăng nhập tại trang Dashboard để xem chi tiết phiên quét này.",
        "warning"
      );
      return;
    }

    try {
      const scanResp = await apiFetch("/api/scans/" + encodeURIComponent(sessionId), { method: "GET" });
      if (scanResp.status === 401) {
        clearSession();
        showAlert("detailAlert", "Phiên đăng nhập đã hết hạn. Vui lòng quay lại Dashboard để đăng nhập.", "warning");
        return;
      }
      if (scanResp.status === 404) {
        stopAllPolling();
        showAlert("detailAlert", "Không tìm thấy phiên quét hoặc bạn không có quyền truy cập.", "danger");
        return;
      }
      if (!scanResp.ok) {
        showAlert("detailAlert", "Không thể tải trạng thái phiên quét (HTTP " + scanResp.status + ").", "danger");
        return;
      }
      const scanData = await scanResp.json();
      const scan = scanData.scan || {};
      renderScanDetailMeta(scan);

      const findingsResp = await apiFetch(
        "/api/scans/" + encodeURIComponent(sessionId) + "/findings",
        { method: "GET" }
      );
      if (findingsResp.ok) {
        const findingsData = await findingsResp.json();
        renderDetailFindings(findingsData.findings || []);
      }

      const status = String(scan.status || "").toUpperCase();
      if (FINISHED_STATUSES.has(status) && detailPollTimer !== null) {
        global.clearInterval(detailPollTimer);
        detailPollTimer = null;
      }
    } catch (_err) {
      showAlert("detailAlert", "Lỗi kết nối mạng khi đồng bộ trạng thái phiên quét.", "danger");
    }
  }

  function initScanDetailView(detailRoot) {
    const sessionId = detailRoot.getAttribute("data-session-id");
    if (!sessionId) {
      return;
    }

    const stopBtn = document.getElementById("stopScanBtn");
    const txtBtn = document.getElementById("downloadTxtBtn");
    const pdfBtn = document.getElementById("downloadPdfBtn");
    const closeModalBtn = document.getElementById("closeFindingModalBtn");
    const modalBackdrop = document.getElementById("findingDetailModal");
    const severityFilter = document.getElementById("findingSeverityFilter");
    const keywordFilter = document.getElementById("findingKeywordFilter");
    const clearFilterBtn = document.getElementById("clearFindingFilterBtn");

    if (severityFilter) {
      severityFilter.addEventListener("change", function () {
        renderFilteredFindingsTable();
      });
    }
    if (keywordFilter) {
      keywordFilter.addEventListener("input", function () {
        renderFilteredFindingsTable();
      });
    }
    if (clearFilterBtn) {
      clearFilterBtn.addEventListener("click", function () {
        if (severityFilter) {
          severityFilter.value = "ALL";
        }
        if (keywordFilter) {
          keywordFilter.value = "";
        }
        renderFilteredFindingsTable();
      });
    }

    if (stopBtn) {
      stopBtn.addEventListener("click", async function () {
        stopBtn.disabled = true;
        hideAlert("detailAlert");
        try {
          const resp = await apiFetch("/api/scans/" + encodeURIComponent(sessionId) + "/stop", {
            method: "POST",
          });
          const body = await resp.json();
          if (!resp.ok) {
            showAlert("detailAlert", (body && body.message) || "Không thể dừng phiên quét.", "warning");
          } else {
            showAlert(
              "detailAlert",
              "Đã gửi tín hiệu dừng phiên quét (trạng thái: " + (body.state || body.status) + ").",
              "info"
            );
          }
          await pollScanDetail(sessionId);
        } catch (_err) {
          showAlert("detailAlert", "Lỗi kết nối mạng khi gửi yêu cầu dừng phiên quét.", "danger");
          stopBtn.disabled = false;
        }
      });
    }

    if (txtBtn) {
      txtBtn.addEventListener("click", function () {
        downloadReportFile(sessionId, "txt", "detailAlert");
      });
    }

    if (pdfBtn) {
      pdfBtn.addEventListener("click", function () {
        downloadReportFile(sessionId, "pdf", "detailAlert");
      });
    }

    if (closeModalBtn) {
      closeModalBtn.addEventListener("click", closeFindingModal);
    }
    if (modalBackdrop) {
      modalBackdrop.addEventListener("click", function (evt) {
        if (evt.target === modalBackdrop) {
          closeFindingModal();
        }
      });
    }

    pollScanDetail(sessionId);
    detailPollTimer = global.setInterval(function () {
      pollScanDetail(sessionId);
    }, POLL_INTERVAL_MS);
  }

  /* ======================================================================
   * BOOTSTRAP ON DOM READY
   * ====================================================================== */
  document.addEventListener("DOMContentLoaded", function () {
    updateNavbarAuth();

    const logoutBtn = document.getElementById("navLogoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        clearSession();
        if (document.getElementById("dashboardView")) {
          toggleDashboardAuthView(false);
        } else {
          global.location.href = "/dashboard";
        }
      });
    }

    if (document.getElementById("dashboardView")) {
      initDashboardView();
    }

    const detailRoot = document.getElementById("scanDetailView");
    if (detailRoot) {
      initScanDetailView(detailRoot);
    }
  });

  global.OWASPScannerApp = {
    escapeHtml: escapeHtml,
    getToken: getToken,
    setSession: setSession,
    clearSession: clearSession,
    downloadReportFile: downloadReportFile,
    filterFindings: filterFindings,
    renderDetailFindings: renderDetailFindings,
    renderFilteredFindingsTable: renderFilteredFindingsTable,
    getCurrentDetailFindings: getCurrentDetailFindings,
  };
})(window);
>>>>>>> Stashed changes
