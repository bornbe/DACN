/* Issue #6.1: Chart.js views for dashboard and scan findings. */
(function () {
  "use strict";

  const charts = new Map();
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const severityColors = ["#8b1e3f", "#dc3545", "#fd7e14", "#f0ad4e", "#6c757d"];
  const statusLabels = {
    PENDING: "Chờ xử lý",
    RUNNING: "Đang chạy",
    CRAWLING: "Đang crawl",
    SCANNING: "Đang quét",
    COMPLETED: "Hoàn tất",
    FAILED: "Thất bại",
    CANCELLED: "Đã hủy",
    NO_MODULES: "Không có module"
  };
  const statusColors = ["#8993a4", "#0d6efd", "#0dcaf0", "#6610f2", "#198754", "#dc3545", "#6c757d", "#ffc107"];

  function drawChart(canvasId, config) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof window.Chart !== "function") return;
    const previous = charts.get(canvasId);
    if (previous) previous.destroy();
    charts.set(canvasId, new window.Chart(canvas, config));
  }

  function setEmptyState(canvasId, emptyId, hasData) {
    const canvas = document.getElementById(canvasId);
    const empty = document.getElementById(emptyId);
    if (canvas) canvas.classList.toggle("d-none", !hasData);
    if (empty) empty.classList.toggle("d-none", hasData);
  }

  function renderOverview(scans) {
    const counts = new Map();
    scans.forEach(function (scan) {
      const status = String(scan.status || "PENDING").toUpperCase();
      counts.set(status, (counts.get(status) || 0) + 1);
    });
    const labels = Array.from(counts.keys());
    const values = labels.map(function (label) { return counts.get(label); });
    setEmptyState("overview-chart", "overview-empty", values.some(function (value) { return value > 0; }));
    if (!values.some(function (value) { return value > 0; })) return;

    drawChart("overview-chart", {
      type: "doughnut",
      data: {
        labels: labels.map(function (label) { return statusLabels[label] || label; }),
        datasets: [{
          data: values,
          backgroundColor: labels.map(function (label) {
            const index = Object.keys(statusLabels).indexOf(label);
            return statusColors[index < 0 ? 0 : index];
          }),
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        cutout: "62%"
      }
    });
  }

  function renderFindings(findings) {
    const severityCounts = new Map(severityOrder.map(function (severity) { return [severity, 0]; }));
    const typeCounts = new Map();
    findings.forEach(function (finding) {
      const severity = String(finding.severity || "INFO").toUpperCase();
      severityCounts.set(severity, (severityCounts.get(severity) || 0) + 1);
      const type = String(finding.vuln_name || finding.vuln_type || "Khác");
      typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
    });

    const severityValues = severityOrder.map(function (severity) { return severityCounts.get(severity) || 0; });
    const hasFindings = findings.length > 0;
    setEmptyState("severity-chart", "severity-empty", hasFindings);
    setEmptyState("type-chart", "type-empty", hasFindings);
    if (!hasFindings) return;

    drawChart("severity-chart", {
      type: "bar",
      data: {
        labels: severityOrder,
        datasets: [{
          label: "Số phát hiện",
          data: severityValues,
          backgroundColor: severityColors,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { display: false } }
      }
    });

    const types = Array.from(typeCounts.keys());
    drawChart("type-chart", {
      type: "doughnut",
      data: {
        labels: types,
        datasets: [{
          data: types.map(function (type) { return typeCounts.get(type); }),
          backgroundColor: ["#0d6efd", "#20c997", "#6610f2", "#fd7e14", "#d63384", "#0dcaf0", "#6c757d"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        cutout: "55%"
      }
    });
  }

  window.DACNCharts = { renderOverview: renderOverview, renderFindings: renderFindings };
}());