/**
 * Module biểu đồ phân bố mức độ nghiêm trọng (Chart.js + Canvas 2D fallback) - Issue #6.1.
 */
(function (global) {
  "use strict";

  const SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const SEVERITY_COLORS = {
    CRITICAL: "#8e0000",
    HIGH: "#d9534f",
    MEDIUM: "#f0ad4e",
    LOW: "#0dcaf0",
    INFO: "#6c757d",
  };

  const chartInstances = {};

  function normalizeCounts(rawCounts) {
    const counts = rawCounts && typeof rawCounts === "object" ? rawCounts : {};
    return SEVERITY_KEYS.map(function (key) {
      const value = Number(counts[key] || 0);
      return Number.isFinite(value) && value > 0 ? value : 0;
    });
  }

  function drawCanvasFallback(canvas, values) {
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      return;
    }
    const width = canvas.width || 340;
    const height = canvas.height || 200;
    ctx.clearRect(0, 0, width, height);

    const total = values.reduce(function (acc, item) {
      return acc + item;
    }, 0);

    ctx.font = "12px sans-serif";
    const rowHeight = Math.floor((height - 20) / SEVERITY_KEYS.length);
    const maxBarWidth = Math.max(width - 140, 80);

    SEVERITY_KEYS.forEach(function (label, index) {
      const count = values[index];
      const y = 12 + index * rowHeight;
      ctx.fillStyle = "#1f2937";
      ctx.fillText(label, 8, y + 14);

      const barWidth = total > 0 ? Math.max(Math.round((count / total) * maxBarWidth), count > 0 ? 6 : 0) : 0;
      ctx.fillStyle = "#e5e7eb";
      ctx.fillRect(85, y + 3, maxBarWidth, 14);

      if (barWidth > 0) {
        ctx.fillStyle = SEVERITY_COLORS[label];
        ctx.fillRect(85, y + 3, barWidth, 14);
      }

      ctx.fillStyle = "#111827";
      ctx.fillText(String(count), 92 + maxBarWidth, y + 14);
    });
  }

  function renderSeverityChart(canvasId, rawCounts) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) {
      return null;
    }

    const values = normalizeCounts(rawCounts);
    const colors = SEVERITY_KEYS.map(function (k) {
      return SEVERITY_COLORS[k];
    });

    if (typeof global.Chart === "function") {
      if (chartInstances[canvasId]) {
        chartInstances[canvasId].data.datasets[0].data = values;
        chartInstances[canvasId].update();
        return chartInstances[canvasId];
      }
      chartInstances[canvasId] = new global.Chart(canvas, {
        type: "doughnut",
        data: {
          labels: SEVERITY_KEYS,
          datasets: [
            {
              label: "Số lượng lỗ hổng",
              data: values,
              backgroundColor: colors,
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
            },
          },
        },
      });
      return chartInstances[canvasId];
    }

    drawCanvasFallback(canvas, values);
    return null;
  }

  global.ScannerCharts = {
    SEVERITY_KEYS: SEVERITY_KEYS,
    SEVERITY_COLORS: SEVERITY_COLORS,
    renderSeverityChart: renderSeverityChart,
  };
})(window);
