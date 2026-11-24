/**
 * Threat Relationship Graph Controller.
 * Manages interactive SVG rendering, pan/zoom, node dragging, and entity inspection.
 */
class ThreatGraphVisualizer {
  constructor() {
    this.graphData = null;
    this.selectedNodeId = null;
    this.filterMode = 'all';
    this.zoomLevel = 1.0;
    this.panOffset = { x: 0, y: 0 };
    this.isDragging = false;
    this.dragStart = { x: 0, y: 0 };

    this.svg = document.getElementById('threat-svg');
    this.world = document.getElementById('svg-world');
    this.container = document.getElementById('graph-canvas-container');

    this.nodeColors = {
      url: { bg: '#1e293b', border: '#94a3b8', text: '#f8fafc', glow: 'rgba(148, 163, 184, 0.3)' },
      hostname: { bg: '#0f2942', border: '#38bdf8', text: '#e0f2fe', glow: 'rgba(56, 189, 248, 0.35)' },
      domain: { bg: '#1e1b4b', border: '#818cf8', text: '#e0e7ff', glow: 'rgba(129, 140, 248, 0.4)' },
      ip: { bg: '#2e1065', border: '#c084fc', text: '#f3e8ff', glow: 'rgba(192, 132, 252, 0.4)' },
      registrar: { bg: '#042f2e', border: '#2dd4bf', text: '#ccfbf1', glow: 'rgba(45, 212, 191, 0.3)' },
      nameserver: { bg: '#142738', border: '#60a5fa', text: '#dbeafe', glow: 'rgba(96, 165, 250, 0.3)' },
      brand_target: { bg: '#4c0519', border: '#fb7185', text: '#ffe4e6', glow: 'rgba(251, 113, 133, 0.6)' },
    };

    this.riskBadges = {
      critical: { label: 'CRITICAL THREAT', color: '#ff3366' },
      high: { label: 'HIGH RISK', color: '#ff5c6c' },
      suspicious: { label: 'SUSPICIOUS', color: '#ffb84d' },
      safe: { label: 'ESTABLISHED / SAFE', color: '#4fd1c5' },
      low: { label: 'LOW RISK', color: '#4fd1c5' },
      neutral: { label: 'NEUTRAL', color: '#94a3b8' },
    };

    this.initEventListeners();
  }

  initEventListeners() {
    if (!this.container) return;

    this.container.addEventListener('mousedown', (e) => {
      if (e.target.closest('.graph-node')) return;
      this.isDragging = true;
      this.dragStart = { x: e.clientX - this.panOffset.x, y: e.clientY - this.panOffset.y };
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.isDragging) return;
      this.panOffset = {
        x: e.clientX - this.dragStart.x,
        y: e.clientY - this.dragStart.y,
      };
      this.updateTransform();
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
    });

    // Zoom buttons
    const zoomIn = document.getElementById('zoom-in-btn');
    const zoomOut = document.getElementById('zoom-out-btn');
    const zoomReset = document.getElementById('zoom-reset-btn');

    if (zoomIn) zoomIn.addEventListener('click', () => this.setZoom(this.zoomLevel + 0.15));
    if (zoomOut) zoomOut.addEventListener('click', () => this.setZoom(this.zoomLevel - 0.15));
    if (zoomReset) zoomReset.addEventListener('click', () => this.resetView());

    // Filter buttons
    const filterBtns = document.querySelectorAll('.threat-graph__filter-group .filter-btn');
    filterBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        filterBtns.forEach((b) => b.classList.remove('active'));
        e.target.classList.add('active');
        this.filterMode = e.target.getAttribute('data-filter') || 'all';
        this.render();
      });
    });
  }

  setZoom(val) {
    this.zoomLevel = Math.max(0.6, Math.min(2.2, val));
    this.updateTransform();
  }

  resetView() {
    this.zoomLevel = 1.0;
    this.panOffset = { x: 0, y: 0 };
    this.updateTransform();
  }

  updateTransform() {
    if (this.world) {
      this.world.setAttribute('transform', `translate(${this.panOffset.x}, ${this.panOffset.y}) scale(${this.zoomLevel})`);
    }
  }

  loadData(graphData) {
    this.graphData = graphData || { nodes: [], edges: [], summary: {}, threat_indicators: [] };
    this.selectedNodeId = null;

    if (this.graphData.nodes.length > 0) {
      const topRisk = this.graphData.nodes.find((n) => n.risk_level === 'critical' || n.type === 'brand_target');
      this.selectedNodeId = topRisk ? topRisk.id : this.graphData.nodes[0].id;
    }

    this.updateTelemetryRibbon();
    this.render();
  }

  updateTelemetryRibbon() {
    if (!this.graphData) return;
    const summary = this.graphData.summary || {};

    const elDomain = document.getElementById('telemetry-domain');
    const elAge = document.getElementById('telemetry-age');
    const elIps = document.getElementById('telemetry-ips');
    const elSsrf = document.getElementById('telemetry-ssrf');

    if (elDomain) elDomain.textContent = summary.domain || summary.registrar || '—';

    if (elAge) {
      if (summary.domain_age_days !== null && summary.domain_age_days !== undefined) {
        let ageText = `${summary.domain_age_days} days`;
        elAge.className = 'telemetry-value';
        if (summary.is_critically_young) {
          elAge.classList.add('text-critical');
          ageText += ' (Critical < 14d)';
        } else if (summary.is_recently_registered) {
          elAge.classList.add('text-warning');
          ageText += ' (Recent < 30d)';
        } else {
          elAge.classList.add('text-safe');
        }
        elAge.textContent = ageText;
      } else {
        elAge.textContent = 'Unknown / Private';
        elAge.className = 'telemetry-value';
      }
    }

    if (elIps) {
      const count = (summary.resolved_ips || []).length;
      elIps.textContent = `${count} ${summary.is_fast_flux ? '(Fast-Flux)' : ''}`;
    }

    if (elSsrf) {
      if (summary.ssrf_risk) {
        elSsrf.textContent = 'BLOCKED / PRIVATE';
        elSsrf.className = 'telemetry-value text-critical';
      } else {
        elSsrf.textContent = 'PASSED (Public)';
        elSsrf.className = 'telemetry-value text-safe';
      }
    }

    // Threat indicators box
    const indBox = document.getElementById('threat-indicators-box');
    const indList = document.getElementById('threat-indicators-list');
    const indicators = this.graphData.threat_indicators || [];

    if (indBox && indList) {
      if (indicators.length > 0) {
        indBox.style.display = 'block';
        indList.innerHTML = indicators.map((ind) => `<li>${this.escapeHtml(ind)}</li>`).join('');
      } else {
        indBox.style.display = 'none';
        indList.innerHTML = '';
      }
    }
  }

  computeNodePositions(nodes) {
    const pos = {};
    const centerY = 240;

    const urlNode = nodes.find((n) => n.type === 'url');
    const hostNode = nodes.find((n) => n.type === 'hostname');
    const domainNode = nodes.find((n) => n.type === 'domain');
    const brandNode = nodes.find((n) => n.type === 'brand_target');
    const ipNodes = nodes.filter((n) => n.type === 'ip');
    const registrarNode = nodes.find((n) => n.type === 'registrar');
    const nsNodes = nodes.filter((n) => n.type === 'nameserver');

    if (urlNode) pos[urlNode.id] = { x: 110, y: centerY - 50 };
    if (hostNode) pos[hostNode.id] = { x: 260, y: centerY - 50 };
    if (domainNode) pos[domainNode.id] = { x: 420, y: centerY };
    if (brandNode) pos[brandNode.id] = { x: 610, y: centerY - 130 };
    if (registrarNode) pos[registrarNode.id] = { x: 610, y: centerY };

    ipNodes.forEach((ip, idx) => {
      pos[ip.id] = { x: 210 + idx * 85, y: centerY + 120 };
    });

    nsNodes.forEach((ns, idx) => {
      pos[ns.id] = { x: 610, y: centerY + 70 + idx * 55 };
    });

    nodes.forEach((n, idx) => {
      if (!pos[n.id]) {
        const angle = (idx / nodes.length) * 2 * Math.PI;
        pos[n.id] = { x: 380 + Math.cos(angle) * 160, y: centerY + Math.sin(angle) * 130 };
      }
    });

    return pos;
  }

  render() {
    if (!this.world || !this.graphData) return;

    let nodes = this.graphData.nodes || [];
    let edges = this.graphData.edges || [];

    if (this.filterMode === 'threats') {
      nodes = nodes.filter(
        (n) => n.risk_level === 'critical' || n.risk_level === 'high' || n.type === 'brand_target' || n.type === 'url'
      );
    } else if (this.filterMode === 'infra') {
      nodes = nodes.filter(
        (n) => n.type === 'ip' || n.type === 'registrar' || n.type === 'nameserver' || n.type === 'domain'
      );
    }

    const visibleIds = new Set(nodes.map((n) => n.id));
    const visibleEdges = edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
    const positions = this.computeNodePositions(nodes);

    let html = '';

    // Render Edges
    visibleEdges.forEach((edge) => {
      const s = positions[edge.source];
      const t = positions[edge.target];
      if (!s || !t) return;

      const isSelected = this.selectedNodeId && (edge.source === this.selectedNodeId || edge.target === this.selectedNodeId);
      const isThreat = edge.relationship === 'IMPERSONATES' || edge.relationship === 'TARGETS_BRAND';
      const marker = isThreat ? 'url(#arrowhead-threat)' : 'url(#arrowhead)';

      html += `
        <g class="graph-edge-group">
          <line
            x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}"
            class="graph-edge ${isSelected ? 'selected' : ''} ${isThreat ? 'threat' : ''}"
            marker-end="${marker}"
          />
          <text
            x="${(s.x + t.x) / 2}" y="${(s.y + t.y) / 2 - 8}"
            class="graph-edge-label ${isThreat ? 'threat' : ''}"
            text-anchor="middle"
          >${this.escapeHtml(edge.label)}</text>
        </g>
      `;
    });

    // Render Nodes
    nodes.forEach((node) => {
      const p = positions[node.id];
      if (!p) return;

      const isSelected = this.selectedNodeId === node.id;
      const isCritical = node.risk_level === 'critical';
      const scheme = this.nodeColors[node.type] || this.nodeColors.url;
      const radius = node.type === 'domain' || node.type === 'brand_target' ? 24 : 18;

      let typeLetter = 'HOST';
      if (node.type === 'url') typeLetter = 'URL';
      else if (node.type === 'domain') typeLetter = 'DOM';
      else if (node.type === 'brand_target') typeLetter = 'TARGET';
      else if (node.type === 'ip') typeLetter = 'IP';
      else if (node.type === 'registrar') typeLetter = 'REG';
      else if (node.type === 'nameserver') typeLetter = 'NS';

      const shortLabel = node.label.length > 20 ? `${node.label.slice(0, 18)}…` : node.label;

      html += `
        <g
          class="graph-node ${isSelected ? 'selected' : ''} ${isCritical ? 'critical-pulse' : ''}"
          transform="translate(${p.x}, ${p.y})"
          data-node-id="${node.id}"
        >
          <circle r="${radius + 6}" fill="${scheme.glow}" opacity="${isSelected ? 0.9 : isCritical ? 0.7 : 0.25}" />
          <circle r="${radius}" fill="${scheme.bg}" stroke="${scheme.border}" stroke-width="${isSelected ? 3 : 2}" ${isCritical || isSelected ? 'filter="url(#node-glow)"' : ''} />
          <text dy="4" text-anchor="middle" fill="${scheme.text}" font-size="${radius > 20 ? 12 : 10}" font-weight="bold" font-family="var(--font-mono)">${typeLetter}</text>
          <text y="${radius + 16}" text-anchor="middle" class="graph-node-label" fill="#cbd5e1">${this.escapeHtml(shortLabel)}</text>
        </g>
      `;
    });

    this.world.innerHTML = html;
    this.updateTransform();

    // Attach click events on nodes
    this.world.querySelectorAll('.graph-node').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = el.getAttribute('data-node-id');
        this.selectNode(id);
      });
    });

    this.updateInspector();
  }

  selectNode(nodeId) {
    this.selectedNodeId = nodeId;
    this.render();
  }

  updateInspector() {
    const riskTag = document.getElementById('inspector-risk-tag');
    const body = document.getElementById('inspector-body');
    if (!body) return;

    const node = (this.graphData?.nodes || []).find((n) => n.id === this.selectedNodeId);

    if (!node) {
      if (riskTag) {
        riskTag.textContent = 'SELECT NODE';
        riskTag.style.color = '#94a3b8';
      }
      body.innerHTML = '<div class="inspector-empty">Select any graph node to inspect forensic attributes.</div>';
      return;
    }

    const badge = this.riskBadges[node.risk_level] || this.riskBadges.neutral;
    if (riskTag) {
      riskTag.textContent = badge.label;
      riskTag.style.color = badge.color;
    }

    const props = node.properties || {};
    let propsHtml = '';
    for (const [k, v] of Object.entries(props)) {
      let displayVal = v;
      if (typeof v === 'boolean') displayVal = v ? 'Yes' : 'No';
      if (Array.isArray(v)) displayVal = v.length ? v.join(', ') : 'None';
      if (v === null || v === undefined) displayVal = '—';
      if (typeof v === 'number' && k.includes('similarity')) {
        displayVal = `${Math.round(v * 100)}%`;
      }

      propsHtml += `
        <div class="inspector-prop-row">
          <span class="prop-name">${this.escapeHtml(k.replace(/_/g, ' '))}</span>
          <span class="prop-val font-mono">${this.escapeHtml(String(displayVal))}</span>
        </div>
      `;
    }

    // Connected edges
    const connectedEdges = (this.graphData.edges || []).filter(
      (e) => e.source === node.id || e.target === node.id
    );

    let relsHtml = '';
    connectedEdges.forEach((e) => {
      const otherId = e.source === node.id ? e.target : e.source;
      const otherNode = (this.graphData.nodes || []).find((n) => n.id === otherId);
      const otherLabel = otherNode ? otherNode.label : otherId;

      relsHtml += `
        <div class="relation-pill" data-target-id="${otherId}" title="Inspect ${this.escapeHtml(otherLabel)}">
          <span class="relation-rel">${this.escapeHtml(e.label)}</span>
          <span class="relation-node-name">${this.escapeHtml(otherLabel)}</span>
        </div>
      `;
    });

    body.innerHTML = `
      <div class="inspector-title-row">
        <span class="inspector-type-badge">${this.escapeHtml(node.type.toUpperCase())}</span>
        <span class="inspector-label font-mono">${this.escapeHtml(node.label)}</span>
      </div>
      <div class="inspector-props-list">${propsHtml}</div>
      <div class="inspector-relations">
        <span class="relations-title">Correlated Connections</span>
        <div class="relations-tags">${relsHtml || '<span style="color:#64748b; font-size:12px;">No direct links</span>'}</div>
      </div>
    `;

    // Attach click handlers to relation pills
    body.querySelectorAll('.relation-pill').forEach((pill) => {
      pill.addEventListener('click', () => {
        const targetId = pill.getAttribute('data-target-id');
        if (targetId) this.selectNode(targetId);
      });
    });
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}

// Global instance
window.threatGraphVisualizer = new ThreatGraphVisualizer();
