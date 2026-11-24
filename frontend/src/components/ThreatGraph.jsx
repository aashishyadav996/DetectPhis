import { useState, useMemo, useRef, useEffect } from 'react'
import './ThreatGraph.css'

const NODE_COLORS = {
  url: { bg: '#1e293b', border: '#94a3b8', text: '#f8fafc', glow: 'rgba(148, 163, 184, 0.3)' },
  hostname: { bg: '#0f2942', border: '#38bdf8', text: '#e0f2fe', glow: 'rgba(56, 189, 248, 0.35)' },
  domain: { bg: '#1e1b4b', border: '#818cf8', text: '#e0e7ff', glow: 'rgba(129, 140, 248, 0.4)' },
  ip: { bg: '#2e1065', border: '#c084fc', text: '#f3e8ff', glow: 'rgba(192, 132, 252, 0.4)' },
  registrar: { bg: '#042f2e', border: '#2dd4bf', text: '#ccfbf1', glow: 'rgba(45, 212, 191, 0.3)' },
  nameserver: { bg: '#142738', border: '#60a5fa', text: '#dbeafe', glow: 'rgba(96, 165, 250, 0.3)' },
  brand_target: { bg: '#4c0519', border: '#fb7185', text: '#ffe4e6', glow: 'rgba(251, 113, 133, 0.6)' },
}

const RISK_BADGES = {
  critical: { label: 'CRITICAL THREAT', color: '#ff3366' },
  high: { label: 'HIGH RISK', color: '#ff5c6c' },
  suspicious: { label: 'SUSPICIOUS', color: '#ffb84d' },
  safe: { label: 'ESTABLISHED / SAFE', color: '#4fd1c5' },
  low: { label: 'LOW RISK', color: '#4fd1c5' },
  neutral: { label: 'NEUTRAL', color: '#94a3b8' },
}

export default function ThreatGraph({ graphData }) {
  const [selectedNodeId, setSelectedNodeId] = useState(null)
  const [filterMode, setFilterMode] = useState('all') // 'all' | 'threats' | 'infra'
  const [zoomLevel, setZoomLevel] = useState(1)
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 })
  const isDraggingRef = useRef(false)
  const dragStartRef = useRef({ x: 0, y: 0 })
  const svgRef = useRef(null)

  const { nodes = [], edges = [], summary = {}, threat_indicators = [] } = graphData || {}

  // Filter nodes according to active view filter
  const visibleNodes = useMemo(() => {
    if (filterMode === 'threats') {
      return nodes.filter(
        (n) => n.risk_level === 'critical' || n.risk_level === 'high' || n.type === 'brand_target' || n.type === 'url'
      )
    }
    if (filterMode === 'infra') {
      return nodes.filter(
        (n) => n.type === 'ip' || n.type === 'registrar' || n.type === 'nameserver' || n.type === 'domain'
      )
    }
    return nodes
  }, [nodes, filterMode])

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes])

  const visibleEdges = useMemo(() => {
    return edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
  }, [edges, visibleNodeIds])

  // Layout node positions hierarchically / organically
  const nodePositions = useMemo(() => {
    const pos = {}
    const width = 760
    const height = 480
    const centerX = width / 2
    const centerY = height / 2

    // Categorize nodes
    const urlNode = visibleNodes.find((n) => n.type === 'url')
    const hostNode = visibleNodes.find((n) => n.type === 'hostname')
    const domainNode = visibleNodes.find((n) => n.type === 'domain')
    const brandNode = visibleNodes.find((n) => n.type === 'brand_target')
    const ipNodes = visibleNodes.filter((n) => n.type === 'ip')
    const registrarNode = visibleNodes.find((n) => n.type === 'registrar')
    const nsNodes = visibleNodes.filter((n) => n.type === 'nameserver')

    if (urlNode) pos[urlNode.id] = { x: 120, y: centerY - 60 }
    if (hostNode) pos[hostNode.id] = { x: 280, y: centerY - 60 }
    if (domainNode) pos[domainNode.id] = { x: 440, y: centerY }

    if (brandNode) {
      pos[brandNode.id] = { x: 620, y: centerY - 140 }
    }

    if (registrarNode) {
      pos[registrarNode.id] = { x: 620, y: centerY }
    }

    // IP nodes on bottom-left / bottom-center
    ipNodes.forEach((ip, idx) => {
      const spacing = 80
      const startX = 220
      pos[ip.id] = { x: startX + idx * spacing, y: centerY + 130 }
    })

    // Nameservers on bottom-right
    nsNodes.forEach((ns, idx) => {
      const startY = centerY + 80
      pos[ns.id] = { x: 620, y: startY + idx * 60 }
    })

    // Fallback for any unpositioned visible nodes
    visibleNodes.forEach((n, idx) => {
      if (!pos[n.id]) {
        const angle = (idx / visibleNodes.length) * 2 * Math.PI
        pos[n.id] = {
          x: centerX + Math.cos(angle) * 180,
          y: centerY + Math.sin(angle) * 160,
        }
      }
    })

    return pos
  }, [visibleNodes])

  // Select initial interesting node if none selected
  useEffect(() => {
    if (!selectedNodeId && nodes.length > 0) {
      const highRisk = nodes.find((n) => n.risk_level === 'critical' || n.type === 'brand_target')
      setSelectedNodeId(highRisk ? highRisk.id : nodes[0].id)
    }
  }, [nodes, selectedNodeId])

  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null
  }, [nodes, selectedNodeId])

  // Pan handlers
  function handleMouseDown(e) {
    if (e.target.tagName === 'circle' || e.target.closest('.graph-node')) return
    isDraggingRef.current = true
    dragStartRef.current = { x: e.clientX - panOffset.x, y: e.clientY - panOffset.y }
  }

  function handleMouseMove(e) {
    if (!isDraggingRef.current) return
    setPanOffset({
      x: e.clientX - dragStartRef.current.x,
      y: e.clientY - dragStartRef.current.y,
    })
  }

  function handleMouseUp() {
    isDraggingRef.current = false
  }

  function handleResetView() {
    setZoomLevel(1)
    setPanOffset({ x: 0, y: 0 })
  }

  return (
    <div className="threat-graph-wrapper card">
      <div className="threat-graph__header">
        <div>
          <div className="threat-graph__title-row">
            <h3 className="threat-graph__title">Threat Relationship Graph</h3>
            <span className="threat-graph__badge">Phase 4 Infrastructure Correlation</span>
          </div>
          <p className="threat-graph__subtitle">
            Interactive correlation of URL destination, registrable domain, authoritative DNS, resolved IPs, and targeted brands.
          </p>
        </div>

        <div className="threat-graph__controls">
          <div className="threat-graph__filter-group">
            <button
              type="button"
              className={`filter-btn ${filterMode === 'all' ? 'active' : ''}`}
              onClick={() => setFilterMode('all')}
            >
              All ({nodes.length})
            </button>
            <button
              type="button"
              className={`filter-btn ${filterMode === 'threats' ? 'active' : ''}`}
              onClick={() => setFilterMode('threats')}
            >
              Threats
            </button>
            <button
              type="button"
              className={`filter-btn ${filterMode === 'infra' ? 'active' : ''}`}
              onClick={() => setFilterMode('infra')}
            >
              Infra
            </button>
          </div>

          <div className="threat-graph__zoom-group">
            <button
              type="button"
              className="zoom-btn"
              title="Zoom In"
              onClick={() => setZoomLevel((z) => Math.min(z + 0.15, 2.0))}
            >
              +
            </button>
            <button
              type="button"
              className="zoom-btn"
              title="Zoom Out"
              onClick={() => setZoomLevel((z) => Math.max(z - 0.15, 0.6))}
            >
              −
            </button>
            <button type="button" className="zoom-btn reset-btn" title="Reset View" onClick={handleResetView}>
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* Infrastructure Telemetry Stats Ribbon */}
      <div className="threat-graph__telemetry-bar">
        <div className="telemetry-item">
          <span className="telemetry-label">Apex Domain</span>
          <span className="telemetry-value font-mono">{summary.registrar ? summary.registrar : (summary.domain_age_days !== undefined ? 'Identified' : 'Analyzing')}</span>
        </div>

        <div className="telemetry-item">
          <span className="telemetry-label">Domain Age</span>
          <span className={`telemetry-value ${summary.is_critically_young ? 'text-critical' : summary.is_recently_registered ? 'text-warning' : 'text-safe'}`}>
            {summary.domain_age_days !== null && summary.domain_age_days !== undefined
              ? `${summary.domain_age_days} days ${summary.is_critically_young ? '(! < 14d)' : summary.is_recently_registered ? '(Recent)' : ''}`
              : 'Unknown / Private'}
          </span>
        </div>

        <div className="telemetry-item">
          <span className="telemetry-label">Resolved IPs</span>
          <span className="telemetry-value">
            {summary.resolved_ips && summary.resolved_ips.length > 0 ? summary.resolved_ips.length : '0 (Offline/Unresolved)'}
            {summary.is_fast_flux && <span className="telemetry-subbadge">Fast-Flux</span>}
          </span>
        </div>

        <div className="telemetry-item">
          <span className="telemetry-label">SSRF Risk</span>
          <span className={`telemetry-value ${summary.ssrf_risk ? 'text-critical' : 'text-safe'}`}>
            {summary.ssrf_risk ? 'BLOCKED / PRIVATE' : 'Passed (Public)'}
          </span>
        </div>
      </div>

      {/* Threat Indicators List */}
      {threat_indicators.length > 0 && (
        <div className="threat-indicators-box">
          <div className="threat-indicators-title">Infrastructure Threat Indicators</div>
          <ul className="threat-indicators-list">
            {threat_indicators.map((ind, i) => (
              <li key={i}>{ind}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Main Canvas + Inspector Grid */}
      <div className="threat-graph__viewport-grid">
        <div
          className="threat-graph__canvas-container"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <svg
            ref={svgRef}
            className="threat-graph__svg"
            viewBox="0 0 760 480"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              <marker
                id="arrowhead"
                markerWidth="8"
                markerHeight="6"
                refX="20"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#64748b" />
              </marker>

              <marker
                id="arrowhead-threat"
                markerWidth="8"
                markerHeight="6"
                refX="20"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#fb7185" />
              </marker>

              <filter id="node-glow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="6" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            <g
              transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}
              style={{ transition: isDraggingRef.current ? 'none' : 'transform 0.15s ease' }}
            >
              {/* Edges */}
              {visibleEdges.map((edge) => {
                const sPos = nodePositions[edge.source]
                const tPos = nodePositions[edge.target]
                if (!sPos || !tPos) return null

                const isSelectedLink =
                  selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId)
                const isThreatEdge = edge.relationship === 'IMPERSONATES' || edge.relationship === 'TARGETS_BRAND'

                return (
                  <g key={edge.id} className="graph-edge-group">
                    <line
                      x1={sPos.x}
                      y1={sPos.y}
                      x2={tPos.x}
                      y2={tPos.y}
                      className={`graph-edge ${isSelectedLink ? 'selected' : ''} ${isThreatEdge ? 'threat' : ''}`}
                      markerEnd={isThreatEdge ? 'url(#arrowhead-threat)' : 'url(#arrowhead)'}
                    />
                    <text
                      x={(sPos.x + tPos.x) / 2}
                      y={(sPos.y + tPos.y) / 2 - 8}
                      className={`graph-edge-label ${isThreatEdge ? 'threat' : ''}`}
                      textAnchor="middle"
                    >
                      {edge.label}
                    </text>
                  </g>
                )
              })}

              {/* Nodes */}
              {visibleNodes.map((node) => {
                const pos = nodePositions[node.id]
                if (!pos) return null

                const isSelected = selectedNodeId === node.id
                const scheme = NODE_COLORS[node.type] || NODE_COLORS.url
                const isCritical = node.risk_level === 'critical'
                const radius = node.type === 'domain' || node.type === 'brand_target' ? 24 : 18

                return (
                  <g
                    key={node.id}
                    className={`graph-node ${isSelected ? 'selected' : ''} ${isCritical ? 'critical-pulse' : ''}`}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedNodeId(node.id)
                    }}
                  >
                    {/* Glow ring */}
                    <circle
                      r={radius + 6}
                      fill={scheme.glow}
                      opacity={isSelected ? 0.9 : isCritical ? 0.7 : 0.25}
                    />

                    {/* Main circle */}
                    <circle
                      r={radius}
                      fill={scheme.bg}
                      stroke={scheme.border}
                      strokeWidth={isSelected ? 3 : 2}
                      filter={isCritical || isSelected ? 'url(#node-glow)' : undefined}
                    />

                    {/* Node Type Indicator Icon Letter */}
                    <text
                      dy="4"
                      textAnchor="middle"
                      fill={scheme.text}
                      fontSize={radius > 20 ? 12 : 10}
                      fontWeight="bold"
                      fontFamily="var(--font-mono)"
                    >
                      {node.type === 'url'
                        ? 'URL'
                        : node.type === 'domain'
                        ? 'DOM'
                        : node.type === 'brand_target'
                        ? 'TARGET'
                        : node.type === 'ip'
                        ? 'IP'
                        : node.type === 'registrar'
                        ? 'REG'
                        : node.type === 'nameserver'
                        ? 'NS'
                        : 'HOST'}
                    </text>

                    {/* Node Label Below */}
                    <text
                      y={radius + 16}
                      textAnchor="middle"
                      className="graph-node-label"
                      fill="#cbd5e1"
                    >
                      {node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label}
                    </text>
                  </g>
                )
              })}
            </g>
          </svg>
        </div>

        {/* Forensic Node Inspector Panel */}
        <div className="threat-inspector-panel">
          <div className="inspector-header">
            <h4>Entity Inspector</h4>
            {selectedNode && (
              <span
                className="risk-tag"
                style={{ color: RISK_BADGES[selectedNode.risk_level]?.color || '#94a3b8' }}
              >
                {RISK_BADGES[selectedNode.risk_level]?.label || 'NEUTRAL'}
              </span>
            )}
          </div>

          {selectedNode ? (
            <div className="inspector-body">
              <div className="inspector-title-row">
                <span className="inspector-type-badge">{selectedNode.type.toUpperCase()}</span>
                <span className="inspector-label font-mono">{selectedNode.label}</span>
              </div>

              <div className="inspector-props-list">
                {Object.entries(selectedNode.properties || {}).map(([key, val]) => {
                  let formattedVal = val
                  if (typeof val === 'boolean') formattedVal = val ? 'Yes' : 'No'
                  if (Array.isArray(val)) formattedVal = val.length ? val.join(', ') : 'None'
                  if (val === null || val === undefined) formattedVal = '—'
                  if (typeof val === 'number' && key.includes('similarity')) {
                    formattedVal = `${Math.round(val * 100)}%`
                  }

                  return (
                    <div className="inspector-prop-row" key={key}>
                      <span className="prop-name">{key.replace(/_/g, ' ')}</span>
                      <span className="prop-val font-mono">{String(formattedVal)}</span>
                    </div>
                  )
                })}
              </div>

              {/* Connected Relationships */}
              <div className="inspector-relations">
                <span className="relations-title">Correlated Connections</span>
                <div className="relations-tags">
                  {edges
                    .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((e) => {
                      const otherId = e.source === selectedNode.id ? e.target : e.source
                      const otherNode = nodes.find((n) => n.id === otherId)
                      return (
                        <div
                          key={e.id}
                          className="relation-pill"
                          onClick={() => setSelectedNodeId(otherId)}
                          title={`Click to inspect ${otherNode?.label}`}
                        >
                          <span className="relation-rel">{e.label}</span>
                          <span className="relation-node-name">{otherNode?.label || otherId}</span>
                        </div>
                      )
                    })}
                </div>
              </div>
            </div>
          ) : (
            <div className="inspector-empty">Select a graph node to inspect forensic attributes.</div>
          )}
        </div>
      </div>
    </div>
  )
}
