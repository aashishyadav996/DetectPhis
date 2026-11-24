import { useState, useEffect } from 'react'
import './ScanHistory.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export default function ScanHistory({ onSelectScan, currentScanId }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function fetchHistory() {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/history?limit=30`)
      if (!response.ok) throw new Error('Could not load scan history.')
      const data = await response.json()
      setHistory(data)
    } catch (err) {
      setError(err.message || 'Error fetching history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [currentScanId])

  async function handleClearHistory() {
    if (!window.confirm('Clear all stored investigation records?')) return
    try {
      await fetch(`${API_BASE_URL}/api/v1/history`, { method: 'DELETE' })
      setHistory([])
    } catch (err) {
      setError('Could not clear history.')
    }
  }

  function handleOpenReport(scanId) {
    window.open(`${API_BASE_URL}/api/v1/reports/${scanId}/html`, '_blank')
  }

  return (
    <div className="scan-history card">
      <div className="scan-history__header">
        <div>
          <div className="history-title-row">
            <h3 className="scan-history__title">Investigation History & Reports</h3>
            <span className="history-count-badge">{history.length} Saved Scans</span>
          </div>
          <p className="scan-history__subtitle">
            Persistent audit trail of previously analyzed URLs. Click any scan to load its multi-signal graph or export a certified forensic report.
          </p>
        </div>

        <div className="history-actions">
          <button type="button" className="refresh-btn" onClick={fetchHistory} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
          {history.length > 0 && (
            <button type="button" className="clear-btn" onClick={handleClearHistory}>
              Clear History
            </button>
          )}
        </div>
      </div>

      {error && <div className="app-alert">{error}</div>}

      {history.length > 0 ? (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Target URL</th>
                <th>Brand Target</th>
                <th>Domain Age</th>
                <th>Timestamp</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => {
                const isHigh = item.classification === 'HIGH RISK'
                const isSuspicious = item.classification === 'SUSPICIOUS'

                return (
                  <tr key={item.id} className={item.id === currentScanId ? 'active-row' : ''}>
                    <td>
                      <span
                        className={`history-verdict-badge ${
                          isHigh ? 'risk-high' : isSuspicious ? 'risk-suspicious' : 'risk-low'
                        }`}
                      >
                        {item.classification} ({item.risk_score})
                      </span>
                    </td>
                    <td className="history-url font-mono" title={item.normalized_url}>
                      {item.normalized_url}
                    </td>
                    <td>{item.detected_brand || '—'}</td>
                    <td className="font-mono">
                      {item.domain_age_days !== null && item.domain_age_days !== undefined
                        ? `${item.domain_age_days}d`
                        : '—'}
                    </td>
                    <td className="history-time font-mono">
                      {item.created_at ? item.created_at.slice(0, 16).replace('T', ' ') : '—'}
                    </td>
                    <td className="history-buttons">
                      <button
                        type="button"
                        className="history-action-btn load"
                        onClick={() => onSelectScan({ ...item.details, scan_id: item.id })}
                      >
                        Inspect
                      </button>
                      <button
                        type="button"
                        className="history-action-btn report"
                        onClick={() => handleOpenReport(item.id)}
                        title="Print / View certified HTML forensic report"
                      >
                        Report ↗
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        !loading && (
          <div className="history-empty">
            <p>No scans recorded yet. Submit a URL to start building an investigation history.</p>
          </div>
        )
      )}
    </div>
  )
}
