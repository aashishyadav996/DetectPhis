import { useState } from 'react'
import './AdversarialPanel.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export default function AdversarialPanel({ targetUrl, initialReport }) {
  const [report, setReport] = useState(initialReport || null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleRunTest() {
    if (!targetUrl) return
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/adversarial/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      })

      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Adversarial test failed (${response.status})`)
      }

      const data = await response.json()
      setReport(data)
    } catch (err) {
      setError(err.message || 'Failed to complete adversarial mutation evaluation.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="adversarial-panel card">
      <div className="adversarial-panel__header">
        <div>
          <div className="adversarial-title-row">
            <h3 className="adversarial-panel__title">Adversarial URL Mutation Testing</h3>
            <span className="adversarial-badge">Phase 5 Evasion Simulation</span>
          </div>
          <p className="adversarial-panel__subtitle">
            Simulates attacker evasion techniques (homoglyph spoofing, typosquatting, subdomain masquerading, userinfo destination masking) to evaluate engine resilience.
          </p>
        </div>

        <button
          type="button"
          className="run-test-btn"
          onClick={handleRunTest}
          disabled={loading || !targetUrl}
        >
          {loading ? 'Simulating Mutations…' : 'Run Evasion Test Suite'}
        </button>
      </div>

      {error && <div className="app-alert">{error}</div>}

      {report && (
        <div className="adversarial-results">
          {/* Resilience Score Gauge Card */}
          <div className="resilience-summary-card">
            <div className="resilience-score-box">
              <span className="resilience-score-val">{report.resilience_rate_percent}%</span>
              <span className="resilience-score-label">Engine Resilience</span>
            </div>

            <div className="resilience-stats-grid">
              <div className="stat-pill">
                <span className="stat-num text-safe">{report.detected_count}</span>
                <span className="stat-desc">Mutations Flagged</span>
              </div>
              <div className="stat-pill">
                <span className="stat-num text-danger">{report.evaded_count}</span>
                <span className="stat-desc">Evasion Blind Spots</span>
              </div>
              <div className="stat-pill">
                <span className="stat-num">{report.total_mutations}</span>
                <span className="stat-desc">Variants Tested</span>
              </div>
              <div className="stat-pill">
                <span className="stat-num font-mono">{report.baseline_risk_score}</span>
                <span className="stat-desc">Baseline Risk Score</span>
              </div>
            </div>
          </div>

          {/* Actionable Vulnerability Summary */}
          {report.vulnerability_summary && report.vulnerability_summary.length > 0 && (
            <div className="vulnerability-box">
              <h4 className="vulnerability-title">Security Resilience Findings</h4>
              <ul className="vulnerability-list">
                {report.vulnerability_summary.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Mutations Table / Cards */}
          <div className="mutations-list">
            <h4 className="mutations-header">Evaluated Evasion Variants</h4>
            {report.mutations.map((mut, idx) => {
              const isDetected = mut.detected

              return (
                <div key={idx} className={`mutation-card ${isDetected ? 'caught' : 'evaded'}`}>
                  <div className="mutation-card__top">
                    <div className="mutation-tech-badge">{mut.technique}</div>
                    <div className="mutation-status-badge">
                      {isDetected ? (
                        <span className="status-caught">FLAGGED ({mut.risk_score} / 100)</span>
                      ) : (
                        <span className="status-evaded">EVADED ({mut.risk_score} / 100)</span>
                      )}
                    </div>
                  </div>

                  <div className="mutation-url-box font-mono">{mut.mutated_url}</div>
                  <p className="mutation-desc">{mut.description}</p>

                  <div className="mutation-factors">
                    <span className="factors-label">Triggered Signals:</span>
                    <span className="factors-text">{mut.key_factors.join(' · ')}</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {!report && !loading && (
        <div className="adversarial-empty">
          <p>
            Click <strong>"Run Evasion Test Suite"</strong> above to generate 8 adversarial variants of{' '}
            <code className="font-mono">{targetUrl || 'the active URL'}</code> and benchmark the detection engine.
          </p>
        </div>
      )}
    </div>
  )
}
