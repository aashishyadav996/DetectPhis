import { useState } from 'react'
import RiskGauge from './components/RiskGauge.jsx'
import EvidencePanel from './components/EvidencePanel.jsx'
import SignalBreakdown from './components/SignalBreakdown.jsx'
import ThreatGraph from './components/ThreatGraph.jsx'
import AdversarialPanel from './components/AdversarialPanel.jsx'
import FileAnalysis from './components/FileAnalysis.jsx'
import EmailInvestigator from './components/EmailInvestigator.jsx'
import ScanHistory from './components/ScanHistory.jsx'
import './App.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const SAMPLE_URLS = [
  { label: 'PayPal Phish', url: 'paypa1-security-update.com/signin?verify=1' },
  { label: 'Netflix Billing', url: 'netflix-billing-verify.org/login' },
  { label: 'IP Host', url: '198.51.100.24/auth/account' },
  { label: 'Legitimate', url: 'https://google.com' },
]

export default function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('overview') // 'overview' | 'graph' | 'adversarial' | 'email-id' | 'upload' | 'features' | 'history'

  async function handleSubmit(e) {
    if (e && e.preventDefault) e.preventDefault()
    if (!url.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      })

      if (!response.ok) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || `Request failed (${response.status})`)
      }

      const data = await response.json()
      setResult(data)
      setActiveTab('overview')
    } catch (err) {
      setError(err.message || 'Something went wrong while analyzing this URL.')
    } finally {
      setLoading(false)
    }
  }

  function handleSelectSample(sampleUrl) {
    setUrl(sampleUrl)
  }

  function handleSelectHistoricalScan(scanDetails) {
    setResult(scanDetails)
    if (scanDetails && scanDetails.normalized_url) {
      setUrl(scanDetails.normalized_url)
    }
    setActiveTab('overview')
  }

  function handleOpenCertifiedReport() {
    if (result && result.scan_id) {
      window.open(`${API_BASE_URL}/api/v1/reports/${result.scan_id}/html`, '_blank')
    } else if (result) {
      // Direct live generation
      fetch(`${API_BASE_URL}/api/v1/reports/export/html`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: result.normalized_url,
          normalized_url: result.normalized_url,
          risk_score: result.risk_score,
          confidence: result.confidence,
          classification: result.classification,
          domain: result.features?.domain,
          details: result,
        }),
      })
        .then((res) => res.text())
        .then((html) => {
          const win = window.open('', '_blank')
          win.document.write(html)
          win.document.close()
        })
        .catch(() => alert('Could not generate live report.'))
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header__brand">
          <span className="app-header__mark" aria-hidden="true" />
          <div>
            <h1>PhishTrace AI</h1>
            <p>Explainable multi-signal phishing URL investigation platform</p>
          </div>
        </div>
        <span className="app-header__status">
          <span className="app-header__status-dot" aria-hidden="true" />
          Production Full Build — Phases 1 to 6 Active
        </span>
      </header>

      <main className="app-main">
        <form className="scan-form" onSubmit={handleSubmit}>
          <label htmlFor="url-input" className="scan-form__label">
            Enter a URL to investigate
          </label>
          <div className="scan-form__row">
            <input
              id="url-input"
              type="text"
              placeholder="e.g. paypa1-login-security.com/verify"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
            <button type="submit" disabled={loading}>
              {loading ? 'Analyzing…' : 'Investigate'}
            </button>
          </div>

          <div className="scan-form__samples">
            <span className="scan-form__samples-label">Quick Test:</span>
            {SAMPLE_URLS.map((sample) => (
              <button
                key={sample.label}
                type="button"
                className="sample-pill"
                onClick={() => handleSelectSample(sample.url)}
              >
                {sample.label}
              </button>
            ))}
          </div>
        </form>

        {error && (
          <div className="app-alert" role="alert">
            Could not complete the analysis: {error}
          </div>
        )}

        {/* Global Navigation Tabs */}
        <div className="results-nav">
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview & Risk
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'graph' ? 'active' : ''}`}
            onClick={() => setActiveTab('graph')}
            disabled={!result}
          >
            Threat Graph
            {result?.threat_graph?.nodes?.length ? (
              <span className="nav-tab-badge">{result.threat_graph.nodes.length}</span>
            ) : null}
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'adversarial' ? 'active' : ''}`}
            onClick={() => setActiveTab('adversarial')}
          >
            Adversarial Testing
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'email-id' ? 'active' : ''}`}
            onClick={() => setActiveTab('email-id')}
          >
            @ Email ID
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'upload' ? 'active' : ''}`}
            onClick={() => setActiveTab('upload')}
          >
            Email & File
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'features' ? 'active' : ''}`}
            onClick={() => setActiveTab('features')}
            disabled={!result}
          >
            Forensic Features
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            Audit History
          </button>
        </div>

        {/* TAB 1: OVERVIEW & RISK */}
        {activeTab === 'overview' && result && (
          <section className="results">
            <div className="results__summary card">
              <RiskGauge score={result.risk_score} classification={result.classification} />
              <div className="results__summary-body">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <p className="results__url" style={{ margin: 0, flex: 1 }}>{result.normalized_url}</p>
                  <button
                    type="button"
                    className="report-export-btn"
                    onClick={handleOpenCertifiedReport}
                    title="Export certified forensic report to printable HTML / PDF"
                  >
                    Export Forensic Report ↗
                  </button>
                </div>

                <div className="confidence-row" style={{ marginTop: '14px' }}>
                  <span className="confidence-row__label">Confidence</span>
                  <div className="confidence-row__track">
                    <div className="confidence-row__fill" style={{ width: `${result.confidence}%` }} />
                  </div>
                  <span className="confidence-row__value">{result.confidence}%</span>
                </div>

                {result.reputation_gap_warning && (
                  <p className="reputation-gap-note">
                    Low-reputation early warning: reputation data alone is not sufficient here — see reasons below.
                  </p>
                )}

                <h3 className="results__reasons-title">Risk-increasing factors</h3>
                <ul className="results__reasons results__reasons--up">
                  {result.reasons_increasing.map((reason, i) => (
                    <li key={i}>{reason}</li>
                  ))}
                </ul>

                {result.reasons_decreasing.length > 0 && (
                  <>
                    <h3 className="results__reasons-title">Risk-reducing factors</h3>
                    <ul className="results__reasons results__reasons--down">
                      {result.reasons_decreasing.map((reason, i) => (
                        <li key={i}>{reason}</li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            </div>

            <div className="results__grid">
              <div className="card">
                <SignalBreakdown contributions={result.signal_contributions} />
              </div>
              <div className="card">
                <EvidencePanel features={result.features} />
              </div>
            </div>

            <div className="results__grid">
              <div className="card evidence-mini">
                <h3 className="evidence-panel__title">Brand Impersonation</h3>
                {result.brand_analysis?.detected_brand ? (
                  <>
                    <p className="evidence-mini__headline">{result.brand_analysis.detected_brand}</p>
                    <p className="evidence-mini__detail">
                      Risk: {result.brand_analysis.impersonation_risk} · Similarity: {Math.round(result.brand_analysis.similarity_score * 100)}%
                    </p>
                    <p className="evidence-mini__detail">{result.brand_analysis.technique}</p>
                  </>
                ) : (
                  <p className="evidence-mini__detail">No known brand impersonation detected.</p>
                )}
              </div>

              <div className="card evidence-mini">
                <h3 className="evidence-panel__title">VirusTotal</h3>
                {result.virustotal?.available ? (
                  <p className="evidence-mini__detail">
                    {result.virustotal.malicious_count}/{result.virustotal.total_engines} engines flagged this URL as malicious.
                  </p>
                ) : (
                  <p className="evidence-mini__detail">{result.virustotal?.error || 'Unavailable'}</p>
                )}
              </div>

              <div className="card evidence-mini">
                <h3 className="evidence-panel__title">ML Prediction</h3>
                {result.ml?.available ? (
                  <p className="evidence-mini__detail">
                    {result.ml.model_name}: {Math.round(result.ml.phishing_probability * 100)}% phishing probability
                  </p>
                ) : (
                  <p className="evidence-mini__detail">{result.ml?.error || 'Unavailable'}</p>
                )}
              </div>
            </div>
          </section>
        )}

        {/* TAB 2: THREAT GRAPH */}
        {activeTab === 'graph' && result && (
          <ThreatGraph graphData={result.threat_graph} />
        )}

        {/* TAB 3: ADVERSARIAL MUTATION TESTING */}
        {activeTab === 'adversarial' && (
          <AdversarialPanel targetUrl={result?.normalized_url || url} />
        )}

        {/* TAB 4: EMAIL ADDRESS INVESTIGATOR */}
        {activeTab === 'email-id' && (
          <EmailInvestigator />
        )}

        {/* TAB 5: EMAIL & FILE ANALYSIS */}
        {activeTab === 'upload' && (
          <FileAnalysis />
        )}

        {/* TAB 5: FORENSIC FEATURES */}
        {activeTab === 'features' && result && (
          <div className="card">
            <EvidencePanel features={result.features} />
          </div>
        )}

        {/* TAB 6: AUDIT HISTORY */}
        {activeTab === 'history' && (
          <ScanHistory onSelectScan={handleSelectHistoricalScan} currentScanId={result?.scan_id} />
        )}

        {!result && !error && !loading && activeTab === 'overview' && (
          <div className="empty-state">
            <p>No investigation active. Enter a URL above or click a Quick Test sample to see the multi-signal risk breakdown and threat graph.</p>
          </div>
        )}
      </main>
    </div>
  )
}
