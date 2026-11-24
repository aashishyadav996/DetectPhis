import { useState } from 'react'
import './FileAnalysis.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const SAMPLE_EMAILS = [
  { label: 'PayPal Spoof', email: 'security@paypa1-login.com' },
  { label: 'Disposable Mail', email: 'victim@mailinator.com' },
  { label: 'Auto-Generated', email: 'admin123456@tempmail.com' },
  { label: 'Legitimate Gmail', email: 'john.doe@gmail.com' },
]

export default function FileAnalysis() {
  const [analysisType, setAnalysisType] = useState('email-id') // 'email-id' | 'email' | 'file'
  const [emailInput, setEmailInput] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [fileName, setFileName] = useState('')

  async function handleEmailIdSubmit(e) {
    if (e && e.preventDefault) e.preventDefault()
    const trimmed = emailInput.trim()
    if (!trimmed) {
      setError('Please enter an Email ID / address.')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/analyze/email-address`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: trimmed }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`)
      setResult(data)
    } catch (err) {
      setError(err.message || 'Investigation failed.')
    } finally {
      setLoading(false)
    }
  }

  async function handleFileUpload(e) {
    e.preventDefault()
    const fileInput = e.target.querySelector('input[type="file"]')
    if (!fileInput || !fileInput.files.length) {
      setError('Please select a file to upload.')
      return
    }

    const file = fileInput.files[0]
    setLoading(true)
    setError(null)
    setResult(null)
    setFileName(file.name)

    const formData = new FormData()
    formData.append('file', file)

    const endpoint =
      analysisType === 'email'
        ? `${API_BASE_URL}/api/v1/analyze/email`
        : `${API_BASE_URL}/api/v1/analyze/file`

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Request failed (${res.status})`)
      }

      const data = await res.json()
      setResult(data)
    } catch (err) {
      setError(err.message || 'Upload failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="file-analysis card">
      <div className="file-analysis__header">
        <div>
          <div className="file-analysis__title-row">
            <h3 className="file-analysis__title">Email &amp; File Forensics</h3>
            <span className="file-analysis__badge">Phase 6 Forensic Analysis</span>
          </div>
          <p className="file-analysis__subtitle">
            Investigate suspicious Email IDs (addresses), parse raw <strong>.eml</strong> email messages for spoofing &amp; link extraction, or calculate cryptographic file hashes.
          </p>
        </div>
      </div>

      <div className="file-analysis__type-selector">
        <button
          type="button"
          className={`type-btn ${analysisType === 'email-id' ? 'active' : ''}`}
          onClick={() => { setAnalysisType('email-id'); setResult(null); setError(null) }}
        >
          <span className="type-btn__icon">@</span>
          Email ID (@ Address)
        </button>
        <button
          type="button"
          className={`type-btn ${analysisType === 'email' ? 'active' : ''}`}
          onClick={() => { setAnalysisType('email'); setResult(null); setError(null) }}
        >
          <span className="type-btn__icon">✉</span>
          Email (.eml) File
        </button>
        <button
          type="button"
          className={`type-btn ${analysisType === 'file' ? 'active' : ''}`}
          onClick={() => { setAnalysisType('file'); setResult(null); setError(null) }}
        >
          <span className="type-btn__icon">📄</span>
          Generic File
        </button>
      </div>

      {/* Mode 1: Email ID Form */}
      {analysisType === 'email-id' && (
        <form className="file-analysis__form" onSubmit={handleEmailIdSubmit}>
          <div className="file-analysis__upload-row">
            <input
              type="text"
              placeholder="e.g. security@paypa1-login.com or victim@mailinator.com"
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              className="email-id-direct-input"
              style={{
                flex: 1,
                padding: '12px 14px',
                background: '#0d1117',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontFamily: 'monospace',
                fontSize: '0.88rem',
              }}
            />
            <button type="submit" className="upload-submit-btn" disabled={loading}>
              {loading ? 'Investigating…' : 'Investigate Email ID'}
            </button>
          </div>
          <div className="ei-samples" style={{ marginTop: '10px', display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>Quick Test:</span>
            {SAMPLE_EMAILS.map((s) => (
              <button
                key={s.label}
                type="button"
                className="sample-pill"
                style={{ fontSize: '0.72rem', padding: '3px 8px' }}
                onClick={() => { setEmailInput(s.email); }}
              >
                {s.label}
              </button>
            ))}
          </div>
        </form>
      )}

      {/* Mode 2 & 3: File Upload Form */}
      {analysisType !== 'email-id' && (
        <form className="file-analysis__form" onSubmit={handleFileUpload}>
          <div className="file-analysis__upload-row">
            <label className="file-upload-zone">
              <input
                type="file"
                accept={analysisType === 'email' ? '.eml,.msg,.txt' : '*/*'}
                className="file-upload-input"
              />
              <span className="file-upload-zone__text">
                {analysisType === 'email'
                  ? 'Choose .eml email file…'
                  : 'Choose file to scan…'
                }
              </span>
            </label>
            <button type="submit" className="upload-submit-btn" disabled={loading}>
              {loading ? 'Analyzing…' : 'Upload & Analyze'}
            </button>
          </div>
        </form>
      )}

      {error && (
        <div className="file-analysis__alert" role="alert">
          {error}
        </div>
      )}

      {/* Email ID Analysis Results */}
      {result && analysisType === 'email-id' && (
        <div className="file-analysis__results">
          <h4 className="results-section-title">Email ID Forensics — {result.email}</h4>

          <div className="email-headers-card" style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
              <div>
                <span style={{ fontSize: '1.1rem', fontWeight: '700', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                  {result.email}
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <span
                  style={{
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontWeight: '700',
                    fontSize: '0.76rem',
                    background: result.risk_score >= 70 ? 'rgba(255,92,108,0.15)' : result.risk_score >= 40 ? 'rgba(255,184,77,0.15)' : 'rgba(72,199,116,0.15)',
                    color: result.risk_score >= 70 ? '#ff7a85' : result.risk_score >= 40 ? '#ffc247' : '#48c774',
                    border: '1px solid currentColor',
                  }}
                >
                  {result.risk_level} RISK ({result.risk_score}/100)
                </span>
              </div>
            </div>

            <dl className="email-headers-grid">
              <div className="header-row">
                <dt>Local Part</dt>
                <dd className="font-mono">{result.local_part || '—'}</dd>
              </div>
              <div className="header-row">
                <dt>Domain</dt>
                <dd className="font-mono">{result.domain || '—'}</dd>
              </div>
              <div className="header-row">
                <dt>MX Server</dt>
                <dd className="font-mono" style={{ color: result.dns?.has_mx ? '#48c774' : '#ff5c6c' }}>
                  {result.dns?.has_mx ? `Active (${result.dns.mx_records[0] || 'MX OK'})` : 'No MX Found'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Domain Age</dt>
                <dd className="font-mono">
                  {result.domain_info?.domain_age_days != null ? `${result.domain_info.domain_age_days} days` : 'Private / Unverified'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Disposable</dt>
                <dd className="font-mono" style={{ color: result.domain_info?.is_disposable ? '#ff5c6c' : '#48c774' }}>
                  {result.domain_info?.is_disposable ? 'Yes (Temporary Mail)' : 'No'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Brand Impersonation</dt>
                <dd className="font-mono" style={{ color: result.brand_analysis?.detected_brand ? '#ff5c6c' : 'inherit' }}>
                  {result.brand_analysis?.detected_brand ? `Targeting ${result.brand_analysis.detected_brand}` : 'None Detected'}
                </dd>
              </div>
            </dl>
          </div>

          {result.reasons_increasing && result.reasons_increasing.length > 0 && (
            <div className="email-urls-card" style={{ marginBottom: '16px' }}>
              <h5 className="subsection-title">Risk-Increasing Indicators</h5>
              <ul className="urls-list">
                {result.reasons_increasing.map((r, i) => (
                  <li key={i} className="url-item" style={{ color: '#ff7a85' }}>⚠️ {r}</li>
                ))}
              </ul>
            </div>
          )}

          {result.reasons_decreasing && result.reasons_decreasing.length > 0 && (
            <div className="email-urls-card">
              <h5 className="subsection-title">Positive Trust Signals</h5>
              <ul className="urls-list">
                {result.reasons_decreasing.map((r, i) => (
                  <li key={i} className="url-item" style={{ color: '#48c774' }}>✅ {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Email File Analysis Results */}
      {result && analysisType === 'email' && (
        <div className="file-analysis__results">
          <h4 className="results-section-title">Email File Investigation — {fileName}</h4>

          {/* Headers */}
          <div className="email-headers-card">
            <h5 className="subsection-title">Extracted Email IDs &amp; Headers</h5>
            <dl className="email-headers-grid">
              <div className="header-row">
                <dt>Sender Email ID</dt>
                <dd className="font-mono" style={{ color: '#38bdf8', fontWeight: '700' }}>
                  {result.headers?.from_email_id || result.sender_analysis?.from_address || result.headers?.from || '—'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Recipient Email ID</dt>
                <dd className="font-mono">
                  {result.headers?.to_email_id || result.headers?.to || '—'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Reply-To Email ID</dt>
                <dd className="font-mono">
                  {result.headers?.reply_to_email_id || result.sender_analysis?.reply_to || 'Same as Sender'}
                </dd>
              </div>
              <div className="header-row">
                <dt>Message-ID</dt>
                <dd className="font-mono">{result.headers?.message_id || '—'}</dd>
              </div>
              <div className="header-row">
                <dt>Subject</dt>
                <dd>{result.headers?.subject || '—'}</dd>
              </div>
              <div className="header-row">
                <dt>Date</dt>
                <dd>{result.headers?.date || '—'}</dd>
              </div>
            </dl>
          </div>

          {/* Sender Email ID Forensics */}
          {result.sender_email_id_investigation && (
            <div className="email-headers-card" style={{ marginTop: '14px', borderLeft: '3px solid #38bdf8' }}>
              <h5 className="subsection-title">Sender Email ID Live Threat Intelligence</h5>
              <dl className="email-headers-grid">
                <div className="header-row">
                  <dt>Sender ID Score</dt>
                  <dd className="font-mono" style={{ fontWeight: '700', color: result.sender_email_id_investigation.risk_score >= 70 ? '#ff5c6c' : '#48c774' }}>
                    {result.sender_email_id_investigation.risk_score}/100 ({result.sender_email_id_investigation.risk_level})
                  </dd>
                </div>
                <div className="header-row">
                  <dt>Mail Server (MX)</dt>
                  <dd className="font-mono">
                    {result.sender_email_id_investigation.dns?.has_mx ? 'Verified Active' : 'No MX Record'}
                  </dd>
                </div>
                <div className="header-row">
                  <dt>Domain History</dt>
                  <dd className="font-mono">
                    {result.sender_email_id_investigation.domain_info?.domain_age_days != null
                      ? `${result.sender_email_id_investigation.domain_info.domain_age_days} days`
                      : 'Unverified'}
                  </dd>
                </div>
                <div className="header-row">
                  <dt>Disposable / Burner</dt>
                  <dd className="font-mono">
                    {result.sender_email_id_investigation.domain_info?.is_disposable ? 'Yes (High Threat)' : 'No'}
                  </dd>
                </div>
              </dl>
            </div>
          )}

          {/* Extracted URLs */}
          <div className="email-urls-card" style={{ marginTop: '14px' }}>
            <h5 className="subsection-title">
              Embedded URLs ({result.extracted_urls?.length || 0})
            </h5>
            {result.extracted_urls && result.extracted_urls.length > 0 ? (
              <ul className="urls-list">
                {result.extracted_urls.map((url, i) => (
                  <li key={i} className="url-item font-mono">{url}</li>
                ))}
              </ul>
            ) : (
              <p className="empty-note">No URLs found in email body.</p>
            )}
          </div>

          {/* Auto-analyzed URL result */}
          {result.url_analysis && !result.url_analysis.error && (
            <div className="email-url-verdict" style={{ marginTop: '14px' }}>
              <h5 className="subsection-title">First URL — Auto-Scan Verdict</h5>
              <div className="url-verdict-grid">
                <div className="verdict-stat">
                  <span className="verdict-stat__label">Target URL</span>
                  <span className="verdict-stat__value font-mono">
                    {result.url_analysis.normalized_url || result.url_analysis.url}
                  </span>
                </div>
                <div className="verdict-stat">
                  <span className="verdict-stat__label">Risk Score</span>
                  <span
                    className="verdict-stat__value verdict-score"
                    style={{
                      color:
                        result.url_analysis.risk_score >= 70
                          ? 'var(--risk-high)'
                          : result.url_analysis.risk_score >= 45
                          ? 'var(--risk-suspicious)'
                          : 'var(--risk-low)',
                    }}
                  >
                    {result.url_analysis.risk_score} / 100
                  </span>
                </div>
                <div className="verdict-stat">
                  <span className="verdict-stat__label">Classification</span>
                  <span className="verdict-stat__value">{result.url_analysis.classification}</span>
                </div>
              </div>
            </div>
          )}

          {/* Body Preview */}
          {result.body_preview && (
            <div className="email-body-preview" style={{ marginTop: '14px' }}>
              <h5 className="subsection-title">Body Preview</h5>
              <pre className="body-preview-text">{result.body_preview}</pre>
            </div>
          )}
        </div>
      )}

      {/* File Analysis Results */}
      {result && analysisType === 'file' && (
        <div className="file-analysis__results">
          <h4 className="results-section-title">File Scan — {fileName}</h4>

          <div className="file-meta-grid">
            <div className="file-meta-item">
              <span className="file-meta-label">Filename</span>
              <span className="file-meta-value font-mono">{result.filename}</span>
            </div>
            <div className="file-meta-item">
              <span className="file-meta-label">Extension</span>
              <span className="file-meta-value font-mono">{result.extension || '—'}</span>
            </div>
            <div className="file-meta-item">
              <span className="file-meta-label">Size</span>
              <span className="file-meta-value font-mono">
                {result.size_bytes != null
                  ? result.size_bytes < 1024
                    ? `${result.size_bytes} B`
                    : result.size_bytes < 1048576
                    ? `${(result.size_bytes / 1024).toFixed(1)} KB`
                    : `${(result.size_bytes / 1048576).toFixed(2)} MB`
                  : '—'
                }
              </span>
            </div>
            <div className="file-meta-item">
              <span className="file-meta-label">Classification</span>
              <span className="file-meta-value">{result.classification || 'Unknown'}</span>
            </div>
          </div>

          {result.hashes && (
            <div className="file-hashes-card">
              <h5 className="subsection-title">Cryptographic Hashes</h5>
              <dl className="hash-grid">
                <div className="hash-row">
                  <dt>MD5</dt>
                  <dd className="font-mono">{result.hashes.md5}</dd>
                </div>
                <div className="hash-row">
                  <dt>SHA-1</dt>
                  <dd className="font-mono">{result.hashes.sha1}</dd>
                </div>
                <div className="hash-row">
                  <dt>SHA-256</dt>
                  <dd className="font-mono">{result.hashes.sha256}</dd>
                </div>
              </dl>
            </div>
          )}

          {result.message && (
            <p className="file-analysis__note">{result.message}</p>
          )}
        </div>
      )}

      {/* Empty State */}
      {!result && !loading && !error && (
        <div className="file-analysis__empty">
          <p>
            {analysisType === 'email-id'
              ? 'Enter an Email ID above and click Investigate to check reputation, domain age & delivery records.'
              : 'Select an analysis type above, choose a file, and click Upload & Analyze to begin investigation.'}
          </p>
        </div>
      )}
    </div>
  )
}
