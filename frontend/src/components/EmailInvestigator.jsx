import { useState } from 'react'
import './EmailInvestigator.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const SAMPLE_EMAILS = [
  { label: 'Disposable', email: 'victim@mailinator.com' },
  { label: 'PayPal Spoof', email: 'security@paypa1-login.com' },
  { label: 'Auto-generated', email: 'ab123456@tempmail.com' },
  { label: 'Legit Gmail', email: 'john.doe@gmail.com' },
]

function RiskBadge({ level }) {
  const colors = {
    HIGH:       { bg: 'rgba(255,92,108,0.12)', border: 'rgba(255,92,108,0.4)', text: '#ff7a85' },
    SUSPICIOUS: { bg: 'rgba(255,184,77,0.12)',  border: 'rgba(255,184,77,0.4)',  text: '#ffc247' },
    LOW:        { bg: 'rgba(79,209,197,0.1)',   border: 'rgba(79,209,197,0.35)', text: '#4fd1c5' },
    SAFE:       { bg: 'rgba(72,199,116,0.1)',   border: 'rgba(72,199,116,0.35)', text: '#48c774' },
  }
  const c = colors[level] || colors.LOW
  return (
    <span className="ei-risk-badge" style={{ background: c.bg, border: `1px solid ${c.border}`, color: c.text }}>
      {level}
    </span>
  )
}

function ScoreArc({ score }) {
  const radius = 52
  const circ   = 2 * Math.PI * radius
  const arc    = circ * 0.75            // 270° arc
  const filled = arc * (score / 100)
  const color  = score >= 70 ? '#ff5c6c' : score >= 40 ? '#ffb84d' : score >= 20 ? '#4fd1c5' : '#48c774'

  return (
    <svg viewBox="0 0 120 120" className="ei-score-arc" aria-label={`Risk score ${score} out of 100`}>
      {/* track */}
      <circle cx="60" cy="60" r={radius}
        fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"
        strokeDasharray={`${arc} ${circ}`}
        strokeDashoffset={0}
        strokeLinecap="round"
        transform="rotate(135 60 60)"
      />
      {/* fill */}
      <circle cx="60" cy="60" r={radius}
        fill="none" stroke={color} strokeWidth="10"
        strokeDasharray={`${filled} ${circ}`}
        strokeDashoffset={0}
        strokeLinecap="round"
        transform="rotate(135 60 60)"
        style={{ filter: `drop-shadow(0 0 6px ${color}88)`, transition: 'stroke-dasharray 0.7s cubic-bezier(.16,1,.3,1)' }}
      />
      <text x="60" y="55" textAnchor="middle" fill={color} fontSize="20" fontWeight="700" fontFamily="monospace">{score}</text>
      <text x="60" y="72" textAnchor="middle" fill="rgba(255,255,255,0.4)" fontSize="9" fontFamily="monospace">/ 100</text>
    </svg>
  )
}

export default function EmailInvestigator() {
  const [email, setEmail]   = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState(null)

  async function handleSubmit(e) {
    e.preventDefault()
    const trimmed = email.trim()
    if (!trimmed) return

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
      if (!res.ok) throw new Error(data.description || data.detail || `Error ${res.status}`)
      setResult(data)
    } catch (err) {
      setError(err.message || 'Investigation failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="ei-card card">
      {/* Header */}
      <div className="ei-header">
        <div className="ei-header__icon">@</div>
        <div>
          <div className="ei-header__title-row">
            <h3 className="ei-header__title">Email Address Investigator</h3>
            <span className="ei-badge">New</span>
          </div>
          <p className="ei-header__sub">
            Investigate any email address for phishing indicators — DNS verification, domain age,
            disposable/free provider detection, brand impersonation &amp; suspicious pattern analysis.
          </p>
        </div>
      </div>

      {/* Form */}
      <form className="ei-form" onSubmit={handleSubmit}>
        <div className="ei-form__row">
          <input
            id="email-id-input"
            type="text"
            className="ei-form__input"
            placeholder="e.g. security@paypa1-verify.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="off"
            spellCheck="false"
          />
          <button type="submit" className="ei-form__btn" disabled={loading}>
            {loading ? 'Investigating…' : 'Investigate'}
          </button>
        </div>

        {/* Sample pills */}
        <div className="ei-samples">
          <span className="ei-samples__label">Quick Test:</span>
          {SAMPLE_EMAILS.map((s) => (
            <button
              key={s.label}
              type="button"
              className="ei-sample-pill"
              onClick={() => setEmail(s.email)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="ei-alert" role="alert">{error}</div>
      )}

      {/* Results */}
      {result && (
        <div className="ei-results">

          {/* Score + verdict hero */}
          <div className="ei-hero">
            <ScoreArc score={result.risk_score} />
            <div className="ei-hero__info">
              <div className="ei-hero__email">{result.email}</div>
              <div className="ei-hero__level">
                <RiskBadge level={result.risk_level} />
                {!result.valid_format && (
                  <span className="ei-invalid-tag">Invalid Format</span>
                )}
              </div>
              {result.domain_info && (
                <div className="ei-hero__tags">
                  {result.domain_info.is_disposable && <span className="ei-tag ei-tag--red">Disposable</span>}
                  {result.domain_info.is_free_provider && !result.domain_info.is_disposable && (
                    <span className="ei-tag ei-tag--yellow">Free Provider</span>
                  )}
                  {result.domain_info.is_recently_registered && (
                    <span className="ei-tag ei-tag--orange">New Domain</span>
                  )}
                  {result.brand_analysis?.detected_brand && (
                    <span className="ei-tag ei-tag--red">Brand Spoof: {result.brand_analysis.detected_brand}</span>
                  )}
                  {!result.dns?.has_mx && result.valid_format && (
                    <span className="ei-tag ei-tag--red">No MX Record</span>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Reasons grid */}
          <div className="ei-reasons-grid">
            {result.reasons_increasing?.length > 0 && (
              <div className="ei-reasons ei-reasons--up">
                <h5 className="ei-reasons__title">⚠ Risk-Increasing Factors</h5>
                <ul>
                  {result.reasons_increasing.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
            {result.reasons_decreasing?.length > 0 && (
              <div className="ei-reasons ei-reasons--down">
                <h5 className="ei-reasons__title">✓ Risk-Reducing Factors</h5>
                <ul>
                  {result.reasons_decreasing.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </div>

          {/* Detail cards */}
          <div className="ei-details-grid">

            {/* DNS */}
            <div className="ei-detail-card">
              <h5 className="ei-detail-card__title">DNS Records</h5>
              <dl className="ei-dl">
                <div className="ei-dl__row">
                  <dt>MX Records</dt>
                  <dd className={result.dns?.has_mx ? 'ei-ok' : 'ei-bad'}>
                    {result.dns?.has_mx
                      ? result.dns.mx_records.join(', ')
                      : 'None found'}
                  </dd>
                </div>
                <div className="ei-dl__row">
                  <dt>A Records</dt>
                  <dd className={result.dns?.has_a ? 'ei-ok' : 'ei-bad'}>
                    {result.dns?.has_a
                      ? result.dns.a_records.join(', ')
                      : 'None found'}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Domain Info */}
            {result.domain_info && (
              <div className="ei-detail-card">
                <h5 className="ei-detail-card__title">Domain Intelligence</h5>
                <dl className="ei-dl">
                  <div className="ei-dl__row">
                    <dt>Domain</dt>
                    <dd className="font-mono">{result.domain}</dd>
                  </div>
                  <div className="ei-dl__row">
                    <dt>Domain Age</dt>
                    <dd className={result.domain_info.is_recently_registered ? 'ei-bad' : 'ei-ok'}>
                      {result.domain_info.domain_age_days != null
                        ? `${result.domain_info.domain_age_days} days`
                        : 'Unknown'}
                    </dd>
                  </div>
                  <div className="ei-dl__row">
                    <dt>Registrar</dt>
                    <dd>{result.domain_info.registrar || '—'}</dd>
                  </div>
                  <div className="ei-dl__row">
                    <dt>Type</dt>
                    <dd>
                      {result.domain_info.is_disposable
                        ? 'Disposable / Temp'
                        : result.domain_info.is_free_provider
                        ? 'Free Consumer Provider'
                        : 'Custom / Business'}
                    </dd>
                  </div>
                </dl>
              </div>
            )}

            {/* Local Part Analysis */}
            <div className="ei-detail-card">
              <h5 className="ei-detail-card__title">Local Part Analysis</h5>
              <dl className="ei-dl">
                <div className="ei-dl__row">
                  <dt>Local Part</dt>
                  <dd className="font-mono">{result.local_part}</dd>
                </div>
                <div className="ei-dl__row">
                  <dt>Flags</dt>
                  <dd>
                    {result.local_part_flags?.length > 0
                      ? result.local_part_flags.map((f, i) => (
                          <span key={i} className="ei-flag-tag">{f}</span>
                        ))
                      : <span className="ei-ok">No suspicious patterns</span>
                    }
                  </dd>
                </div>
              </dl>
            </div>

            {/* Brand Analysis */}
            {result.brand_analysis && (
              <div className="ei-detail-card">
                <h5 className="ei-detail-card__title">Brand Impersonation</h5>
                {result.brand_analysis.detected_brand ? (
                  <dl className="ei-dl">
                    <div className="ei-dl__row">
                      <dt>Target Brand</dt>
                      <dd className="ei-bad">{result.brand_analysis.detected_brand}</dd>
                    </div>
                    <div className="ei-dl__row">
                      <dt>Similarity</dt>
                      <dd>{Math.round((result.brand_analysis.similarity_score || 0) * 100)}%</dd>
                    </div>
                    <div className="ei-dl__row">
                      <dt>Technique</dt>
                      <dd>{result.brand_analysis.technique || '—'}</dd>
                    </div>
                  </dl>
                ) : (
                  <p className="ei-ok ei-no-brand">No known brand impersonation detected.</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && !error && (
        <div className="ei-empty">
          <p>Enter an email address above to investigate it for phishing indicators.</p>
        </div>
      )}
    </div>
  )
}
