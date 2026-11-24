import './SignalBreakdown.css'

const SIGNAL_LABELS = {
  ml: 'ML Prediction',
  reputation: 'VirusTotal Reputation',
  url_structure: 'URL Structure',
  brand_impersonation: 'Brand Impersonation',
}

export default function SignalBreakdown({ contributions }) {
  return (
    <div className="signal-breakdown">
      <h3 className="signal-breakdown__title">Signal contributions</h3>
      <div className="signal-breakdown__list">
        {contributions.map((c) => (
          <div className="signal-row" key={c.signal}>
            <div className="signal-row__head">
              <span className="signal-row__name">{SIGNAL_LABELS[c.signal] || c.signal}</span>
              <span className={`signal-row__status ${c.available ? 'is-available' : 'is-unavailable'}`}>
                {c.available ? `weight ${Math.round(c.weight_used * 100)}%` : 'unavailable'}
              </span>
            </div>
            <div className="signal-row__bar-track">
              <div
                className="signal-row__bar-fill"
                style={{ width: `${c.available ? c.raw_score * 100 : 0}%` }}
              />
            </div>
            {!c.available && <p className="signal-row__detail">{c.detail}</p>}
          </div>
        ))}
      </div>
    </div>
  )
}
