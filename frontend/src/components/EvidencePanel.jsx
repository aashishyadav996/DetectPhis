import './EvidencePanel.css'

const FEATURE_LABELS = {
  domain: 'Domain',
  subdomain: 'Subdomain',
  suffix: 'TLD',
  url_length: 'URL length',
  num_dots: 'Dot count',
  num_hyphens: 'Hyphen count',
  num_digits: 'Digit count',
  num_subdomains: 'Subdomain depth',
  has_at_symbol: 'Contains "@"',
  has_ip_address_host: 'IP-address host',
  is_https: 'HTTPS',
  uses_url_shortener: 'URL shortener',
  suspicious_keyword_count: 'Suspicious keywords',
}

function formatValue(key, value) {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—'
  return String(value)
}

export default function EvidencePanel({ features }) {
  const entries = Object.entries(features).filter(([key]) => key in FEATURE_LABELS)

  return (
    <div className="evidence-panel">
      <h3 className="evidence-panel__title">Lexical evidence</h3>
      <dl className="evidence-panel__grid">
        {entries.map(([key, value]) => (
          <div className="evidence-panel__row" key={key}>
            <dt>{FEATURE_LABELS[key]}</dt>
            <dd>{formatValue(key, value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
