import './RiskGauge.css'

const RADIUS = 70
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function colorForScore(score) {
  if (score >= 70) return 'var(--risk-high)'
  if (score >= 40) return 'var(--risk-suspicious)'
  return 'var(--risk-low)'
}

export default function RiskGauge({ score, classification }) {
  const clamped = Math.max(0, Math.min(100, score))
  const offset = CIRCUMFERENCE - (clamped / 100) * CIRCUMFERENCE
  const color = colorForScore(clamped)

  return (
    <div className="risk-gauge">
      <svg viewBox="0 0 180 180" className="risk-gauge__svg">
        <circle
          cx="90"
          cy="90"
          r={RADIUS}
          fill="none"
          stroke="var(--border)"
          strokeWidth="10"
        />
        <circle
          cx="90"
          cy="90"
          r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 90 90)"
          className="risk-gauge__arc"
        />
      </svg>
      <div className="risk-gauge__readout">
        <span className="risk-gauge__score" style={{ color }}>{clamped}</span>
        <span className="risk-gauge__scale">/100</span>
        <span className="risk-gauge__label" style={{ color }}>{classification}</span>
      </div>
    </div>
  )
}
