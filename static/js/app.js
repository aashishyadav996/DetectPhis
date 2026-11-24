/**
 * PhishTrace AI - Main Frontend Application Controller.
 * Orchestrates URL submission, API calls, tab navigation, and all result rendering.
 */

'use strict';

// -----------------------------------------------------------------------
// State
// -----------------------------------------------------------------------
var state = {
  lastResult: null,
  currentTab: 'overview',
  historyLoaded: false,
};

// -----------------------------------------------------------------------
// DOM Refs (resolved once on DOMContentLoaded)
// -----------------------------------------------------------------------
var $scanForm, $urlInput, $scanButton, $errorAlert;
var $resultsView, $overviewEmpty;
var $riskScoreValue, $gaugeArc, $riskClassBadge;
var $normalizedUrlDisplay, $confidenceFill, $confidenceValue;
var $reputationGapAlert, $reasonsUpList, $reasonsDownList, $reasonsDownContainer;
var $signalsContainer, $featuresSummaryList;
var $brandMiniContent, $vtMiniContent, $mlMiniContent;
var $tabBtns, $tabPanes;
var $investigationType, $fileInput, $tabBtnFile, $fileResultsContainer, $fileResultsBody, $fileResultsTitle;

// -----------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------
function escHtml(str) {
  if (str === null || str === undefined) return '\u2014';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showError(msg) {
  if (!$errorAlert) return;
  $errorAlert.textContent = msg;
  $errorAlert.style.display = 'block';
  $errorAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearError() {
  if ($errorAlert) $errorAlert.style.display = 'none';
}

// Parse API responses defensively: reverse proxies and framework error pages
// sometimes return HTML instead of JSON, which otherwise hides the real error.
async function readJsonResponse(response) {
  var body = await response.text();
  if (!body) return {};
  try {
    return JSON.parse(body);
  } catch (_error) {
    return { detail: response.ok
      ? 'The server returned an unexpected response.'
      : 'Request failed with HTTP ' + response.status + '.' };
  }
}

function setLoading(isLoading) {
  if (!$scanButton) return;
  if (isLoading) {
    $scanButton.disabled = true;
    $scanButton.textContent = 'Analyzing\u2026';
  } else {
    $scanButton.disabled = false;
    $scanButton.textContent = 'Investigate';
  }
}

// -----------------------------------------------------------------------
// Tab navigation
// -----------------------------------------------------------------------
function activateTab(tabName) {
  state.currentTab = tabName;
  $tabBtns.forEach(function(btn) {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
  });
  $tabPanes.forEach(function(pane) {
    var id = pane.id.replace('tab-content-', '');
    pane.classList.toggle('active', id === tabName);
  });
  if (tabName === 'history' && !state.historyLoaded) {
    loadHistory();
  }
}

// -----------------------------------------------------------------------
// Risk gauge rendering
// -----------------------------------------------------------------------
var GAUGE_FULL_LENGTH = 141.37;

function renderGauge(score, classification) {
  var clamped = Math.max(0, Math.min(100, score));
  var offset = GAUGE_FULL_LENGTH - (clamped / 100) * GAUGE_FULL_LENGTH;
  var colour = '#4fd1c5';
  if (clamped >= 60) colour = '#ff5c6c'; // risk-high
  else if (clamped >= 40) colour = '#ffb84d'; // risk-suspicious

  if ($gaugeArc) {
    $gaugeArc.style.strokeDashoffset = offset;
    $gaugeArc.style.stroke = colour;
  }
  if ($riskScoreValue) $riskScoreValue.textContent = clamped;

  if ($riskClassBadge) {
    $riskClassBadge.textContent = escHtml(classification || 'UNKNOWN');
    $riskClassBadge.className = 'risk-classification-tag';
    if (clamped >= 60) $riskClassBadge.style.color = '#ff5c6c';
    else if (clamped >= 40) $riskClassBadge.style.color = '#ffb84d';
    else $riskClassBadge.style.color = '#4fd1c5';
  }
}

// -----------------------------------------------------------------------
// Multi-signal attribution bar
// -----------------------------------------------------------------------
function renderSignals(contributions) {
  if (!$signalsContainer || !contributions) return;
  var items = contributions.slice().sort(function(a, b) {
    return Math.abs(b.raw_score) - Math.abs(a.raw_score);
  });
  $signalsContainer.innerHTML = items.map(function(sig) {
    var pct = Math.min(100, Math.abs((sig.raw_score || 0) * 100));
    var positive = (sig.raw_score || 0) >= 0.5;
    var barColor = positive ? '#ff5c6c' : '#4fd1c5';
    var labelColor = positive ? '#ff5c6c' : '#4fd1c5';
    var scoreDisplay = sig.available
      ? Math.round((sig.raw_score || 0) * 100) + '%'
      : 'N/A';
    var weightDisplay = sig.available
      ? '(weight ' + Math.round((sig.weight_used || 0) * 100) + '%)'
      : '(unavailable)';
    
    return '<div class="signal-row">'
      + '  <div class="signal-row__meta">'
      + '    <span class="signal-row__name">' + escHtml(sig.signal) + '</span>'
      + '    <span class="signal-row__values" style="color:' + labelColor + '">' + scoreDisplay + ' ' + weightDisplay + '</span>'
      + '  </div>'
      + '  <div class="signal-row__track">'
      + '    <div class="signal-row__fill" style="width:' + pct + '%; background:' + barColor + ';"></div>'
      + '  </div>'
      + '  <div class="signal-row__detail">' + escHtml(sig.detail || '') + '</div>'
      + '</div>';
  }).join('');
}

// -----------------------------------------------------------------------
// Lexical evidence grid
// -----------------------------------------------------------------------
var FEATURE_LABELS = {
  // Actual URLFeatures fields returned by the API
  url:                       'Full URL',
  domain:                    'Domain',
  sld:                       'Second-Level Domain',
  subdomain:                 'Subdomain',
  suffix:                    'TLD / Suffix',
  url_length:                'URL Length',
  num_dots:                  'Dot Count',
  num_hyphens:               'Hyphen Count',
  num_digits:                'Digit Count',
  num_subdomains:            'Subdomain Depth',
  has_at_symbol:             'At-Sign in URL',
  has_ip_address_host:       'IP-Based Host',
  is_https:                  'HTTPS',
  uses_url_shortener:        'URL Shortener',
  suspicious_keyword_count:  'Suspicious Keywords',
  suspicious_keywords_found: 'Suspicious Keywords Found',
};

function formatFeatureValue(key, val) {
  if (typeof val === 'boolean') return val ? 'Yes' : 'No';
  if (val === null || val === undefined) return '\u2014';
  if (Array.isArray(val)) return val.length ? val.join(', ') : '\u2014';
  return String(val);
}

function renderFeaturesGrid(features, container) {
  if (!container || !features) return;
  container.innerHTML = Object.keys(features).map(function(k) {
    var label = FEATURE_LABELS[k] || k.replace(/_/g, ' ');
    var val = formatFeatureValue(k, features[k]);
    var isFlag = typeof features[k] === 'boolean' && features[k] === true;
    return '<div class="evidence-row">'
      + '<dt>' + escHtml(label) + '</dt>'
      + '<dd style="' + (isFlag ? 'color:var(--risk-high);' : '') + '">' + escHtml(val) + '</dd>'
      + '</div>';
  }).join('');
}

// -----------------------------------------------------------------------
// Mini evidence cards
// -----------------------------------------------------------------------
function renderBrandMini(brand) {
  if (!$brandMiniContent) return;
  if (!brand || !brand.detected_brand) {
    $brandMiniContent.innerHTML = '<p class="evidence-mini__detail">No brand impersonation detected.</p>';
    return;
  }
  $brandMiniContent.innerHTML = '<h4 class="evidence-mini__headline" style="color:var(--risk-suspicious)">' + escHtml(brand.detected_brand) + '</h4>'
    + '<p class="evidence-mini__detail">Similarity: ' + Math.round((brand.similarity_score || 0) * 100) + '%</p>'
    + '<p class="evidence-mini__detail">Risk: ' + escHtml(brand.impersonation_risk) + '</p>'
    + (brand.technique ? '<p class="evidence-mini__detail">Technique: ' + escHtml(brand.technique) + '</p>' : '');
}

function renderVtMini(vt) {
  if (!$vtMiniContent) return;
  if (!vt || vt.error) {
    $vtMiniContent.innerHTML = '<p class="evidence-mini__detail">VirusTotal: ' + escHtml((vt && vt.error) || 'Unavailable') + '</p>';
    return;
  }
  var detections = vt.malicious_count != null ? vt.malicious_count : 0;
  var total = vt.total_engines != null ? vt.total_engines : 0;
  var colourClass = detections > 3 ? 'var(--risk-high)' : detections > 0 ? 'var(--risk-suspicious)' : 'var(--risk-low)';
  
  $vtMiniContent.innerHTML = '<h4 class="evidence-mini__headline" style="color:' + colourClass + ';">' + detections + ' / ' + total + ' detections</h4>'
    + '<p class="evidence-mini__detail">Cache status: ' + escHtml(vt.cache_status || 'Live') + '</p>'
    + (vt.scan_date ? '<p class="evidence-mini__detail">Scan date: ' + escHtml(vt.scan_date) + '</p>' : '');
}

function renderMlMini(ml) {
  if (!$mlMiniContent) return;
  if (!ml || !ml.available) {
    $mlMiniContent.innerHTML = '<p class="evidence-mini__detail">ML model unavailable.' + (ml && ml.error ? ' ' + escHtml(ml.error) : '') + '</p>';
    return;
  }
  var prob = Math.round((ml.phishing_probability || 0) * 100);
  var colourClass = prob >= 70 ? 'var(--risk-high)' : prob >= 45 ? 'var(--risk-suspicious)' : 'var(--risk-low)';
  $mlMiniContent.innerHTML = '<h4 class="evidence-mini__headline" style="color:' + colourClass + ';">' + prob + '% Phishing Prob.</h4>'
    + '<p class="evidence-mini__detail">Model: ' + escHtml(ml.model_name || 'Unknown') + '</p>';
}

// -----------------------------------------------------------------------
// Main result renderer
// -----------------------------------------------------------------------
function renderResults(data) {
  state.lastResult = data;
  if ($resultsView) $resultsView.style.display = '';
  if ($overviewEmpty) $overviewEmpty.style.display = 'none';

  renderGauge(data.risk_score, data.classification);

  if ($normalizedUrlDisplay) $normalizedUrlDisplay.textContent = data.normalized_url;
  if ($confidenceFill) $confidenceFill.style.width = data.confidence + '%';
  if ($confidenceValue) $confidenceValue.textContent = data.confidence + '%';

  if ($reputationGapAlert) {
    $reputationGapAlert.style.display = data.reputation_gap_warning ? '' : 'none';
  }

  if ($reasonsUpList) {
    var upItems = (data.reasons_increasing || []).map(function(r) { return '<li>' + escHtml(r) + '</li>'; }).join('');
    $reasonsUpList.innerHTML = upItems || '<li>None identified.</li>';
  }
  if ($reasonsDownList && $reasonsDownContainer) {
    var down = data.reasons_decreasing || [];
    $reasonsDownContainer.style.display = down.length > 0 ? '' : 'none';
    if (down.length > 0) {
      $reasonsDownList.innerHTML = down.map(function(r) { return '<li>' + escHtml(r) + '</li>'; }).join('');
    }
  }

  renderSignals(data.signal_contributions);

  var summaryKeys = ['is_https','url_length','num_dots','num_hyphens','num_subdomains','has_ip_address_host','has_at_symbol','uses_url_shortener','suspicious_keyword_count'];
  if ($featuresSummaryList && data.features) {
    var subset = {};
    summaryKeys.forEach(function(k) { if (k in data.features) subset[k] = data.features[k]; });
    renderFeaturesGrid(subset, $featuresSummaryList);
  }
  var featuresFullGrid = document.getElementById('features-full-grid');
  if (featuresFullGrid && data.features) renderFeaturesGrid(data.features, featuresFullGrid);

  renderBrandMini(data.brand_analysis);
  renderVtMini(data.virustotal);
  renderMlMini(data.ml);

  var graphData = data.threat_graph;
  if (window.threatGraphVisualizer && graphData) window.threatGraphVisualizer.loadData(graphData);

  var tabGraphBadge = document.getElementById('tab-graph-badge');
  if (tabGraphBadge && graphData && graphData.nodes) {
    tabGraphBadge.textContent = graphData.nodes.length;
    tabGraphBadge.style.display = graphData.nodes.length > 0 ? '' : 'none';
  }

  var exportBtn = document.getElementById('export-report-btn');
  if (exportBtn) {
    if (data.scan_id) {
      exportBtn.onclick = function() { window.open('/api/v1/reports/' + data.scan_id + '/html', '_blank'); };
    } else {
      exportBtn.onclick = function() { exportLiveReport(data); };
    }
    exportBtn.style.display = '';
  }

  activateTab('overview');
}

// -----------------------------------------------------------------------
// Live report export
// -----------------------------------------------------------------------
async function exportLiveReport(resultData) {
  try {
    var res = await fetch('/api/v1/reports/export/html', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(resultData),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    var html = await res.text();
    var blob = new Blob([html], { type: 'text/html' });
    var blobUrl = URL.createObjectURL(blob);
    window.open(blobUrl, '_blank');
    setTimeout(function() { URL.revokeObjectURL(blobUrl); }, 60000);
  } catch (err) {
    showError('Failed to generate report: ' + err.message);
  }
}

// -----------------------------------------------------------------------
// Scan submission
// -----------------------------------------------------------------------
async function submitScan(rawUrl) {
  clearError();
  setLoading(true);
  try {
    var res = await fetch('/api/v1/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl }),
    });
    var data = await readJsonResponse(res);
    if (!res.ok) {
      showError(data.detail || 'Server error (' + res.status + '). Please try again.');
      return;
    }
    renderResults(data);
  } catch (err) {
    showError('Network error: ' + err.message + '. Is the server running?');
  } finally {
    setLoading(false);
  }
}

// -----------------------------------------------------------------------
// Forensics Module: Email ID, Email File (.eml), and File Scan
// -----------------------------------------------------------------------
function switchForensicsMode(mode) {
  document.querySelectorAll('.forensics-mode-btn').forEach(function(btn) {
    btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
  });
  var subEmailId = document.getElementById('subpane-email-id');
  var subEmailFile = document.getElementById('subpane-email-file');
  var subFileHash = document.getElementById('subpane-file-hash');

  if (subEmailId) subEmailId.style.display = mode === 'email_id' ? 'block' : 'none';
  if (subEmailFile) subEmailFile.style.display = mode === 'email_file' ? 'block' : 'none';
  if (subFileHash) subFileHash.style.display = mode === 'file_hash' ? 'block' : 'none';
}

function renderEmailIdResults(data, $target) {
  if (!$target) $target = document.getElementById('email-id-results');
  if (!$target) return;

  var score = data.risk_score || 0;
  var level = (data.risk_level || 'LOW').toLowerCase();
  var color = score >= 70 ? '#ff5c6c' : score >= 40 ? '#ffb84d' : score >= 20 ? '#4fd1c5' : '#48c774';

  var reasonsUpHtml = '';
  if (data.reasons_increasing && data.reasons_increasing.length) {
    reasonsUpHtml = data.reasons_increasing.map(function(r) {
      return '<li class="forensics-finding-item">⚠️ ' + escHtml(r) + '</li>';
    }).join('');
  }

  var reasonsDownHtml = '';
  if (data.reasons_decreasing && data.reasons_decreasing.length) {
    reasonsDownHtml = data.reasons_decreasing.map(function(r) {
      return '<li class="forensics-good-item">✅ ' + escHtml(r) + '</li>';
    }).join('');
  }

  var dnsMxText = data.dns && data.dns.has_mx
    ? data.dns.mx_records.slice(0, 2).join(', ')
    : 'No MX record found (Cannot receive emails)';
  var dnsAText = data.dns && data.dns.has_a
    ? data.dns.a_records.slice(0, 3).join(', ')
    : 'No active A record';

  var domainInfo = data.domain_info || {};
  var brandInfo = data.brand_analysis || {};

  var html = '' +
    '<div class="forensics-hero-card">' +
      '<div class="forensics-score-circle" style="border-color: ' + color + '; color: ' + color + ';">' +
        '<span class="num">' + score + '</span>' +
        '<span class="den">/ 100</span>' +
      '</div>' +
      '<div class="forensics-hero-details">' +
        '<div class="forensics-hero-email">' + escHtml(data.email) + '</div>' +
        '<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">' +
          '<span class="forensics-level-badge ' + level + '">' + escHtml(data.risk_level || 'UNKNOWN') + ' RISK</span>' +
          (!data.valid_format ? '<span class="forensics-level-badge high">INVALID RFC FORMAT</span>' : '') +
          (domainInfo.is_disposable ? '<span class="forensics-level-badge high">DISPOSABLE BURNER MAIL</span>' : '') +
          (domainInfo.is_free_provider ? '<span class="forensics-level-badge suspicious">FREE CONSUMER EMAIL</span>' : '') +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="forensics-grid-2">' +
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Identity &amp; Address Breakdown</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Email ID</span>' +
            '<span class="forensics-meta-val"><span class="email-id-highlight">' + escHtml(data.email) + '</span></span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Local Part</span>' +
            '<span class="forensics-meta-val">' + escHtml(data.local_part || '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Domain</span>' +
            '<span class="forensics-meta-val">' + escHtml(data.domain || '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Format Syntax</span>' +
            '<span class="forensics-meta-val">' + (data.valid_format ? 'RFC 5321 Valid' : 'Syntax Error') + '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="forensics-card">' +
        '<div class="forensics-card-title">DNS &amp; Mail Server Delivery</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">MX Status</span>' +
            '<span class="forensics-meta-val" style="color:' + (data.dns && data.dns.has_mx ? '#48c774' : '#ff5c6c') + '; font-weight:600;">' +
              (data.dns && data.dns.has_mx ? 'VERIFIED ACTIVE' : 'NO MX / UNROUTABLE') +
            '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">MX Hosts</span>' +
            '<span class="forensics-meta-val">' + escHtml(dnsMxText) + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Resolved A IPs</span>' +
            '<span class="forensics-meta-val">' + escHtml(dnsAText) + '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +

    '<div class="forensics-grid-2">' +
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Domain Intelligence &amp; Profiling</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Domain Age</span>' +
            '<span class="forensics-meta-val">' + (domainInfo.domain_age_days != null ? domainInfo.domain_age_days + ' days' : 'Unavailable / Private') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Recent Domain</span>' +
            '<span class="forensics-meta-val">' + (domainInfo.is_recently_registered ? 'Yes (&lt; 180 days)' : 'No') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Registrar</span>' +
            '<span class="forensics-meta-val">' + escHtml(domainInfo.registrar || 'Protected / Hidden') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Disposable Mail</span>' +
            '<span class="forensics-meta-val" style="color:' + (domainInfo.is_disposable ? '#ff5c6c' : '#48c774') + '; font-weight:600;">' +
              (domainInfo.is_disposable ? 'TRUE (Throwaway)' : 'FALSE') +
            '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Brand Impersonation &amp; Flags</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Target Brand</span>' +
            '<span class="forensics-meta-val" style="font-weight:600; color:' + (brandInfo.detected_brand ? '#ff5c6c' : 'inherit') + ';">' + escHtml(brandInfo.detected_brand || 'None Detected') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Similarity</span>' +
            '<span class="forensics-meta-val">' + (brandInfo.similarity_score ? Math.round(brandInfo.similarity_score * 100) + '%' : '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Local Anomalies</span>' +
            '<span class="forensics-meta-val">' + (data.local_part_flags && data.local_part_flags.length ? escHtml(data.local_part_flags.join(', ')) : 'None') + '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';

  if (reasonsUpHtml || reasonsDownHtml) {
    html += '<div class="forensics-card">' +
      '<div class="forensics-card-title">Risk Engine Factors &amp; Reasons</div>' +
      '<ul class="forensics-findings-list">' + reasonsUpHtml + reasonsDownHtml + '</ul>' +
    '</div>';
  }

  $target.innerHTML = html;
  $target.style.display = 'block';
}

function renderEmailFileResults(data, fileName, $target) {
  if (!$target) $target = document.getElementById('email-file-results');
  if (!$target) return;

  var score = data.risk_score || 0;
  var color = score >= 65 ? '#ff5c6c' : score >= 35 ? '#ffb84d' : '#48c774';
  var verdictClass = score >= 65 ? 'danger' : score >= 35 ? 'suspicious' : 'safe';

  var auth = data.auth_results || { spf: 'none', dkim: 'none', dmarc: 'none' };
  var headers = data.headers || {};
  var sender = data.sender_analysis || {};
  var senderInvest = data.sender_email_id_investigation || null;

  var findingsHtml = '';
  if (data.findings && data.findings.length) {
    findingsHtml += data.findings.map(function(f) {
      return '<li class="forensics-finding-item">' + escHtml(f) + '</li>';
    }).join('');
  }
  if (data.good_signs && data.good_signs.length) {
    findingsHtml += data.good_signs.map(function(g) {
      return '<li class="forensics-good-item">' + escHtml(g) + '</li>';
    }).join('');
  }

  var urlsHtml = '<p style="color:var(--text-secondary); margin:0;">No links found in message.</p>';
  if (data.extracted_urls && data.extracted_urls.length) {
    urlsHtml = '<ul class="forensics-url-list">' +
      data.extracted_urls.map(function(u) {
        return '<li class="forensics-url-item">' + escHtml(u) + '</li>';
      }).join('') +
    '</ul>';
  }

  var senderInvestHtml = '';
  if (senderInvest) {
    var sScore = senderInvest.risk_score || 0;
    var sColor = sScore >= 70 ? '#ff5c6c' : sScore >= 40 ? '#ffb84d' : '#48c774';
    senderInvestHtml = '' +
      '<div class="forensics-card" style="border-left: 3px solid ' + sColor + ';">' +
        '<div class="forensics-card-title">' +
          '<span>Sender Email ID Forensics: <span class="email-id-highlight">' + escHtml(senderInvest.email) + '</span></span>' +
          '<span class="forensics-level-badge ' + (senderInvest.risk_level || 'low').toLowerCase() + '">' + escHtml(senderInvest.risk_level || 'SAFE') + ' RISK</span>' +
        '</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Sender Risk Score</span>' +
            '<span class="forensics-meta-val" style="color:' + sColor + '; font-weight:700;">' + sScore + ' / 100</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">MX Mail Delivery</span>' +
            '<span class="forensics-meta-val">' + (senderInvest.dns && senderInvest.dns.has_mx ? 'Verified Active (' + escHtml(senderInvest.dns.mx_records.slice(0, 1).join('')) + ')' : 'No MX Records Found') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Domain Age</span>' +
            '<span class="forensics-meta-val">' + (senderInvest.domain_info && senderInvest.domain_info.domain_age_days != null ? senderInvest.domain_info.domain_age_days + ' days' : 'Unknown / Private') + '</span>' +
          '</div>' +
          (senderInvest.brand_analysis && senderInvest.brand_analysis.detected_brand ?
            '<div class="forensics-meta-row">' +
              '<span class="forensics-meta-key">Brand Spoofing</span>' +
              '<span class="forensics-meta-val" style="color:#ff5c6c; font-weight:600;">Targeting ' + escHtml(senderInvest.brand_analysis.detected_brand) + '</span>' +
            '</div>' : '') +
        '</div>' +
      '</div>';
  }

  var html = '' +
    '<div class="forensics-hero-card">' +
      '<div class="forensics-score-circle" style="border-color: ' + color + '; color: ' + color + ';">' +
        '<span class="num">' + score + '</span>' +
        '<span class="den">/ 100</span>' +
      '</div>' +
      '<div class="forensics-hero-details">' +
        '<div class="forensics-hero-email">' + escHtml(data.verdict_emoji || '🔍') + ' ' + escHtml(data.verdict || 'INVESTIGATION COMPLETE') + '</div>' +
        '<div style="font-size:0.84rem; color:var(--text-secondary); margin-bottom:8px;">' + escHtml(data.verdict_reason || '') + '</div>' +
        '<span class="forensics-level-badge ' + verdictClass + '">' + escHtml(data.verdict || 'ANALYZED') + '</span>' +
      '</div>' +
    '</div>' +

    '<div class="forensics-grid-2">' +
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Extracted Email IDs &amp; Headers</div>' +
        '<div class="forensics-meta-list">' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Sender Email ID</span>' +
            '<span class="forensics-meta-val"><span class="email-id-highlight">' + escHtml(headers.from_email_id || sender.from_address || headers.from || '—') + '</span></span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">From (Header)</span>' +
            '<span class="forensics-meta-val">' + escHtml(headers.from || '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Recipient Email ID</span>' +
            '<span class="forensics-meta-val">' + escHtml(headers.to_email_id || headers.to || '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Reply-To ID</span>' +
            '<span class="forensics-meta-val">' + escHtml(headers.reply_to_email_id || sender.reply_to || 'Same as Sender') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Subject</span>' +
            '<span class="forensics-meta-val" style="font-family:inherit; font-weight:600;">' + escHtml(headers.subject || '(No Subject)') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Date</span>' +
            '<span class="forensics-meta-val">' + escHtml(headers.date || '—') + '</span>' +
          '</div>' +
          '<div class="forensics-meta-row">' +
            '<span class="forensics-meta-key">Message-ID</span>' +
            '<span class="forensics-meta-val" style="font-size:0.72rem;">' + escHtml(headers.message_id || '—') + '</span>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Email Authentication Verification</div>' +
        '<div class="auth-badge-row">' +
          '<span class="auth-pill ' + (auth.spf === 'pass' ? 'pass' : auth.spf === 'fail' ? 'fail' : 'none') + '">SPF: ' + escHtml(auth.spf.toUpperCase()) + '</span>' +
          '<span class="auth-pill ' + (auth.dkim === 'pass' ? 'pass' : auth.dkim === 'fail' ? 'fail' : 'none') + '">DKIM: ' + escHtml(auth.dkim.toUpperCase()) + '</span>' +
          '<span class="auth-pill ' + (auth.dmarc === 'pass' ? 'pass' : auth.dmarc === 'fail' ? 'fail' : 'none') + '">DMARC: ' + escHtml(auth.dmarc.toUpperCase()) + '</span>' +
        '</div>' +
        '<p style="font-size:0.8rem; color:var(--text-secondary); margin:0;">' +
          (auth.spf === 'pass' && auth.dkim === 'pass' && auth.dmarc === 'pass'
            ? 'All cryptographic domain verification checks passed successfully.'
            : 'Authentication irregularities detected. Possible spoofing or domain forgery.') +
        '</p>' +
      '</div>' +
    '</div>' +

    (senderInvestHtml ? senderInvestHtml : '') +

    '<div class="forensics-grid-2">' +
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Embedded Links (' + (data.extracted_urls ? data.extracted_urls.length : 0) + ')</div>' +
        urlsHtml +
        (data.url_analysis ?
          '<div style="margin-top:14px; padding:10px; background:rgba(0,0,0,0.2); border-radius:6px; border:1px solid var(--border); font-size:0.8rem;">' +
            '<strong style="color:var(--text-primary);">First URL Auto-Scan:</strong> ' +
            '<span style="color:#38bdf8;">' + escHtml(data.url_analysis.url) + '</span><br>' +
            '<span style="color:' + (data.url_analysis.classification === 'HIGH RISK' ? '#ff5c6c' : '#48c774') + '; font-weight:700;">Verdict: ' + escHtml(data.url_analysis.classification || 'UNKNOWN') + '</span>' +
          '</div>' : '') +
      '</div>' +

      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Attachments &amp; Files (' + (data.attachments ? data.attachments.length : 0) + ')</div>' +
        (data.dangerous_attachments && data.dangerous_attachments.length
          ? '<div style="background:rgba(255,92,108,0.15); border:1px solid rgba(255,92,108,0.4); color:#ff7a85; padding:8px 12px; border-radius:6px; margin-bottom:10px; font-size:0.8rem;">' +
              '⚠️ DANGEROUS ATTACHMENT(S) DETECTED: ' + escHtml(data.dangerous_attachments.map(function(a){return a.filename;}).join(', ')) +
            '</div>' : '') +
        (data.attachments && data.attachments.length
          ? '<ul class="forensics-url-list">' + data.attachments.map(function(a){
              return '<li class="forensics-url-item" style="color:var(--text-primary);">' + escHtml(a.filename) + ' (' + escHtml(a.content_type || 'binary') + ')</li>';
            }).join('') + '</ul>'
          : '<p style="color:var(--text-secondary); margin:0;">No attachments in message.</p>') +
      '</div>' +
    '</div>' +

    (findingsHtml ?
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Phishing Forensic Signals</div>' +
        '<ul class="forensics-findings-list">' + findingsHtml + '</ul>' +
      '</div>' : '') +

    (data.body_preview ?
      '<div class="forensics-card">' +
        '<div class="forensics-card-title">Message Body Content Preview</div>' +
        '<pre class="forensics-body-box">' + escHtml(data.body_preview) + '</pre>' +
      '</div>' : '');

  $target.innerHTML = html;
  $target.style.display = 'block';
}

function renderFileHashResults(data, $target) {
  if (!$target) $target = document.getElementById('generic-file-results');
  if (!$target) return;

  var hashes = data.hashes || {};
  var sizeText = data.size_bytes != null
    ? data.size_bytes < 1024 ? data.size_bytes + ' B'
    : data.size_bytes < 1048576 ? (data.size_bytes / 1024).toFixed(1) + ' KB'
    : (data.size_bytes / 1048576).toFixed(2) + ' MB'
    : '—';

  var html = '' +
    '<div class="forensics-card">' +
      '<div class="forensics-card-title">Cryptographic File Signature &amp; Integrity</div>' +
      '<div class="forensics-meta-list">' +
        '<div class="forensics-meta-row">' +
          '<span class="forensics-meta-key">File Name</span>' +
          '<span class="forensics-meta-val" style="color:#38bdf8;">' + escHtml(data.filename || '—') + '</span>' +
        '</div>' +
        '<div class="forensics-meta-row">' +
          '<span class="forensics-meta-key">Size</span>' +
          '<span class="forensics-meta-val">' + sizeText + '</span>' +
        '</div>' +
        '<div class="forensics-meta-row">' +
          '<span class="forensics-meta-key">SHA-256 Hash</span>' +
          '<span class="forensics-meta-val" style="color:#4fd1c5;">' + escHtml(hashes.sha256 || '—') + '</span>' +
        '</div>' +
        '<div class="forensics-meta-row">' +
          '<span class="forensics-meta-key">SHA-1 Hash</span>' +
          '<span class="forensics-meta-val">' + escHtml(hashes.sha1 || '—') + '</span>' +
        '</div>' +
        '<div class="forensics-meta-row">' +
          '<span class="forensics-meta-key">MD5 Hash</span>' +
          '<span class="forensics-meta-val">' + escHtml(hashes.md5 || '—') + '</span>' +
        '</div>' +
      '</div>' +
      '<p style="font-size:0.78rem; color:var(--text-secondary); margin:14px 0 0;">' +
        escHtml(data.message || 'Cryptographic hashes establish file identity and verify against known malware databases.') +
      '</p>' +
    '</div>';

  $target.innerHTML = html;
  $target.style.display = 'block';
}

async function submitEmailIdScan(email) {
  clearError();
  var trimmed = (email || '').trim();
  if (!trimmed) { showError('Please enter an Email ID to investigate.'); return; }
  setLoading(true);
  try {
    var res = await fetch('/api/v1/analyze/email-address', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: trimmed })
    });
    var data = await readJsonResponse(res);
    if (!res.ok) {
      showError(data.detail || 'Email investigation failed (' + res.status + ').');
      return;
    }
    activateTab('file');
    switchForensicsMode('email_id');
    var $input = document.getElementById('tab-email-input');
    if ($input) $input.value = trimmed;
    renderEmailIdResults(data);
  } catch (err) {
    showError('Network error: ' + err.message + '. Is the server running?');
  } finally {
    setLoading(false);
  }
}

async function submitFileUpload(file, type) {
  clearError();
  if (!file) { showError('Please select a file to upload.'); return; }
  if (file.size > 10 * 1024 * 1024) { showError('Files must be 10 MB or smaller.'); return; }
  if (type === 'email' && !file.name.toLowerCase().endsWith('.eml')) { showError('Email analysis accepts .eml files only.'); return; }
  setLoading(true);
  try {
    var formData = new FormData();
    formData.append('file', file);
    
    var endpoint = type === 'email' ? '/api/v1/analyze/email' : '/api/v1/analyze/file';
    
    var res = await fetch(endpoint, {
      method: 'POST',
      body: formData
    });
    
    var data = await readJsonResponse(res);
    if (!res.ok) {
      showError(data.detail || 'Server error (' + res.status + '). Please try again.');
      return;
    }
    
    activateTab('file');
    if (type === 'email') {
      switchForensicsMode('email_file');
      renderEmailFileResults(data, file.name);
    } else {
      switchForensicsMode('file_hash');
      renderFileHashResults(data);
    }
    
  } catch (err) {
    showError('Network error: ' + err.message + '. Is the server running?');
  } finally {
    setLoading(false);
  }
}

// -----------------------------------------------------------------------
// Adversarial testing
// -----------------------------------------------------------------------
async function runAdversarialTest() {
  if (!state.lastResult) {
    showError('Please analyze a URL first before running the adversarial evasion test suite.');
    return;
  }
  var elLoading = document.getElementById('adversarial-loading');
  var elResults = document.getElementById('adversarial-results');
  var elEmpty   = document.getElementById('adversarial-empty');
  var elRunBtn  = document.getElementById('run-adversarial-btn');

  if (elLoading) elLoading.style.display = '';
  if (elResults) elResults.style.display = 'none';
  if (elEmpty)   elEmpty.style.display   = 'none';
  if (elRunBtn)  { elRunBtn.disabled = true; elRunBtn.textContent = 'Running\u2026'; }

  try {
    var res = await fetch('/api/v1/adversarial/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: state.lastResult.normalized_url }),
    });
    var data = await readJsonResponse(res);
    if (!res.ok) {
      showError(data.detail || 'Adversarial test failed (' + res.status + ').');
      if (elEmpty) elEmpty.style.display = '';
      return;
    }
    renderAdversarialResults(data);
  } catch (err) {
    showError('Adversarial test error: ' + err.message);
    if (elEmpty) elEmpty.style.display = '';
  } finally {
    if (elLoading) elLoading.style.display = 'none';
    if (elRunBtn)  { elRunBtn.disabled = false; elRunBtn.textContent = 'Run Evasion Test Suite'; }
  }
}

function renderAdversarialResults(data) {
  var elResults = document.getElementById('adversarial-results');
  if (elResults) elResults.style.display = '';

  var rate = Math.round(data.resilience_rate_percent != null ? data.resilience_rate_percent : 0);
  var el;

  el = document.getElementById('resilience-rate-display');   if (el) el.textContent = rate + '%';
  el = document.getElementById('mutations-flagged-count');   if (el) el.textContent = data.detected_count != null ? data.detected_count : 0;
  el = document.getElementById('mutations-evaded-count');    if (el) el.textContent = data.evaded_count   != null ? data.evaded_count   : 0;
  el = document.getElementById('mutations-total-count');     if (el) el.textContent = data.total_mutations != null ? data.total_mutations : 0;
  el = document.getElementById('baseline-score-display');    if (el) el.textContent = data.baseline_risk_score != null ? data.baseline_risk_score : '\u2014';

  var vulnBox  = document.getElementById('adversarial-vulnerabilities-box');
  var vulnList = document.getElementById('vulnerabilities-list');
  if (vulnList) {
    var vulns = data.vulnerability_summary || [];
    if (vulns.length > 0) {
      if (vulnBox) vulnBox.style.display = '';
      vulnList.innerHTML = vulns.map(function(v) {
        // v can be a plain string or {technique, description} object
        if (typeof v === 'string') {
          return '<li>' + escHtml(v) + '</li>';
        }
        return '<li><strong>' + escHtml(v.technique || '') + '</strong>: ' + escHtml(v.description || '') + '</li>';
      }).join('');
    } else {
      if (vulnBox) vulnBox.style.display = 'none';
    }
  }

  var mutContainer = document.getElementById('mutations-container');
  if (mutContainer) {
    var mutations = data.mutations || [];
    mutContainer.innerHTML = mutations.map(function(m) {
      var flagged     = m.is_flagged;
      var score      = m.risk_score != null ? m.risk_score : 0;
      var cName = flagged ? 'caught' : 'evaded';
      var statusBadge = flagged ? '<span class="status-caught">FLAGGED</span>' : '<span class="status-evaded">EVADED</span>';
      
      return '<div class="mutation-card ' + cName + '">'
        + '  <div class="mutation-card__top">'
        + '    <span class="mutation-tech-badge">' + escHtml(m.technique) + '</span>'
        + '    ' + statusBadge
        + '  </div>'
        + '  <div class="mutation-url-box">'
        + '    <div class="mutation-url">' + escHtml(m.mutated_url) + '</div>'
        + '  </div>'
        + '  <p class="mutation-desc">' + escHtml(m.description) + '</p>'
        + '  <div class="mutation-factors">'
        + '    <span class="factors-label">Risk Score:</span>'
        + '    <span class="factors-text">' + (m.risk_score != null ? m.risk_score : '\u2014') + '</span>'
        + '  </div>'
        + '</div>';
    }).join('');
  }
}

// -----------------------------------------------------------------------
// Audit history
// -----------------------------------------------------------------------
async function loadHistory() {
  state.historyLoaded = true;
  var tableWrapper = document.getElementById('history-table-wrapper');
  var tableBody    = document.getElementById('history-table-body');
  var emptyState   = document.getElementById('history-empty');
  var countBadge   = document.getElementById('history-count-badge');

  try {
    var res   = await fetch('/api/v1/history?limit=50');
    var scans = await readJsonResponse(res);
    if (!res.ok) throw new Error(scans.detail || ('HTTP ' + res.status));

    if (!Array.isArray(scans) || scans.length === 0) {
      if (tableWrapper) tableWrapper.style.display = 'none';
      if (emptyState)   emptyState.style.display   = '';
      if (countBadge)   countBadge.textContent      = '0 Saved Scans';
      return;
    }

    if (countBadge)   countBadge.textContent    = scans.length + ' Saved Scan' + (scans.length !== 1 ? 's' : '');
    if (tableWrapper) tableWrapper.style.display = '';
    if (emptyState)   emptyState.style.display   = 'none';

    if (tableBody) {
      tableBody.innerHTML = scans.map(function(scan) {
        var score = scan.risk_score != null ? scan.risk_score : 0;
        var badgeClass = 'risk-low';
        if      (score >= 60) badgeClass = 'risk-high';
        else if (score >= 40) badgeClass = 'risk-suspicious';

        var ageText = scan.domain_age_days != null ? scan.domain_age_days + 'd' : '\u2014';
        var brand   = scan.detected_brand || '\u2014';
        var timestamp = scan.scanned_at || scan.created_at;
        var ts      = timestamp ? new Date(timestamp).toLocaleString('en-GB', { timeZone: 'UTC', hour12: false }) : '\u2014';
        var fullUrl = scan.normalized_url || scan.url || '';
        var shortUrl = fullUrl.length > 50 ? fullUrl.slice(0, 48) + '\u2026' : fullUrl;

        return '<tr>'
          + '<td><span class="history-verdict-badge ' + badgeClass + '">' + score + ' - ' + escHtml(scan.classification || '') + '</span></td>'
          + '<td class="history-url font-mono" title="' + escHtml(fullUrl) + '">' + escHtml(shortUrl) + '</td>'
          + '<td>' + escHtml(brand) + '</td>'
          + '<td>' + escHtml(ageText) + '</td>'
          + '<td class="history-time font-mono">' + escHtml(ts) + ' UTC</td>'
          + '<td class="history-buttons">'
          + '<button type="button" class="history-action-btn load" data-action="reload" data-scan-id="' + scan.id + '" title="Reload scan">\u21ba Load</button>'
          + '<a class="history-action-btn report" href="/api/v1/reports/' + scan.id + '/html" target="_blank" title="Export HTML">\ud83d\udcc4 Report</a>'
          + '</td></tr>';
      }).join('');

      tableBody.querySelectorAll('[data-action="reload"]').forEach(function(btn) {
        btn.addEventListener('click', async function() {
          await reloadScan(Number(btn.getAttribute('data-scan-id')));
        });
      });
    }
  } catch (err) {
    state.historyLoaded = false;
    if (emptyState) {
      emptyState.innerHTML  = '<p style="color:#ff7582;">Failed to load history: ' + escHtml(err.message) + '</p>';
      emptyState.style.display = '';
    }
  }
}

async function reloadScan(scanId) {
  try {
    var res  = await fetch('/api/v1/history/' + scanId);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    var scan = await readJsonResponse(res);
    var fullResp = scan.details || scan.full_response || {};
    var syntheticData = {
      scan_id:              scan.id,
      normalized_url:       scan.normalized_url || scan.url,
      risk_score:           scan.risk_score,
      confidence:           scan.confidence,
      classification:       scan.classification,
      reasons_increasing:   fullResp.reasons_increasing   || [],
      reasons_decreasing:   fullResp.reasons_decreasing   || [],
      signal_contributions: fullResp.signal_contributions || [],
      reputation_gap_warning: fullResp.reputation_gap_warning || false,
      features:       fullResp.features       || {},
      brand_analysis: fullResp.brand_analysis || {},
      virustotal:     fullResp.virustotal     || {},
      ml:             fullResp.ml             || { available: false },
      threat_graph:   fullResp.threat_graph   || { nodes: [], edges: [], summary: {}, threat_indicators: [] },
    };
    if ($urlInput) $urlInput.value = scan.url || scan.normalized_url || '';
    renderResults(syntheticData);
  } catch (err) {
    showError('Failed to reload scan #' + scanId + ': ' + err.message);
  }
}

async function clearHistory() {
  if (!confirm('Clear all investigation history? This cannot be undone.')) return;
  try {
    var res = await fetch('/api/v1/history', { method: 'DELETE' });
    var result = await readJsonResponse(res);
    if (!res.ok) throw new Error(result.detail || ('HTTP ' + res.status));
    state.historyLoaded = false;
    loadHistory();
  } catch (err) {
    showError('Failed to clear history: ' + err.message);
  }
}

// -----------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
  $scanForm             = document.getElementById('scan-form');
  $urlInput             = document.getElementById('url-input');
  $scanButton           = document.getElementById('scan-button');
  $errorAlert           = document.getElementById('error-alert');
  $resultsView          = document.getElementById('results-view');
  $overviewEmpty        = document.getElementById('overview-empty');
  $riskScoreValue       = document.getElementById('risk-score-value');
  $gaugeArc             = document.getElementById('gauge-arc');
  $riskClassBadge       = document.getElementById('risk-class-badge');
  $normalizedUrlDisplay = document.getElementById('normalized-url-display');
  $confidenceFill       = document.getElementById('confidence-fill');
  $confidenceValue      = document.getElementById('confidence-value');
  $reputationGapAlert   = document.getElementById('reputation-gap-alert');
  $reasonsUpList        = document.getElementById('reasons-up-list');
  $reasonsDownList      = document.getElementById('reasons-down-list');
  $reasonsDownContainer = document.getElementById('reasons-down-container');
  $signalsContainer     = document.getElementById('signals-container');
  $featuresSummaryList  = document.getElementById('features-summary-list');
  $brandMiniContent     = document.getElementById('brand-mini-content');
  $vtMiniContent        = document.getElementById('vt-mini-content');
  $mlMiniContent        = document.getElementById('ml-mini-content');
  $tabBtns              = document.querySelectorAll('.nav-tab-btn');
  $tabPanes             = document.querySelectorAll('.tab-pane');
  
  $investigationType    = document.getElementById('investigation-type');
  $fileInput            = document.getElementById('file-input');
  $tabBtnFile           = document.getElementById('tab-btn-file');
  $fileResultsContainer = document.getElementById('file-results-container');
  $fileResultsBody      = document.getElementById('file-results-body');
  $fileResultsTitle     = document.getElementById('file-results-title');

  if ($investigationType && $urlInput && $fileInput) {
    $investigationType.addEventListener('change', function() {
      var scanLabel = document.querySelector('.scan-form__label');
      if (this.value === 'url') {
        $urlInput.style.display = '';
        $urlInput.required = true;
        $urlInput.placeholder = 'e.g. paypa1-login-security.com/verify';
        if (scanLabel) scanLabel.textContent = 'Enter a URL to investigate';
        $fileInput.style.display = 'none';
        $fileInput.required = false;
      } else if (this.value === 'email_id') {
        $urlInput.style.display = '';
        $urlInput.required = true;
        $urlInput.placeholder = 'e.g. security@paypa1-login.com or victim@mailinator.com';
        if (scanLabel) scanLabel.textContent = 'Enter an Email ID / Address to investigate';
        $fileInput.style.display = 'none';
        $fileInput.required = false;
      } else if (this.value === 'email') {
        $urlInput.style.display = 'none';
        $urlInput.required = false;
        $fileInput.style.display = '';
        $fileInput.required = true;
        $fileInput.accept = '.eml';
        if (scanLabel) scanLabel.textContent = 'Select an Email (.eml) message file to dissect';
      } else {
        $urlInput.style.display = 'none';
        $urlInput.required = false;
        $fileInput.style.display = '';
        $fileInput.required = true;
        $fileInput.accept = '*/*';
        if (scanLabel) scanLabel.textContent = 'Select a generic file to calculate cryptographic hashes';
      }
    });
  }

  if ($scanForm) {
    $scanForm.addEventListener('submit', function(e) {
      e.preventDefault();
      
      var type = $investigationType ? $investigationType.value : 'url';
      
      if (type === 'url') {
        var url = ($urlInput ? $urlInput.value : '').trim();
        if (!url) { showError('Please enter a URL to analyze.'); return; }
        submitScan(url);
      } else if (type === 'email_id') {
        var email = ($urlInput ? $urlInput.value : '').trim();
        if (!email) { showError('Please enter an Email ID to investigate.'); return; }
        submitEmailIdScan(email);
      } else {
        var file = $fileInput && $fileInput.files.length > 0 ? $fileInput.files[0] : null;
        if (!file) { showError('Please select a file to upload.'); return; }
        submitFileUpload(file, type);
      }
    });
  }

  document.querySelectorAll('.sample-pill').forEach(function(pill) {
    pill.addEventListener('click', function() {
      var sampleVal = pill.getAttribute('data-val') || pill.getAttribute('data-url');
      var sampleType = pill.getAttribute('data-type') || 'url';
      if ($investigationType) {
        $investigationType.value = sampleType;
        $investigationType.dispatchEvent(new Event('change'));
      }
      if ($urlInput) $urlInput.value = sampleVal;
      if (sampleType === 'email_id') {
        submitEmailIdScan(sampleVal);
      } else {
        submitScan(sampleVal);
      }
    });
  });

  // Forensics subpane mode switcher
  document.querySelectorAll('.forensics-mode-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      switchForensicsMode(btn.getAttribute('data-mode'));
    });
  });

  // Forensics tab Email ID submit & sample buttons
  var tabEmailBtn = document.getElementById('tab-email-btn');
  var tabEmailInput = document.getElementById('tab-email-input');
  if (tabEmailBtn && tabEmailInput) {
    tabEmailBtn.addEventListener('click', function() {
      submitEmailIdScan(tabEmailInput.value);
    });
    tabEmailInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        submitEmailIdScan(tabEmailInput.value);
      }
    });
  }

  document.querySelectorAll('.forensics-sample-pill').forEach(function(pill) {
    pill.addEventListener('click', function() {
      var sampleEmail = pill.getAttribute('data-email');
      if (tabEmailInput) tabEmailInput.value = sampleEmail;
      submitEmailIdScan(sampleEmail);
    });
  });

  // Forensics tab Email File (.eml) upload
  var tabEmlBtn = document.getElementById('tab-eml-btn');
  var tabEmlFile = document.getElementById('tab-eml-file');
  if (tabEmlBtn && tabEmlFile) {
    tabEmlBtn.addEventListener('click', function() {
      var file = tabEmlFile.files && tabEmlFile.files[0];
      if (!file) { showError('Please select a .eml file to upload.'); return; }
      submitFileUpload(file, 'email');
    });
  }

  // Forensics tab Generic File hash scan
  var tabGenericBtn = document.getElementById('tab-generic-btn');
  var tabGenericFile = document.getElementById('tab-generic-file');
  if (tabGenericBtn && tabGenericFile) {
    tabGenericBtn.addEventListener('click', function() {
      var file = tabGenericFile.files && tabGenericFile.files[0];
      if (!file) { showError('Please select a file to compute hashes.'); return; }
      submitFileUpload(file, 'file');
    });
  }

  $tabBtns.forEach(function(btn) {
    btn.addEventListener('click', function() { activateTab(btn.getAttribute('data-tab')); });
  });

  var runAdversarialBtn = document.getElementById('run-adversarial-btn');
  if (runAdversarialBtn) runAdversarialBtn.addEventListener('click', runAdversarialTest);

  var refreshHistoryBtn = document.getElementById('refresh-history-btn');
  if (refreshHistoryBtn) {
    refreshHistoryBtn.addEventListener('click', function() {
      state.historyLoaded = false;
      loadHistory();
    });
  }

  var clearHistoryBtn = document.getElementById('clear-history-btn');
  if (clearHistoryBtn) clearHistoryBtn.addEventListener('click', clearHistory);

  setTimeout(function() { if (state.currentTab === 'history') loadHistory(); }, 800);
});
