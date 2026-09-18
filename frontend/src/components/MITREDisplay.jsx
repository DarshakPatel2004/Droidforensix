import { memo } from 'react'
import './MITREDisplay.css'

const MITRE_MAP = {
  'T1402': 'Device Administration',
  'T1404': 'Exploit Device',
  'T1406': 'Obfuscated Files',
  'T1407': 'Exploit Device',
  'T1408': 'Masquerading',
  'T1411': 'Exfiltration',
  'T1412': 'Modify System Partition',
  'T1418': 'Software Discovery',
  'T1424': 'Process Injection',
  'T1434': 'Distribute Malware',
  'T1509': 'System Network Configuration Discovery',
  'T1516': 'Input Injection',
  'T1517': 'Spearphishing',
  'T1518': 'Software Discovery',
  'T1520': 'Encoder',
  'T1521': 'Command and Control',
  'T1522': 'Exfiltration',
  'T1523': 'Exfiltration',
  'T1524': 'Exfiltration',
  'T1533': 'Exfiltration',
  'T1538': 'Cloud Service Consumption',
  'T1541': 'Exfiltration',
  'T1559': 'Interprocess Communication',
  'T1600': 'Cryptography',
  'T1601': 'Firmware Corruption',
  'T1602': 'Data Encrypted',
  'T1603': 'Proxy',
  'T1604': 'Proxy',
  'T1609': 'Downgrade Attack',
  'T1623': 'Exfiltration',
  'T1624': 'Encrypted Channel',
  'T1625': 'File Deletion',
  'T1626': 'System Information Discovery',
  'T1627': 'Location Tracking',
  'T1628': 'Hide Artifacts',
  'T1629': 'Service Execution',
  'T1630': 'Data from Local System',
  'T1631': 'Interprocess Communication',
  'T1632': 'Native Code',
  'T1801': 'Cryptography',
  'T1802': 'Command and Control',
  'T1803': 'Obfuscated Files',
  'T1804': 'Mobile Device Management Enrollment',
  'T1805': 'Transmitted Data Manipulation',
  'T1806': 'Obfuscated Files',
  'T1809': 'Service Execution',
  'T1812': 'Input Injection',
}

const SEVERITY_MAP = {
  'T1404': 'critical',
  'T1434': 'critical',
  'T1521': 'high',
  'T1524': 'high',
  'T1407': 'high',
  'T1412': 'high',
}

const SEVERITY_COLORS = {
  'critical': '#FF0000',
  'high': '#FF6B6B',
  'medium': '#FFAA00',
  'low': '#FFFF00'
}

function MITREDisplay({ tactics = [] }) {
  if (!tactics || tactics.length === 0) return null

  const getSeverity = (tactic) => SEVERITY_MAP[tactic] || 'medium'
  const getColor = (severity) => SEVERITY_COLORS[severity] || SEVERITY_COLORS.medium
  const getDescription = (tactic) => MITRE_MAP[tactic] || 'Unknown Tactic'

  return (
    <div className="mitre-display">
      <div className="mitre-header">
        <span className="mitre-header-text">MITRE ATT&CK Mobile Tactics</span>
      </div>

      <div className="mitre-tactic-grid">
        {tactics.map((tactic) => {
          const severity = getSeverity(tactic)
          const color = getColor(severity)
          const description = getDescription(tactic)

          return (
            <div
              key={tactic}
              className="mitre-tactic-card"
              style={{ borderLeftColor: color }}
            >
              <div className="mitre-tactic-code" style={{ color }}>
                {tactic}
              </div>
              <div className="mitre-tactic-description">
                {description}
              </div>
              <div className="mitre-tactic-severity">
                <span
                  className="mitre-severity-badge"
                  style={{ backgroundColor: color }}
                >
                  {severity.toUpperCase()}
                </span>
              </div>
            </div>
          )
        })}
      </div>

      <div className="mitre-footer">
        <span className="mitre-footer-text">
          {tactics.length} tactic{tactics.length !== 1 ? 's' : ''} identified
        </span>
      </div>
    </div>
  )
}

export default memo(MITREDisplay)
