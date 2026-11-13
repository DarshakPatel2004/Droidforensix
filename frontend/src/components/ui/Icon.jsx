// One drawn icon set, one stroke weight. Replaces emoji glyphs across the viewer.
const PATHS = {
  upload: 'M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3',
  alert: 'M12 9v4m0 4h.01M10.3 3.9 2.6 17a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  error: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-6h.01M12 8v4',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zm0-8v4m0-8h.01',
  help: 'M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z',
  file: 'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6',
  copy: 'M9 9h10v12H9zM5 15H4V4h11v1',
  lock: 'M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5z',
  unlock: 'M7 11V7a5 5 0 0 1 9.9-1M5 11h14v10H5z',
  pin: 'M12 22s7-7.5 7-12a7 7 0 0 0-14 0c0 4.5 7 12 7 12zm0-9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2c3 3.5 3 16.5 0 20M12 2c-3 3.5-3 16.5 0 20',
  sliders: 'M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0',
  chain: 'M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  x: 'M6 6l12 12M18 6L6 18',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm9 3-4.3-4.3',
  inbox: 'M3 13l3-8h12l3 8v6H3zm0 0h5l1 2h6l1-2h5',
  cube: 'M12 2 21 7v10l-9 5-9-5V7zM3 7l9 5 9-5M12 12v10',
}

export default function Icon({ name, size = 18, className }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" className={className}>
      <path d={PATHS[name] || PATHS.help} />
    </svg>
  )
}
