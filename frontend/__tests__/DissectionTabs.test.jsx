import { describe, test, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import DissectionTabs from '../src/components/DissectionTabs'

vi.mock('../src/components/tabs/ManifestTab', () => ({ default: () => <div>ManifestTab</div> }))
vi.mock('../src/components/tabs/PermissionsTab', () => ({ default: () => <div>PermissionsTab</div> }))
vi.mock('../src/components/tabs/ComponentsTab', () => ({ default: () => <div>ComponentsTab</div> }))
vi.mock('../src/components/tabs/CodeTab', () => ({ default: () => <div>CodeTab</div> }))
vi.mock('../src/components/tabs/StringsTab', () => ({ default: () => <div>StringsTab</div> }))
vi.mock('../src/components/tabs/DEXTab', () => ({ default: () => <div>DEXTab</div> }))
vi.mock('../src/components/tabs/NativeLibsTab', () => ({ default: () => <div>NativeLibsTab</div> }))

describe('DissectionTabs', () => {
  test('renders all tab buttons', () => {
    render(<DissectionTabs sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('Manifest')).toBeTruthy()
    expect(screen.getByText('Permissions')).toBeTruthy()
    expect(screen.getByText('Components')).toBeTruthy()
    expect(screen.getByText('Code')).toBeTruthy()
    expect(screen.getByText('Strings')).toBeTruthy()
    expect(screen.getByText('DEX')).toBeTruthy()
    expect(screen.getByText('Native Libs')).toBeTruthy()
  })

  test('defaults to Manifest tab', () => {
    render(<DissectionTabs sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('ManifestTab')).toBeTruthy()
  })

  test('switches tabs on click', () => {
    render(<DissectionTabs sampleId="test-001" apiUrl="http://localhost:8000" />)
    expect(screen.getByText('ManifestTab')).toBeTruthy()
    fireEvent.click(screen.getByText('Permissions'))
    expect(screen.getByText('PermissionsTab')).toBeTruthy()
  })

  test('switches to each tab', () => {
    render(<DissectionTabs sampleId="test-001" apiUrl="http://localhost:8000" />)
    const tabs = ['Code', 'Strings', 'DEX', 'Native Libs', 'Components']
    tabs.forEach(label => {
      fireEvent.click(screen.getByText(label))
      expect(screen.getByText(`${label === 'Native Libs' ? 'NativeLibs' : label}Tab`)).toBeTruthy()
    })
  })
})
