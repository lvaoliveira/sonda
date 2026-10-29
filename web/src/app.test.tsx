import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { ApiProvider } from '@/api/ApiProvider'
import { createMockApi } from '@/api/mock'
import { AppRoutes } from '@/App'
import { PipMeter } from '@/components/sonda/meters'
import { GateStatus } from '@/components/sonda/status'

function renderAt(path: string) {
  return render(
    <ApiProvider api={createMockApi(0)}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </ApiProvider>,
  )
}

describe('primitives', () => {
  it('pip meters fill up to the level and say so', () => {
    const { container } = render(<PipMeter level={3} label="Security" />)
    expect(screen.getByRole('img', { name: 'Security: level 3 of 5' })).toBeInTheDocument()
    expect(container.querySelectorAll('[data-filled="true"]')).toHaveLength(3)
  })

  it('gate status is a word, not only a color', () => {
    render(<GateStatus state="failed" />)
    expect(screen.getByText('Blocking')).toBeInTheDocument()
  })
})

describe('Issues', () => {
  it('applies drill-down links and explains them', async () => {
    renderAt('/issues?cat=vulnerability')
    expect(await screen.findByText(/Showing vulnerabilities — from the metric you clicked/)).toBeInTheDocument()
    const list = screen.getByRole('listbox', { name: 'Issues' })
    const rows = within(list).getAllByRole('option')
    expect(rows.length).toBeGreaterThan(0)
    for (const row of rows) expect(row).toHaveTextContent('Vulnerability')
  })

  it('changes status with an undo, through the API', async () => {
    const user = userEvent.setup()
    renderAt('/issues')
    const detail = await screen.findByRole('article', { name: 'Issue detail' })
    // Read the title first: once accepted, the issue leaves the default
    // (open + confirmed) view and the selection moves to the next one.
    const title = within(detail).getByRole('heading', { level: 2 }).textContent
    await user.click(within(detail).getByRole('button', { name: 'Accept risk' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Marked accepted')
    await waitFor(() => expect(screen.getByRole('listbox', { name: 'Issues' })).not.toHaveTextContent(title ?? ''))
    await user.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(screen.getByRole('listbox', { name: 'Issues' })).toHaveTextContent(title ?? ''))
  })

  it('moves the selection with j and k', async () => {
    const user = userEvent.setup()
    renderAt('/issues')
    const list = await screen.findByRole('listbox', { name: 'Issues' })
    const options = within(list).getAllByRole('option')
    expect(options[0]).toHaveAttribute('aria-selected', 'true')
    await user.keyboard('j')
    expect(within(list).getAllByRole('option')[1]).toHaveAttribute('aria-selected', 'true')
    await user.keyboard('k')
    expect(within(list).getAllByRole('option')[0]).toHaveAttribute('aria-selected', 'true')
  })

  it('links each issue to its rule', async () => {
    renderAt('/issues')
    const detail = await screen.findByRole('article', { name: 'Issue detail' })
    const ruleLink = within(detail).getAllByRole('link').find((a) => a.getAttribute('href')?.startsWith('/rules#'))
    expect(ruleLink).toBeDefined()
  })
})

describe('Rules', () => {
  it('searches by id and tag, with an explicit empty state', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    const search = await screen.findByRole('textbox', { name: 'Search rules' })
    await user.type(search, 'cwe-89')
    expect(within(screen.getByRole('listbox', { name: 'Rules' })).getAllByRole('option')).toHaveLength(1)
    await user.clear(search)
    await user.type(search, 'no-such-rule')
    expect(screen.getByText('No rules match “no-such-rule”')).toBeInTheDocument()
  })

  it('toggles a rule in the profile', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    const toggle = await screen.findByRole('switch')
    const before = toggle.getAttribute('aria-checked')
    await user.click(toggle)
    await waitFor(() => expect(screen.getByRole('switch')).not.toHaveAttribute('aria-checked', before ?? ''))
  })

  it('selects the rule named in the URL hash', async () => {
    renderAt('/rules#py/broad-except')
    const detail = await screen.findByRole('heading', { level: 2, name: /bare or broad except/ })
    expect(detail).toBeInTheDocument()
  })
})

describe('Overview', () => {
  it('opens the drill-down drawer from a metric and closes it with Escape', async () => {
    const user = userEvent.setup()
    renderAt('/')
    const metrics = await screen.findByRole('region', { name: 'Key metrics' })
    await user.click(within(metrics).getByRole('button', { name: /^Vulnerabilities 23/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('heading', { name: '23 open vulnerabilities' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('reloads for the selected scope', async () => {
    const user = userEvent.setup()
    renderAt('/')
    await screen.findByRole('region', { name: 'Key metrics' })
    await user.click(screen.getByRole('button', { name: 'My team' }))
    const metrics = await screen.findByRole('region', { name: 'Key metrics' })
    expect(within(metrics).getByRole('button', { name: /^Gate pass rate 67%/ })).toBeInTheDocument()
  })

  it('expands monorepos into components', async () => {
    const user = userEvent.setup()
    renderAt('/')
    const table = await screen.findByRole('table')
    expect(within(table).getByText('services/checkout-api')).toBeInTheDocument()
    await user.click(within(table).getByText('payments-platform'))
    expect(within(table).queryByText('services/checkout-api')).not.toBeInTheDocument()
  })
})

describe('Shell', () => {
  it('marks the current page and links unbuilt screens to an honest placeholder', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    const nav = screen.getByRole('complementary', { name: 'Primary' })
    expect(within(nav).getByRole('link', { name: /Rules/ })).toHaveAttribute('aria-current', 'page')
    await user.click(within(nav).getByRole('link', { name: /Quality gates/ }))
    expect(await screen.findByText('Designed, not built yet.')).toBeInTheDocument()
  })

  it('toggles and remembers the theme', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('sonda-theme')).toBe('light')
  })
})
