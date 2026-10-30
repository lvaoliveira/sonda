import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { ApiProvider } from '@/api/ApiProvider'
import { createMockApi, MOCK_PASSWORD } from '@/api/mock'
import type { SondaApi } from '@/api/types'
import { AppRoutes } from '@/App'
import { SessionGate } from '@/components/shell/SessionGate'
import { PipMeter } from '@/components/sonda/meters'
import { GateStatus } from '@/components/sonda/status'

function renderAt(path: string, api: SondaApi = createMockApi(0)) {
  return render(
    <ApiProvider api={api}>
      <MemoryRouter initialEntries={[path]}>
        <SessionGate>
          <AppRoutes />
        </SessionGate>
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

  it('changes status with an undo, through the API, and records it', async () => {
    const user = userEvent.setup()
    renderAt('/issues')
    const detail = await screen.findByRole('article', { name: 'Issue detail' })
    await within(detail).findByRole('button', { name: 'Accept risk' })
    expect(within(detail).getByText('No triage changes yet.')).toBeInTheDocument()
    const row = within(screen.getByRole('listbox', { name: 'Issues' })).getAllByRole('option')[0]
    const before = within(row).getByText(/^(Open|Confirmed)$/).textContent ?? ''
    await user.click(within(detail).getByRole('button', { name: 'Accept risk' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Marked accepted')
    await waitFor(() => expect(within(row).getByText('Accepted')).toBeInTheDocument())
    expect(await within(detail).findByText(/→ accepted/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(within(row).getByText(before)).toBeInTheDocument())
  })

  it('offers no "assign to me" without a name', async () => {
    const api = createMockApi(0)
    const shell = api.shell
    renderAt('/issues', { ...api, shell: async () => ({ ...(await shell()), me: null }) })
    const detail = await screen.findByRole('article', { name: 'Issue detail' })
    expect(await within(detail).findByRole('button', { name: /sign in with a name/ })).toBeDisabled()
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
    // The detail loads after the list.
    const links = await within(detail).findAllByRole('link')
    const ruleLink = links.find((a) => a.getAttribute('href')?.startsWith('/rules#'))
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

  it('is read-only and shows how to configure a rule in sonda.toml', async () => {
    renderAt('/rules#py/broad-except')
    await screen.findByRole('heading', { level: 2, name: /bare or broad except/ })
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
    expect(screen.getByText(/disabled = \["py\/broad-except"\]/)).toBeInTheDocument()
  })

  it('shows how to turn on a rule that is off by default', async () => {
    renderAt('/rules#rust/undocumented-unsafe')
    const detail = await screen.findByRole('article')
    expect(within(detail).getByText('Off by default')).toBeInTheDocument()
    expect(within(detail).getByText(/enabled = \["rust\/undocumented-unsafe"\]/)).toBeInTheDocument()
  })

  it('shows the CWE and OWASP standards a rule relates to', async () => {
    renderAt('/rules#go/sql-string-concat')
    const detail = await screen.findByRole('article')
    expect(within(detail).getByRole('link', { name: 'CWE-89' })).toHaveAttribute('href', 'https://cwe.mitre.org/data/definitions/89.html')
    expect(detail).toHaveTextContent('OWASP A05:2025 Injection')
    expect(detail).toHaveTextContent('A03:2021 Injection')
  })

  it('selects the rule named in the URL hash', async () => {
    renderAt('/rules#py/broad-except')
    const detail = await screen.findByRole('heading', { level: 2, name: /bare or broad except/ })
    expect(detail).toBeInTheDocument()
  })
})

describe('Projects', () => {
  it('lists projects, filters them by gate, language and name, and keeps the filters in the URL', async () => {
    const user = userEvent.setup()
    renderAt('/projects')
    const table = await screen.findByRole('table')
    const names = () => within(table).getAllByRole('row').slice(1).map((r) => within(r).getAllByRole('link')[0].textContent)
    // Lowest score first.
    expect(names()[0]).toBe('billing-service')
    expect(names()).toHaveLength(8)
    await user.click(screen.getByRole('button', { name: /^Blocking/ }))
    expect(names()).toEqual(['billing-service', 'ml-feature-store', 'payments-platform', 'mobile-bff'])
    await user.click(screen.getByRole('button', { name: 'Java' }))
    expect(names()).toEqual(['billing-service'])
    await user.type(screen.getByRole('textbox', { name: 'Search projects' }), 'zzz')
    expect(await screen.findByText('No projects match these filters')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(within(await screen.findByRole('table')).getAllByRole('row')).toHaveLength(9)
  })

  it('opens a project with its gate, measures, history and components', async () => {
    const user = userEvent.setup()
    renderAt('/projects')
    await user.click(await screen.findByRole('link', { name: 'payments-platform' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'payments-platform' })).toBeInTheDocument()
    expect(screen.getByText(/2 of 4 conditions failing/)).toBeInTheDocument()
    expect(screen.getAllByRole('img', { name: 'Failing' })).toHaveLength(2)
    expect(screen.getByRole('heading', { name: 'History' })).toBeInTheDocument()
    expect(screen.getByText('services/')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'New code' }))
    // The main branch: new code since its current version's first analysis (ADR-0011).
    expect(screen.getByText(/new lines since .* \(version 2\.4\.0\)/)).toBeInTheDocument()
    expect(screen.getByText(/Issues first seen after analysis/)).toBeInTheDocument()
    // Its coverage is per file, so the server computed it; duplication is the scan's.
    expect(screen.getByText('on changed lines')).toBeInTheDocument()
    expect(screen.getByText('in lines the scan changed')).toBeInTheDocument()
  })

  it('lets an admin start the main branch’s new code at a later analysis', async () => {
    const user = userEvent.setup()
    renderAt('/projects/billing-service')
    await screen.findByRole('heading', { level: 1, name: 'billing-service' })
    await user.click(screen.getByRole('button', { name: 'New code' }))
    const start = await screen.findByRole('combobox', { name: 'Start new code at' })
    const options = within(start).getAllByRole('option')
    await user.selectOptions(start, options[0])
    // The page reloads (the gate and new-code measures change): wait for
    // the old view to go before opening New code again.
    const reopen = async (button: string) => {
      await user.click(screen.getByRole('button', { name: button }))
      await waitFor(() => expect(screen.queryByRole('button', { name: button })).not.toBeInTheDocument())
      await user.click(await screen.findByRole('button', { name: 'New code' }))
    }
    await reopen('Start new code here')
    expect(await screen.findByText(/\(set by an admin\)/)).toBeInTheDocument()
    await reopen('Back to the default start')
    expect(await screen.findByText(/\(the first analysis\)/)).toBeInTheDocument()
  })

  it('switches branches through the URL and explains unknown ones', async () => {
    const user = userEvent.setup()
    renderAt('/projects/payments-platform')
    await user.selectOptions(await screen.findByRole('combobox'), 'release/2.4')
    expect(await screen.findByText(/0 of 4 conditions failing/)).toBeInTheDocument()
    renderAt('/projects/payments-platform?branch=gone')
    expect(await screen.findByText(/analyzed branches: main, release\/2.4/)).toBeInTheDocument()
  })

  it("links a project's issues to the Issues page, filtered to it", async () => {
    renderAt('/issues?project=billing-service')
    expect(await screen.findByText(/Showing billing-service — from the metric you clicked/)).toBeInTheDocument()
    expect(screen.getByText(/billing-service on its main branch/)).toBeInTheDocument()
    // billing-service has two of the mock's issues; the accepted one is filtered out by default.
    const rows = within(screen.getByRole('listbox', { name: 'Issues' })).getAllByRole('option')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toHaveTextContent('StripeConfig.java')
  })
})

describe('Dependencies', () => {
  it('summarizes a project\'s dependencies and lists them with filters and changes', async () => {
    renderAt('/projects/payments-platform')
    const card = await screen.findByRole('region', { name: 'Dependencies' })
    expect(card).toHaveTextContent('17 packages')
    expect(card).toHaveTextContent('6 direct')
    expect(within(card).getByRole('link', { name: '2 with known vulnerabilities' })).toHaveAttribute('href', '/projects/payments-platform/dependencies')
    expect(within(card).getByRole('link', { name: 'All 17 →' })).toHaveAttribute('href', '/projects/payments-platform/dependencies')

    const user = userEvent.setup()
    renderAt('/projects/payments-platform/dependencies')
    const packages = await screen.findByRole('region', { name: 'Packages' })
    const rows = () => within(packages).getAllByRole('row').slice(1)
    expect(rows()).toHaveLength(17)
    await user.type(within(packages).getByRole('searchbox', { name: 'Search packages' }), 'lodash')
    expect(rows()).toHaveLength(1)
    expect(rows()[0]).toHaveTextContent('pkg:npm/lodash@4.17.20')
    expect(rows()[0]).toHaveTextContent('package-lock.json, web/package-lock.json')
    await user.clear(within(packages).getByRole('searchbox', { name: 'Search packages' }))
    await user.click(within(packages).getByRole('button', { name: 'PyPI' }))
    expect(rows()).toHaveLength(3)
    await user.click(within(packages).getByRole('button', { name: 'All' }))
    await user.click(within(packages).getByRole('button', { name: 'Direct only' }))
    expect(rows()).toHaveLength(6)
    expect(screen.getByRole('region', { name: 'Changed' })).toHaveTextContent('updated express 4.18.2 → 4.19.2')
    expect(screen.getByRole('region', { name: 'Licenses' })).toHaveTextContent('not recorded')

    // Known vulnerabilities, from imported advisories.
    expect(screen.getByRole('region', { name: 'Dependency counts' })).toHaveTextContent('Vulnerable2')
    const vulns = screen.getByRole('region', { name: 'Vulnerabilities' })
    const items = within(vulns).getAllByRole('listitem')
    expect(items[0]).toHaveTextContent('Command Injection in lodash')
    expect(items[0]).toHaveTextContent('fixed in 4.17.21')
    expect(within(items[0]).getByRole('link', { name: 'GHSA-35jh-r3h4-6jhm' })).toHaveAttribute('href', 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm')
    expect(items[1]).toHaveTextContent('requests 2.31.0')
    await user.click(within(packages).getByRole('button', { name: 'Direct only' }))
    await user.click(within(packages).getByRole('button', { name: 'Vulnerable only' }))
    expect(rows()).toHaveLength(2)

    // Accepting needs a reason; it then stops counting, and can be reopened.
    const finding = within(vulns).getByRole('listitem', { name: 'GHSA-35jh-r3h4-6jhm in lodash 4.17.20' })
    await user.click(within(finding).getByRole('button', { name: 'Accept…' }))
    const accept = within(finding).getByRole('button', { name: 'Accept' })
    expect(accept).toBeDisabled()
    await user.type(within(finding).getByRole('textbox'), 'Only used by the build, never on user input.')
    await user.click(accept)
    expect(await within(finding).findByText(/Accepted by mara/)).toHaveTextContent('“Only used by the build, never on user input.”')
    expect(screen.getByRole('region', { name: 'Dependency counts' })).toHaveTextContent('Vulnerable1')
    await user.click(within(finding).getByRole('button', { name: 'Reopen' }))
    await waitFor(() => expect(screen.getByRole('region', { name: 'Dependency counts' })).toHaveTextContent('Vulnerable2'))
  })

  it('says so when an analysis recorded none', async () => {
    renderAt('/projects/payments-platform?branch=release%2F2.4')
    const card = await screen.findByRole('region', { name: 'Dependencies' })
    expect(card).toHaveTextContent('None recorded in this analysis')
    expect(within(card).queryByRole('link')).not.toBeInTheDocument()
  })
})

describe('Coverage', () => {
  it('opens from the project, then walks directories down to a file’s uncovered lines', async () => {
    const user = userEvent.setup()
    renderAt('/projects/payments-platform')
    await user.click(await screen.findByRole('link', { name: /%$/ }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Coverage' })).toBeInTheDocument()
    // The root: directories add up their files, the biggest gaps first.
    const rows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1)
    expect(rows().map((r) => within(r).getByRole('link').textContent)).toEqual(['src/', 'scripts/'])
    expect(within(rows()[0]).getByText('1 without data')).toBeInTheDocument()

    await user.click(screen.getByRole('link', { name: 'src/' }))
    expect(await screen.findByRole('navigation', { name: 'Directory' })).toHaveTextContent('All files/src')
    await user.click(screen.getByRole('button', { name: 'Name' }))
    expect(rows().map((r) => within(r).getByRole('link').textContent)).toEqual(['api/', 'billing/', 'generated/', 'util/', 'index.ts'])
    await user.click(screen.getByRole('link', { name: 'billing/' }))
    await user.click(await screen.findByRole('link', { name: 'refunds.ts' }))

    // Every coverable line of refunds.ts is uncovered: one block to step to.
    expect(await screen.findByRole('heading', { level: 1, name: 'refunds.ts' })).toBeInTheDocument()
    expect(screen.getByText(/0\.0% · 0 of 21 lines covered/)).toBeInTheDocument()
    expect(screen.getByText('1 uncovered block')).toBeInTheDocument()
    const source = screen.getByRole('region', { name: 'Source code with coverage' })
    expect(source.querySelectorAll('[data-coverage="uncovered"]')).toHaveLength(21)
    expect(source.querySelectorAll('[data-coverage="covered"]')).toHaveLength(0)
  })

  it('searches files across directories and keeps only those with gaps', async () => {
    const user = userEvent.setup()
    renderAt('/projects/payments-platform/coverage')
    await user.type(await screen.findByRole('searchbox', { name: 'Search files' }), 'auth')
    const names = () => within(screen.getByRole('table')).getAllByRole('link').map((l) => l.textContent)
    expect(names()).toEqual(['src/api/auth/session.ts', 'src/api/auth/tokens.ts'])
    await user.clear(screen.getByRole('searchbox', { name: 'Search files' }))
    await user.click(screen.getByRole('button', { name: 'With uncovered lines' }))
    await user.click(screen.getByRole('link', { name: 'src/' }))
    expect(await screen.findByRole('link', { name: 'index.ts' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'generated/' })).not.toBeInTheDocument()
  })

  it('explains how to get coverage when the analysis has none', async () => {
    renderAt('/projects/docs-site/coverage')
    expect(await screen.findByText('No coverage per file in this analysis')).toBeInTheDocument()
  })
})

describe('Analyses', () => {
  it('lists analyses newest first, filters by gate and project, and pages', async () => {
    const user = userEvent.setup()
    renderAt('/analyses')
    const list = await screen.findByRole('list', { name: 'Analyses' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(16)
    expect(screen.getByText('16 analyses · newest first · every branch')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Blocking' }))
    const failed = within(await screen.findByRole('list', { name: 'Analyses' })).getAllByRole('listitem')
    expect(failed).toHaveLength(4)
    for (const row of failed) expect(row).toHaveTextContent('Gate failed: New vulnerabilities > 0 (+1)')
    await user.selectOptions(screen.getByRole('combobox'), 'billing-service')
    expect(within(await screen.findByRole('list', { name: 'Analyses' })).getAllByRole('listitem')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  })

  it('shows an analysis: result, what changed, warnings, and its neighbors', async () => {
    const user = userEvent.setup()
    renderAt('/analyses')
    await user.click(within(await screen.findByRole('list', { name: 'Analyses' })).getAllByRole('link', { name: 'payments-platform' })[0])
    expect(await screen.findByText('Analysis · payments-platform')).toBeInTheDocument()
    expect(screen.getByText(/2 of 4 conditions failing/)).toBeInTheDocument()
    expect(screen.getByText('+14')).toBeInTheDocument()
    expect(screen.getByText('2 critical · 5 major')).toBeInTheDocument()
    const introduced = screen.getByRole('region', { name: /Introduced/ })
    expect(within(introduced).getByText('Remove this use of eval().')).toBeInTheDocument()
    expect(within(introduced).getByRole('link', { name: 'js/no-eval' })).toHaveAttribute('href', '/rules#js%2Fno-eval')
    expect(within(introduced).getByRole('link', { name: 'services/checkout-api/handlers.js:88' })).toHaveAttribute(
      'href',
      '/issues?project=payments-platform&branch=main&file=services%2Fcheckout-api%2Fhandlers.js',
    )
    expect(screen.getByRole('region', { name: 'Warnings' })).toHaveTextContent('skipped, looks minified')
    await user.click(screen.getByRole('link', { name: /^← / }))
    expect(await screen.findByText(/0 of 4 conditions failing/)).toBeInTheDocument()
  })

  it('is reached from the Overview and from a project', async () => {
    const user = userEvent.setup()
    renderAt('/projects/payments-platform')
    await user.click(await screen.findByRole('link', { name: '9f3c2a1e7' }))
    expect(await screen.findByText('Analysis · payments-platform')).toBeInTheDocument()
  })
})

describe('Components', () => {
  it('lists components across projects, filtered by project, owner and search', async () => {
    const user = userEvent.setup()
    renderAt('/components')
    const table = await screen.findByRole('table')
    expect(within(table).getAllByRole('row').length).toBeGreaterThan(20)
    await user.selectOptions(screen.getByRole('combobox', { name: 'Owner' }), '@checkout')
    const rows = within(screen.getByRole('table')).getAllByRole('row').slice(1)
    for (const row of rows) expect(row).toHaveTextContent('@checkout')
    await user.selectOptions(screen.getByRole('combobox', { name: 'Project' }), 'billing-service')
    expect(within(screen.getByRole('table')).getAllByRole('row').slice(1)).toHaveLength(1)
    await user.type(screen.getByRole('textbox', { name: 'Search components' }), 'nothing-here')
    expect(await screen.findByText('No components match these filters')).toBeInTheDocument()
  })

  it('opens a component from its project, with issues, trend, owners and files', async () => {
    const user = userEvent.setup()
    renderAt('/projects/payments-platform')
    await user.click(await screen.findByRole('link', { name: 'services/' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'services/' })).toBeInTheDocument()
    expect(screen.getByText('Component · payments-platform')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'payments-platform components' })).toHaveTextContent('packages/')
    expect(screen.getByRole('heading', { name: 'Open issues · 8 weeks' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Owners' })).toHaveTextContent('@checkout')
    const files = screen.getByRole('region', { name: 'Files' })
    expect(within(files).getAllByRole('link')[0]).toHaveAttribute('href', '/issues?project=payments-platform&branch=main&file=services%2Finternal%2Fhandlers.go')
    await user.click(within(files).getByRole('button', { name: 'Path' }))
    expect(within(files).getAllByRole('link')[0]).toHaveTextContent('config.go')
    await user.click(screen.getByRole('link', { name: /packages\// }))
    expect(await screen.findByRole('heading', { level: 1, name: 'packages/' })).toBeInTheDocument()
  })
})

describe('Security', () => {
  it('shows open vulnerabilities, what to fix first, risk and where they concentrate', async () => {
    renderAt('/security')
    expect(await screen.findByText(/23 open vulnerabilities in 6 projects/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Triage vulnerabilities' })).toHaveAttribute('href', '/issues?cat=vulnerability')
    const focus = screen.getByRole('region', { name: 'Fix these first' })
    const items = within(focus).getAllByRole('listitem')
    expect(items[0]).toHaveTextContent('Blocker')
    expect(items[items.length - 1]).toHaveTextContent('Major')
    expect(within(focus).getByRole('link', { name: 'js/no-eval' })).toHaveAttribute('href', '/rules#js%2Fno-eval')
    expect(screen.getByRole('region', { name: /Risk · 12 weeks/ })).toHaveTextContent('−')
    expect(screen.getByRole('region', { name: 'High-risk components' })).toHaveTextContent('billing-service/src/')
    expect(screen.getByRole('region', { name: 'Remediation' })).toHaveTextContent('4.2 days')
    const deps = screen.getByRole('region', { name: 'Vulnerable dependencies' })
    expect(deps).toHaveTextContent('2 vulnerable packages in 2 projects')
    expect(within(deps).getByRole('link', { name: 'payments-platform' })).toHaveAttribute('href', '/projects/payments-platform/dependencies')
    expect(deps).toHaveTextContent('fixed in 4.17.21')
    expect(within(focus).getAllByRole('link', { name: 'CWE-798' })[0]).toHaveAttribute('href', 'https://cwe.mitre.org/data/definitions/798.html')
    // The 2025 edition by default, 2021 a click away.
    const owasp = screen.getByRole('region', { name: 'OWASP Top 10' })
    let categories = within(within(owasp).getByRole('list', { name: 'OWASP Top 10 2025 categories' })).getAllByRole('listitem')
    expect(categories).toHaveLength(10)
    expect(categories[4]).toHaveTextContent('A05Injection3')
    expect(categories[6]).toHaveTextContent('A07Authentication Failures11')
    expect(within(categories[6]).getByRole('link', { name: 'js/hardcoded-password' })).toHaveAttribute('href', '/rules#js%2Fhardcoded-password')
    expect(owasp).toHaveTextContent('1 open vulnerability has no category in the 2025 edition')
    await userEvent.setup().click(within(owasp).getByRole('button', { name: '2021' }))
    categories = within(within(owasp).getByRole('list', { name: 'OWASP Top 10 2021 categories' })).getAllByRole('listitem')
    expect(categories[2]).toHaveTextContent('A03Injection3')
  })
})

describe('Quality gates', () => {
  it('shows each gate with its conditions, projects and evaluations, read-only', async () => {
    const user = userEvent.setup()
    renderAt('/gates')
    const list = await screen.findByRole('list', { name: 'Gates' })
    const [first, second] = within(list).getAllByRole('button')
    expect(first).toHaveTextContent('Default')
    expect(first).toHaveTextContent('sonda default')
    expect(screen.getByRole('region', { name: 'Default' })).toHaveTextContent('Coverage on new code < 80%')
    expect(screen.getByRole('region', { name: 'Configure' })).toHaveTextContent('metric = "new_coverage"')
    await user.click(second)
    expect(screen.getByRole('region', { name: 'Custom gate 1' })).toHaveTextContent('Coverage < 70%')
    expect(screen.getByRole('region', { name: 'Assigned to' })).toHaveTextContent('payments-platform')
    const evaluations = screen.getByRole('list', { name: 'Evaluations, newest first' })
    expect(within(evaluations).getAllByRole('link')).toHaveLength(40)
    expect(screen.getByText('New vulnerabilities > 0', { selector: 'span' })).toBeInTheDocument()
  })

  it('says so for an unknown address', async () => {
    renderAt('/nowhere')
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument()
  })
})

describe('Signing in', () => {
  it('requires a username and password when the server requires them to read', async () => {
    const user = userEvent.setup()
    renderAt('/rules', createMockApi(0, { signedIn: false, readsRequireAuth: true }))
    expect(await screen.findByRole('heading', { name: 'Sign in to sonda' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Continue read-only' })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Username'), 'dev')
    await user.type(screen.getByLabelText('Password'), 'wrong password')
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password')
    await user.clear(screen.getByLabelText('Password'))
    await user.type(screen.getByLabelText('Password'), MOCK_PASSWORD)
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Rules' })).toBeInTheDocument()
    // A member sees no administration.
    expect(screen.queryByRole('link', { name: /Administration/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Dev Patel/ })).toHaveAttribute('href', '/account')
  })

  it('lets a viewer continue read-only where reads are open, and sign out', async () => {
    const user = userEvent.setup()
    renderAt('/rules', createMockApi(0, { signedIn: false, readsRequireAuth: false }))
    await user.click(await screen.findByRole('button', { name: 'Continue read-only' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Rules' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument()
  })

  it('signs out back to the sign-in page', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'Sign in to sonda' })).toBeInTheDocument()
  })
})

describe('Users', () => {
  it('lets an admin add users and refuses to remove the last admin', async () => {
    const user = userEvent.setup()
    renderAt('/admin')
    expect(await screen.findByRole('cell', { name: /Dev Patel/ })).toBeInTheDocument()
    await user.type(screen.getByLabelText('Username'), 'bob')
    await user.type(screen.getByLabelText('Display name'), 'Bob Builder')
    await user.type(screen.getByLabelText('Initial password'), 'a long enough one')
    await user.click(screen.getByRole('button', { name: 'Add user' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Created bob')
    expect(await screen.findByRole('cell', { name: /Bob Builder/ })).toBeInTheDocument()
    // Mara is the only admin: demoting her is refused, and says why.
    await user.selectOptions(screen.getByLabelText('Role of mara'), 'member')
    expect(await screen.findByRole('alert')).toHaveTextContent('last active admin')
  })

  it('keeps administration from members', async () => {
    const user = userEvent.setup()
    renderAt('/admin', createMockApi(0, { signedIn: false, readsRequireAuth: true }))
    await user.type(await screen.findByLabelText('Username'), 'dev')
    await user.type(screen.getByLabelText('Password'), MOCK_PASSWORD)
    await user.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Admins only.')).toBeInTheDocument()
  })

  it('changes your own password', async () => {
    const user = userEvent.setup()
    renderAt('/account')
    await user.type(await screen.findByLabelText('Current password'), MOCK_PASSWORD)
    await user.type(screen.getByLabelText('New password'), 'an even better one')
    await user.type(screen.getByLabelText('Repeat the new password'), 'an even better one')
    await user.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Password changed')
  })
})

describe('Overview', () => {
  it('shows what a server knows, and only that', async () => {
    const user = userEvent.setup()
    const api = createMockApi(0)
    const real = api.overview!
    // What sonda-server returns: no teams, no coverage, no commit messages,
    // and no drill-down data yet.
    const overview: SondaApi['overview'] = async (scope, range) => {
      const o = await real(scope, range)
      return {
        ...o,
        teams: false,
        summary: { ...o.summary, components: null },
        health: { ...o.health, delta: null, dimensions: o.health.dimensions.map((d) => (d.label === 'Coverage' ? { ...d, level: null, score: null } : d)) },
        projects: o.projects.map((p) => ({ ...p, coverage: null, components: undefined })),
        recent: o.recent.map((r) => ({ ...r, message: null, duration: null })),
      }
    }
    renderAt('/', { ...api, overview, drill: undefined })
    const metrics = await screen.findByRole('region', { name: 'Key metrics' })
    expect(screen.queryByRole('button', { name: 'My team' })).not.toBeInTheDocument()
    expect(screen.queryByText(/components ·/)).not.toBeInTheDocument()
    const coverage = screen.getAllByRole('button').find((b) => b.textContent?.startsWith('Coverage'))
    expect(coverage).toHaveTextContent('No data')
    // No comparison is shown, so no "vs 90 days ago" either.
    expect(screen.queryByText(/days ago$/)).not.toBeInTheDocument()
    // Without drill-down data, a metric opens the issues it is about.
    await user.click(within(metrics).getByRole('button', { name: /^Vulnerabilities/ }))
    // The banner exists only once the Issues page has loaded (not its skeleton).
    expect(await screen.findByRole('status')).toHaveTextContent('Showing vulnerabilities')
  })

  it('drills into a metric, then into the issues of one file', async () => {
    const user = userEvent.setup()
    const api = createMockApi(0)
    const real = api.drill!
    // As sonda-server answers: no owners recorded.
    const drill: SondaApi['drill'] = async (metric, scope) => {
      const d = await real(metric, scope)
      return { ...d, items: d.items.map((i) => ({ ...i, owner: null })) }
    }
    renderAt('/', { ...api, drill })
    const metrics = await screen.findByRole('region', { name: 'Key metrics' })
    await user.click(within(metrics).getByRole('button', { name: /^Vulnerabilities/ }))
    const dialog = await screen.findByRole('dialog')
    const first = await within(dialog).findByRole('button', { expanded: true })
    expect(first).not.toHaveTextContent('·')
    await user.click(within(dialog).getAllByRole('button', { name: /repo\.go/ })[0])
    expect(await screen.findByRole('status')).toHaveTextContent('repo.go')
  })

  it('says so honestly when the server has no overview yet', async () => {
    const api = createMockApi(0)
    renderAt('/', { ...api, overview: undefined, drill: undefined })
    expect(await screen.findByText('Trends, ratings and the quality-gate history come next.')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Key metrics' })).not.toBeInTheDocument()
  })

  it('colors each metric by how its value stands, not by its trend', async () => {
    renderAt('/')
    const metrics = await screen.findByRole('region', { name: 'Key metrics' })
    const tone = (label: string) => within(metrics).getByRole('button', { name: new RegExp(`^${label} `) }).dataset.tone
    // 47 blocker or critical issues, 72.4% coverage, 3.1% duplication.
    expect([tone('Blocker \\+ critical'), tone('Coverage'), tone('Duplication')]).toEqual(['crit', 'warn', 'warn'])
  })

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
  it('marks the current page, and every screen in the navigation exists', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    const nav = await screen.findByRole('complementary', { name: 'Primary' })
    expect(within(nav).getByRole('link', { name: /Rules/ })).toHaveAttribute('aria-current', 'page')
    await user.click(within(nav).getByRole('link', { name: /Quality gates/ }))
    expect(await screen.findByRole('heading', { level: 1, name: 'Quality gates' })).toBeInTheDocument()
    // Each screen mounts its own shell, so find the navigation again.
    const after = screen.getByRole('complementary', { name: 'Primary' })
    expect(within(after).getByRole('link', { name: /Quality gates/ })).toHaveAttribute('aria-current', 'page')
    expect(screen.queryByText('Page not found')).not.toBeInTheDocument()
  })

  it('toggles and remembers the theme', async () => {
    const user = userEvent.setup()
    renderAt('/rules')
    await user.click(await screen.findByRole('button', { name: 'Switch to light theme' }))
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('sonda-theme')).toBe('light')
  })
})
