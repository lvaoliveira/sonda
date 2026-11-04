/** Where a repository's CI runs, which decides how it gets sonda and reaches the server. */
export type Runner = 'self-hosted' | 'github'

export interface WorkflowOptions {
  project: string
  /** The project's main branch: pushes to it are analyzed. */
  mainBranch: string
  /** The server the runner uploads to. */
  server: string
  runner: Runner
}

export const WORKFLOW_PATH = '.github/workflows/sonda.yml'
export const SECRET_NAME = 'SONDA_TOKEN'

/** `owner/name`, as GitHub allows them (and as the server checks). */
export function isRepository(r: string): boolean {
  return /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/.test(r)
}

/**
 * The `owner/name` a pasted repository names: its URL as the browser shows
 * it (`https://github.com/acme/shop`, any page under it, `.git` or not), its
 * SSH address (`git@github.com:acme/shop.git`), or `owner/name` itself.
 * Null for anything else, another host's included.
 */
export function parseRepository(input: string): string | null {
  const text = input.trim()
  const path = text.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/(.+)$/i)?.[1] ?? text.match(/^git@github\.com:(.+)$/i)?.[1] ?? (text.includes(':') ? null : text)
  if (path === null) return null
  const [owner = '', name = ''] = path.split(/[?#]/, 1)[0].split('/')
  const repository = `${owner}/${name.replace(/\.git$/, '')}`
  return isRepository(repository) ? repository : null
}

/** A project key from a repository's name, as the server allows keys. */
export function projectKeyFor(repository: string): string {
  const name = repository.split('/').pop() ?? ''
  return name.replace(/^[^A-Za-z0-9]+/, '').slice(0, 100)
}

/** Why the runner can't upload to `server`, if it can't. */
export function serverProblem(server: string, runner: Runner): string | null {
  let url: URL
  try {
    url = new URL(server)
  } catch {
    return 'Enter the address the runner uploads to, such as http://localhost:9000.'
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (url.protocol === 'https:' || (url.protocol === 'http:' && local)) {
    if (runner === 'github' && local) return "GitHub's runners can't reach this machine: use the server's public https:// address."
    return null
  }
  return 'sonda sends its token over plain HTTP only to localhost: use http://localhost:PORT on this machine, or an https:// address.'
}

/** The GitHub Actions workflow that scans pushes to the main branch and every pull request. */
export function workflowYaml({ project, mainBranch, server, runner }: WorkflowOptions): string {
  const selfHosted = runner === 'self-hosted'
  const sonda = selfHosted ? '"$HOME/.local/bin/sonda"' : 'sonda'
  const install = selfHosted
    ? ''
    : `      - name: Install sonda
        run: cargo install --locked --git https://github.com/lvaoliveira/sonda sonda
`
  return `# Scans every push to ${mainBranch} and every pull request, and uploads the
# analysis to sonda, which posts each pull request's result on it.
# A failing quality gate fails this job: add continue-on-error: true to the
# scan step to only report it.
name: sonda
on:
  push:
    branches: [${JSON.stringify(mainBranch)}]
  pull_request:
jobs:
  sonda:
    runs-on: ${selfHosted ? 'self-hosted' : 'ubuntu-latest'}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # new code is judged against the base branch
${install}      - name: sonda scan
        env:
          ${SECRET_NAME}: \${{ secrets.${SECRET_NAME} }}
          # Through env, not inline: a branch name is untrusted input.
          BRANCH: \${{ github.head_ref || github.ref_name }}
        run: >
          ${sonda} scan . --upload
          --server ${server} --project ${project}
          --branch "$BRANCH" --commit "$GITHUB_SHA"
`
}

/** GitHub's editor for a new file in `repository`, filled with `content`. */
export function newFileUrl(repository: string, branch: string, path: string, content: string): string {
  const ref = branch.split('/').map(encodeURIComponent).join('/')
  return `https://github.com/${repository}/new/${ref}?filename=${encodeURIComponent(path)}&value=${encodeURIComponent(content)}`
}

/** GitHub's page for adding a repository secret for Actions. */
export function newSecretUrl(repository: string): string {
  return `https://github.com/${repository}/settings/secrets/actions/new`
}

/** The server as a runner on this machine reaches it: the page's own port, on localhost. */
export function localServer(location: Pick<Location, 'protocol' | 'port'>): string {
  const port = location.port || (location.protocol === 'https:' ? '443' : '80')
  return `http://localhost:${port}`
}
