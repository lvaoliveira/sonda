import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createHttpApi } from '@/api/http'
import type { SondaApi } from '@/api/types'
import { App } from './App'
import { storedTheme } from '@/lib/theme'
import './index.css'

// Apply the saved theme before the first paint to avoid a flash.
document.documentElement.dataset.theme = storedTheme()

const root = document.getElementById('root')
if (!root) throw new Error('missing #root element')

/**
 * The real server, except under `pnpm dev`. The mock is imported lazily so
 * its sample data never ships in a production build.
 */
async function chooseApi(): Promise<SondaApi> {
  if (import.meta.env.VITE_SONDA_API === 'mock') {
    const { createMockApi } = await import('@/api/mock')
    return createMockApi()
  }
  return createHttpApi()
}

void chooseApi().then((api) =>
  createRoot(root).render(
    <StrictMode>
      <App api={api} />
    </StrictMode>,
  ),
)
