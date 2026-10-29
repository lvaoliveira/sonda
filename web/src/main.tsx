import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createMockApi } from '@/api/mock'
import { App } from './App'
import { storedTheme } from '@/lib/theme'
import './index.css'

// Apply the saved theme before the first paint to avoid a flash.
document.documentElement.dataset.theme = storedTheme()

const root = document.getElementById('root')
if (!root) throw new Error('missing #root element')

createRoot(root).render(
  <StrictMode>
    <App api={createMockApi()} />
  </StrictMode>,
)
