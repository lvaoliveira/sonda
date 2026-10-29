import type { ReactNode } from 'react'
import { ApiContext } from './apiContext'
import type { SondaApi } from './types'

/** Supplies the API implementation: the mock today, `sonda server` later. */
export function ApiProvider({ api, children }: { api: SondaApi; children: ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>
}
