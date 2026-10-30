import { createContext, useContext } from 'react'

export interface SessionActions {
  /** Null when there is no session to end (read-only viewing). */
  signOut: (() => void) | null
}

export const SessionContext = createContext<SessionActions>({ signOut: null })

export function useSessionActions(): SessionActions {
  return useContext(SessionContext)
}
