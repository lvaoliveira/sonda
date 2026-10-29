import { createContext } from 'react'
import type { SondaApi } from './types'

export const ApiContext = createContext<SondaApi | null>(null)
