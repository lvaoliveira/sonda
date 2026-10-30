interface ImportMetaEnv {
  /** `mock` for the in-memory API (`pnpm dev`); anything else uses the server. */
  readonly VITE_SONDA_API?: 'mock' | 'http'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
