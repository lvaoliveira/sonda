import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { useAsync, type Async, type AsyncOptions } from './hooks'

/** A promise per call, resolved or rejected by the test. */
function deferred() {
  const calls: { arg: string; resolve: (v: string) => void; reject: (e: Error) => void }[] = []
  const load = (arg: string) =>
    new Promise<string>((resolve, reject) => {
      calls.push({ arg, resolve, reject })
    })
  return { calls, load }
}

function setup(options?: AsyncOptions) {
  const { calls, load } = deferred()
  const hook = renderHook(({ arg }: { arg: string }) => useAsync(() => load(arg), [arg], options), {
    initialProps: { arg: 'a' },
  })
  const answer = async (i: number, value: string) => {
    await act(async () => calls[i].resolve(value))
  }
  const current = () => hook.result.current as Async<string>
  return { calls, hook, answer, current }
}

describe('useAsync', () => {
  it('starts over when its deps change', async () => {
    const { hook, answer, current } = setup()
    await answer(0, 'A')
    expect(current()).toMatchObject({ state: 'ready', data: 'A' })
    hook.rerender({ arg: 'b' })
    expect(current().state).toBe('loading')
  })

  it('with keep, shows the last data, marked refreshing, until the new arrives', async () => {
    const { hook, answer, current } = setup({ keep: true })
    await answer(0, 'A')
    hook.rerender({ arg: 'b' })
    expect(current()).toMatchObject({ state: 'ready', data: 'A', refreshing: true })
    await answer(1, 'B')
    const ready = current()
    expect(ready).toMatchObject({ state: 'ready', data: 'B' })
    expect(ready.state === 'ready' && ready.refreshing).toBeFalsy()
  })

  it('with keep, an error for the new deps replaces the kept data', async () => {
    const { calls, hook, answer, current } = setup({ keep: true })
    await answer(0, 'A')
    hook.rerender({ arg: 'b' })
    await act(async () => calls[1].reject(new Error('down')))
    expect(current()).toMatchObject({ state: 'error' })
  })

  it('with keep, still loads from scratch the first time', () => {
    const { current } = setup({ keep: true })
    expect(current().state).toBe('loading')
  })

  it('a reload keeps the data without marking it refreshing', async () => {
    const { answer, current } = setup()
    await answer(0, 'A')
    const before = current()
    act(() => before.state === 'ready' && before.reload())
    expect(current()).toBe(before)
    await answer(1, 'A2')
    expect(current()).toMatchObject({ state: 'ready', data: 'A2' })
  })

  it('ignores an answer for deps that changed since', async () => {
    const { hook, answer, current } = setup({ keep: true })
    await answer(0, 'A')
    hook.rerender({ arg: 'b' })
    hook.rerender({ arg: 'c' })
    await answer(2, 'C')
    await answer(1, 'B, late')
    await waitFor(() => expect(current()).toMatchObject({ state: 'ready', data: 'C' }))
  })
})
