import assert from 'node:assert/strict'
import { JSDOM } from 'jsdom'
import React, { act } from 'react'
// tsx may use classic JSX for the standalone script outside src.
;(globalThis as any).React = React
import { createRoot } from 'react-dom/client'
import { StoreProvider, useStore } from '../src/state/store'
import { HttpAdapter } from '../src/adapter/http'
import { DemoAdapter } from '../src/adapter/demo'
import { RunDetail } from '../src/screens/RunDetail'
import { Runs } from '../src/screens/Runs'

const dom = new JSDOM('<meta name="securitylab-core" content="same-origin"><div id="root"></div>', { url: 'http://localhost:8765', pretendToBeVisual: true })
for (const key of ['window', 'document', 'location', 'localStorage', 'HTMLElement', 'MouseEvent', 'Event']) {
  Object.defineProperty(globalThis, key, { value: (dom.window as any)[key], configurable: true })
}
;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true
;(globalThis as any).ResizeObserver = class { observe() {} disconnect() {} }
window.matchMedia = (() => ({ matches: false, addEventListener() {}, removeEventListener() {} })) as any
const seed = (await new DemoAdapter().listRuns())[0]
const run = { ...seed, id: 'refresh-run', demo: false, script: undefined, exec: 'running' as const, finishedAt: undefined }
let requests = 0
let pending: { resolve: (value: any) => void; reject: (error: Error) => void } | undefined
HttpAdapter.prototype.listRuns = async () => [run]
HttpAdapter.prototype.listAiConfigs = async () => []
HttpAdapter.prototype.getRun = async () => {
  requests++
  if (requests === 1) return structuredClone(run)
  return new Promise((resolve, reject) => { pending = { resolve, reject } })
}
let store: ReturnType<typeof useStore>
function Harness({ list = false, id = run.id }) {
  store = useStore()
  return list ? <Runs navigate={() => {}} /> : <RunDetail runId={id} navigate={() => {}} />
}
const root = createRoot(document.getElementById('root')!)
const render = async (list = false, id = run.id) => act(async () => { root.render(<StoreProvider><Harness list={list} id={id} /></StoreProvider>) })
const wait = async (ms: number) => act(async () => { await new Promise(resolve => setTimeout(resolve, ms)) })
await render()
const reporter = store!.reportConnection
const tab = document.querySelector<HTMLButtonElement>('[data-tab=checks]')!
assert.ok(tab)
await act(async () => tab.click())
const tabNode = document.querySelector('[role=tab][aria-selected=true]')
assert.ok(tabNode)
await wait(1200)
assert.equal(store!.reportConnection, reporter, 'clock ticks must keep connection callback stable')
assert.equal(requests, 1, 'clock ticks must not refetch/reset the detail')
assert.equal(document.querySelector('[role=tab][aria-selected=true]'), tabNode)
await wait(1500)
assert.equal(requests, 2, 'active detail still polls')
assert.equal(document.querySelector('[role=tab][aria-selected=true]'), tabNode, 'pending refresh keeps content mounted')
await act(async () => pending!.resolve({ ...run, events: [...run.events, { at: 42, role: 'system', text: 'new event' }] }))
assert.equal(document.querySelector('[role=tab][aria-selected=true]'), tabNode, 'successful poll keeps selected tab DOM')
await act(async () => store!.bumpData())
assert.equal(document.querySelector('[role=tab][aria-selected=true]'), tabNode, 'manual/cancel refresh keeps content')
await act(async () => pending!.reject(new Error('temporary outage')))
assert.equal(document.querySelector('[role=tab][aria-selected=true]'), tabNode, 'network failure keeps content')
assert.match(document.body.textContent!, /temporary outage/)
await act(async () => store!.bumpData())
const stale = pending!
await render(false, 'another-run')
await act(async () => stale.resolve(run))
assert.equal(document.querySelector('[role=tab]'), null, 'old response cannot populate a different run')
await act(async () => pending!.resolve({ ...run, id: 'another-run', exec: 'blocked', error: '<img src=x onerror=alert(1)> timeout', events: [] }))
const log = document.querySelector('[role=log]')!
assert.match(log.textContent!, /<img src=x onerror=alert\(1\)> timeout/)
assert.equal(log.querySelector('img'), null, 'untrusted error must render as text')
const terminalRequests = requests
await wait(2700)
assert.equal(requests, terminalRequests, 'terminal detail stops polling')
await render(true)
const filter = document.querySelector('select')!
await act(async () => { filter.value = run.projectId; filter.dispatchEvent(new Event('change', { bubbles: true })) })
filter.focus()
await wait(3200)
assert.equal(document.querySelector('select'), filter, 'list refresh must not recreate filter controls')
assert.equal(document.activeElement, filter, 'filter focus survives clock and poll')
assert.equal(filter.value, run.projectId, 'selected filter survives refresh')
await act(async () => root.unmount())
dom.window.close()
console.log('PASS: clock, background polling, selected tab, focus/filter retention, cancellation refresh, outage, stale response and terminal polling')
// jsdom has no layout: browser scroll geometry is explicitly outside this test.
