import assert from 'node:assert/strict'
import { JSDOM } from 'jsdom'
import React, { act } from 'react'
// tsx may use classic JSX for the standalone script outside src.
;(globalThis as any).React = React
import { createRoot } from 'react-dom/client'
import { StoreProvider, useStore } from '../src/state/store'
import { HttpAdapter } from '../src/adapter/http'
import { DemoAdapter } from '../src/adapter/demo'
import { NewRun } from '../src/screens/NewRun'
import { projects, policies, aiConfigs } from '../src/adapter/demoData'
import { Runs } from '../src/screens/Runs'

const dom = new JSDOM('<meta name="securitylab-core" content="same-origin"><div id="root"></div>', { url: 'http://localhost:8765', pretendToBeVisual: true })
for (const key of ['window', 'document', 'location', 'localStorage', 'HTMLElement', 'MouseEvent', 'Event']) {
  Object.defineProperty(globalThis, key, { value: (dom.window as any)[key], configurable: true })
}
;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true
;(globalThis as any).ResizeObserver = class { observe() {} disconnect() {} }
window.matchMedia = (() => ({ matches: false, addEventListener() {}, removeEventListener() {} })) as any

let captured: any
let navigation = ''
HttpAdapter.prototype.listRuns = async () => []
HttpAdapter.prototype.listProjects = async () => projects
HttpAdapter.prototype.listPolicies = async () => [...policies, {...policies[0], id:'discovery', name:'Discovery rules',kind:'discovery',casesCount:0}, {...policies[0],id:'defensive',name:'Defensive rules',kind:'defensive',casesCount:0}]
HttpAdapter.prototype.listAiConfigs = async () => aiConfigs
HttpAdapter.prototype.preflight = async (input) => ({ docker: 'verified', images: 'verified', model: 'verified', checkedAt: new Date().toISOString(), params: input })
HttpAdapter.prototype.createRun = async (input) => { captured = input; return { runId: 'new-run' } }
const root = createRoot(document.getElementById('root')!)
await act(async () => root.render(<StoreProvider><NewRun navigate={to => { navigation = to }} /></StoreProvider>))
const button = (text: string) => [...document.querySelectorAll<HTMLButtonElement>('button')].find(b => b.textContent?.includes(text))!
const choose = async (index: number, value?: string) => act(async () => {
  const select = document.querySelectorAll('select')[index]
  select.value = value ?? select.options[1].value
  select.dispatchEvent(new Event('change', { bubbles: true }))
})
assert.equal(button('Запустить проверку').disabled, true)
for (const i of [0,1,2,4,5]) await choose(i)
assert.equal(button('Запустить проверку').disabled, true, 'filled form still requires preflight')
await act(async () => button('Выполнить предпроверку').click())
assert.equal(button('Запустить проверку').disabled, false)
await choose(5, aiConfigs[1].id)
assert.equal(button('Запустить проверку').disabled, true, 'model change invalidates preflight')
await act(async () => button('Выполнить предпроверку').click())
assert.equal(button('Запустить проверку').disabled, false)
await act(async () => document.querySelector<HTMLInputElement>('input[type=checkbox]')!.click())
assert.equal(button('Запустить проверку').disabled, true, 'package mode invalidates preflight')
await act(async () => button('Выполнить предпроверку').click())
await act(async () => button('Запустить проверку').click())
assert.equal(captured.aiConfigId, aiConfigs[1].id)
assert.equal(captured.profileId, 'access-ai-package-v1')
assert.ok(captured.projectId && captured.snapshotId && captured.entryModule && captured.policyId)
assert.equal(navigation, '/runs/new-run')
assert.equal(localStorage.getItem('slb.aiConfig.v1'), aiConfigs[1].id)
await choose(4, 'discovery')
assert.equal(button('Запустить проверку').disabled, true, 'discovery rules invalidate preflight')
assert.equal(document.querySelector<HTMLInputElement>('input[type=checkbox]')!.disabled,true)
await act(async () => button('Выполнить предпроверку').click())
await act(async () => button('Запустить проверку').click())
assert.equal(captured.profileId,'access-ai-discovery-v1')
assert.equal(captured.policyId,'discovery')
await choose(4, 'defensive')
assert.equal(button('Запустить проверку').disabled,true)
await act(async () => button('Выполнить предпроверку').click())
await act(async () => button('Запустить проверку').click())
assert.equal(captured.profileId,'defensive-review-v1')
await act(async () => root.unmount())
dom.window.close()
console.log('PASS: new-run form, required preflight, model selection invalidation, launch payload and navigation')
