import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {stripTypeScriptTypes} from 'node:module'
const text=stripTypeScriptTypes(readFileSync(new URL('../src/adapter/dto.ts',import.meta.url),'utf8'),{mode:'transform'})
const {mapCoreRun}=await import('data:text/javascript;base64,'+Buffer.from(text).toString('base64'))
const r=mapCoreRun({run_id:'real-id',status:'PASS',security_verdict:'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX',finding_status:'FIXED'})
assert.equal(r.exec,'completed');assert.equal(r.finding,'FIXED');assert.equal(r.verdict,'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX')
const blocked=mapCoreRun({id:'blocked',status:'BLOCKED',security_verdict:'NOT_EVALUATED',finding_status:null})
assert.equal(blocked.exec,'blocked');assert.equal(blocked.finding,null)
const shaped=mapCoreRun({id:'shaped',exec:'completed',verdict:r.verdict,finding:r.finding})
assert.equal(shaped.verdict,r.verdict);assert.equal(shaped.finding,r.finding)
assert.equal(mapCoreRun({status:'NEEDS_REVIEW'}).exec,'blocked')
assert.equal(mapCoreRun({status:'STOPPED'}).exec,'cancelled')
assert.equal(mapCoreRun({status:'PASS',security_verdict:'future'}).verdict,'UNKNOWN')
console.log('DTO integration cases PASS')
