import assert from 'node:assert/strict'
import { fmtSec } from '../src/lib/format'
import { stagePresentation } from '../src/lib/stagePresentation'
for (const [input, expected] of [
  [292.12999999999994, '4 мин 52.13 с'], [437.99299999999994, '7 мин 17.993 с'],
  [59.9999,'1 мин'], [3599.9999,'1 ч 0 мин'], [0.027,'0.027 с'], [0,'0 с'],
  [-1,'—'], [NaN,'—'], [Infinity,'—'],
] as const) assert.equal(fmtSec(input),expected)
const stage = { id: 'candidate', label: 'Кандидат', state: 'done' as const }
assert.equal(stagePresentation({...stage,detail:'ACCESS_POLICY_VIOLATION_REPRODUCED'}).tone,'violation')
assert.match(stagePresentation({...stage,detail:'ACCESS_POLICY_VIOLATION_REPRODUCED'}).label,/не прошло/)
assert.equal(stagePresentation({...stage,id:'baseline',detail:'ACCESS_POLICY_VIOLATION_REPRODUCED'}).label,'Нарушение воспроизведено')
assert.equal(stagePresentation({...stage,detail:'ACCESS_POLICY_MATCHED'}).tone,'matched')
assert.equal(stagePresentation({...stage,detail:'UNKNOWN'}).tone,'neutral')
assert.equal(stagePresentation({...stage,id:'blue_1'}).tone,'neutral')
assert.equal(stagePresentation({...stage,id:'result',detail:'Результат: STOPPED'}).tone,'neutral')
assert.equal(stagePresentation({...stage,state:'failed'}).tone,'failed')
console.log('PASS: duration rounding/boundaries and execution vs security result presentation')
