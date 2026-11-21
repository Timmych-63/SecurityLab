import type { Stage } from '../adapter/types'

/** Completion is an execution fact, not a security verdict. Unknown details stay neutral. */
export function stagePresentation(stage: Stage): { tone: string; label: string } {
  if (stage.state === 'failed') return { tone: 'failed', label: 'Этап прерван или завершён с ошибкой' }
  if (stage.state === 'skipped') return { tone: 'neutral', label: 'Не завершён / пропущен' }
  if (stage.state !== 'done') return { tone: stage.state, label: '' }
  const verifier = ['baseline', 'candidate', 'candidate_retry', 'recheck'].includes(stage.id)
  if (verifier && stage.detail === 'ACCESS_POLICY_VIOLATION_REPRODUCED') {
    return { tone: 'violation', label: stage.id === 'baseline' ? 'Нарушение воспроизведено' : 'Нарушение сохранилось — исправление не прошло проверку' }
  }
  if (verifier && stage.detail === 'ACCESS_POLICY_MATCHED') {
    return { tone: 'matched', label: 'Проверенные случаи соответствуют политике' }
  }
  return { tone: 'neutral', label: 'Этап завершён' }
}
