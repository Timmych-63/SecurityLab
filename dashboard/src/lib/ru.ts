/** Known machine codes only; arbitrary model output and raw evidence stay intact. */
const labels: Record<string,string> = {
  map: 'Карта приложения', review: 'Защитное ревью', red: 'Анализ', blue_1: 'Исправление · попытка 1', blue_2: 'Исправление · попытка 2',
  baseline: 'Исходное приложение', candidate: 'Проверка исправления 1', candidate_retry: 'Проверка исправления 2',
  recheck: 'Повторная проверка', cancellation: 'Остановка', result: 'Результат', verifier: 'Независимая проверка',
  'ACCESS_POLICY_VIOLATION_REPRODUCED': 'Нарушение правил доступа воспроизведено',
  'ACCESS_POLICY_MATCHED': 'Проверенные случаи соответствуют правилам доступа',
}
export function translateStageText(value: string): string {
  if (labels[value]) return labels[value]
  return value.replace('Red · анализ','Анализ приложения').replace('Blue · предложение','Предложение исправления')
    .replace('Red:', 'Анализ:').replace('Blue:', 'Исправление:')
    .replace('Предложение Red', 'Результат анализа').replace('Предложение Blue', 'Предложение исправления')
    .replace('Результат: BLOCKED','Результат: проверка остановлена')
    .replace('Результат: STOPPED','Результат: отменено оператором')
    .replace('Результат: PASS','Результат: проверка пройдена')
    .replace('Результат: NEEDS_REVIEW','Результат: требуется проверка оператором')
}
