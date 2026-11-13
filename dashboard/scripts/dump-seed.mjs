/**
 * Выгрузка демо-данных адаптера в JSON для референсного сервера.
 * Запуск из корня проекта: node scripts/dump-seed.mjs
 * Использует vite ssrLoadModule, чтобы импортировать TypeScript без сборки.
 */
import { createServer } from 'vite'
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const vite = await createServer({
  root,
  logLevel: 'error',
  server: { middlewareMode: true },
  appType: 'custom',
})

try {
  const mod = await vite.ssrLoadModule('/src/adapter/demoData.ts')
  const seed = {
    exportedAt: new Date().toISOString(),
    projects: mod.projects,
    policies: mod.policies,
    aiConfigs: mod.aiConfigs,
    demoRuns: mod.demoRuns,
    fixDiff: mod.FIX_DIFF,
    newRunScript: mod.newRunScript,
  }
  mkdirSync(join(root, 'server'), { recursive: true })
  writeFileSync(join(root, 'server', 'seed.json'), JSON.stringify(seed, null, 2))
  console.log('seed.json записан:',
    seed.projects.length, 'проектов,',
    seed.policies.length, 'политик,',
    seed.aiConfigs.length, 'конфигураций,',
    seed.demoRuns.length, 'прогонов')
} finally {
  await vite.close()
}
