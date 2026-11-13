import { useCallback, useEffect, useState } from 'react'
import type { Project, Snapshot } from '../adapter/types'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Card, Chip, EmptyState, Modal, Skeleton, TextInput, Note, Overline } from '../components/ui'
import { fmtDateTime } from '../lib/format'

function SnapshotRows({ snapshots, mobile }: { snapshots: Snapshot[]; mobile: boolean }) {
  if (mobile) {
    return (
      <div className="space-y-2.5">
        {snapshots.map((s) => (
          <div key={s.id} className="rounded-field bg-dim px-3.5 py-3">
            <div className="font-mono text-[12.5px] font-semibold">{s.id}</div>
            <div className="mt-1 text-[12px] text-ink3">
              снимок <span className="font-mono">{s.commit}</span> · {fmtDateTime(s.createdAt)}
              {s.note ? ` · ${s.note}` : ''}
            </div>
          </div>
        ))}
      </div>
    )
  }
  return (
    <div className="overflow-x-auto rounded-field bg-dim p-1.5">
      <table className="tbl max-w-3xl">
        <thead>
          <tr>
            <th>Снимок</th>
            <th>Снимок</th>
            <th>Зафиксирован</th>
            <th>Примечание</th>
          </tr>
        </thead>
        <tbody className="bg-surface">
          {snapshots.map((s) => (
            <tr key={s.id}>
              <td className="font-mono text-[12.5px] font-semibold">{s.id}</td>
              <td className="font-mono text-[12.5px] text-ink2">{s.commit}</td>
              <td className="text-ink2">{fmtDateTime(s.createdAt)}</td>
              <td className="text-ink3">{s.note ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Projects({ navigate }: { navigate: (to: string) => void }) {
  const { adapter, pushToast, dataVersion, bumpData } = useStore()
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [pathInput, setPathInput] = useState('')
  const [refusal, setRefusal] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [mobile, setMobile] = useState(() => window.innerWidth < 900)

  useEffect(() => {
    const onResize = () => setMobile(window.innerWidth < 900)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  useEffect(() => {
    adapter.listProjects().then(setProjects).catch(() => setProjects([]))
  }, [adapter, dataVersion])

  const addProject = useCallback(async () => {
    setBusy(true)
    const res = await adapter.registerProject(pathInput)
    setBusy(false)
    if ('ok' in res) {
      setRefusal(res.reason)
      return
    }
    // backend реально зарегистрировал проект: закрываем форму и перечитываем реестр
    setAddOpen(false)
    setPathInput('')
    pushToast(`Проект «${res.name}» зарегистрирован на backend (${res.id}). Профиль не настроен — запуск недоступен до настройки оператором.`, 'ok')
    bumpData()
  }, [adapter, pathInput, pushToast, bumpData])

  const makeSnapshot = useCallback(
    async (p: Project) => {
      const res = await adapter.createSnapshot(p.id)
      if ('ok' in res) {
        pushToast(res.reason, 'error')
        return
      }
      pushToast(`Снимок ${res.id} зафиксирован на backend (идентификатор ${res.commit}).`, 'ok')
      bumpData()
    },
    [adapter, pushToast, bumpData],
  )

  return (
    <>
      <ScreenHead
        no="01 · Реестр"
        title="Проекты"
        meta={
          <>
            Локальные репозитории, разрешённые к проверке. Просмотр списка не исполняет код проектов и не
            подключается к Docker — это делает только запуск проверки.
          </>
        }
        actions={<Button variant="primary" icon="plus" onClick={() => { setAddOpen(true); setRefusal(null); setPathInput('') }}>Добавить проект</Button>}
      />
      {projects === null ? (
        <Skeleton lines={6} />
      ) : projects.length === 0 ? (
        <EmptyState icon="box" title="Проектов пока нет">
          Добавьте первый локальный путь через backend — выбор папки в браузере не выдаётся за серверный абсолютный путь.
        </EmptyState>
      ) : (
        <div className="space-y-5">
          {projects.map((p, i) => (
            <Card key={p.id}>
              <div className="anim-in" style={{ animationDelay: `${i * 60}ms` }}>
                <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                      <h2 className="text-[18px] font-extrabold tracking-[-0.02em]">{p.name}</h2>
                      {p.supported ? (
                        <Chip tone="accent">профиль {p.profile}</Chip>
                      ) : (
                        <Chip tone="danger">стек не поддерживается</Chip>
                      )}
                    </div>
                    <div className="mt-2 font-mono text-[12px] text-ink3">{p.path}</div>
                    <div className="mt-0.5 text-[13px] text-ink2">{p.stack}</div>
                  </div>
                  <div className="flex items-center gap-2.5">
                    {p.lastRunId && (
                      <Button variant="ghost" icon="arrow" onClick={() => navigate(`/runs/${p.lastRunId}`)}>
                        Последний прогон
                      </Button>
                    )}
                    <Button
                      variant="primary"
                      icon="play"
                      disabled={!p.supported}
                      title={p.supported ? '' : 'стек не поддерживается профилем'}
                      onClick={() => navigate(`/new?project=${p.id}`)}
                    >
                      Новый запуск
                    </Button>
                  </div>
                </div>

                {!p.supported && (
                  <div className="mt-4 max-w-3xl">
                    <Note tone="warn" title="Причина:">
                      {p.unsupportedReason}
                    </Note>
                  </div>
                )}

                {p.supported && (
                  <div className="mt-6">
                    <div className="mb-2.5 flex items-center justify-between gap-4">
                      <Overline>Снимки · {p.snapshots.length}</Overline>
                      <Button variant="ghost" onClick={() => makeSnapshot(p)} title="создаёт backend через Git">
                        Создать снимок
                      </Button>
                    </div>
                    {p.snapshots.length ? (
                      <SnapshotRows snapshots={p.snapshots} mobile={mobile} />
                    ) : (
                      <p className="text-[13px] text-ink3">Снимков нет — запустите фиксацию через backend.</p>
                    )}
                  </div>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Добавить проект">
        <div className="space-y-4">
          <p className="text-[14px] leading-relaxed text-ink2">
            Путь передаётся локальному backend (предлагаемый <span className="font-mono text-[12.5px]">POST /api/projects</span>).
            Выбор папки в браузере не выдаётся за серверный абсолютный путь — поэтому поле принимает путь вручную.
          </p>
          <TextInput
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="/home/operator/lab/orders-api"
            aria-label="Локальный путь репозитория"
          />
          {refusal && <Note tone="warn" title="Операция отклонена (деморежим):">{refusal}</Note>}
          <div className="flex justify-end gap-2.5">
            <Button onClick={() => setAddOpen(false)}>Закрыть</Button>
            <Button variant="primary" onClick={addProject} disabled={busy || pathInput.trim() === ''}>
              {busy ? 'Передача…' : 'Передать backend'}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  )
}
