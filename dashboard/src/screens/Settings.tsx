import { useEffect, useState } from 'react'
import type { AiConfig, Diagnostics } from '../adapter/types'
import { useStore } from '../state/store'
import { ScreenHead } from '../components/layout'
import { Button, Chip, Icon, Note, Select, Card, Overline } from '../components/ui'

function NumRow({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-line py-2.5 last:border-b-0">
      <span className="text-[13px] text-ink3">{k}</span>
      <span className={`text-right text-[13.5px] font-semibold ${mono ? 'font-mono text-[12.5px]' : ''}`}>{v}</span>
    </div>
  )
}

type CheckState = { busy: boolean; result?: { ok: boolean; detail: string } }

export function Settings() {
  const { adapter, pushToast, mode, selectedAiConfigId, setSelectedAiConfigId } = useStore()
  const [configs, setConfigs] = useState<AiConfig[] | null>(null)
  const [diag, setDiag] = useState<Diagnostics | null>(null)
  const [validate, setValidate] = useState<Record<string, CheckState>>({})
  const [ping, setPing] = useState<Record<string, CheckState>>({})
  const [copied, setCopied] = useState<string | null>(null)

  useEffect(() => {
    adapter.listAiConfigs().then(setConfigs).catch(() => {
      setConfigs([])
      pushToast('Конфигурации недоступны: ошибка связи', 'error')
    })
    adapter.diagnostics().then(setDiag)
  }, [adapter, pushToast])

  const runValidate = async (c: AiConfig) => {
    setValidate((s) => ({ ...s, [c.id]: { busy: true } }))
    try {
      const res = await adapter.validateAiConfig(c.id)
      setValidate((s) => ({ ...s, [c.id]: { busy: false, result: { ok: res.valid, detail: res.detail } } }))
    } catch (e) {
      setValidate((s) => ({ ...s, [c.id]: { busy: false, result: { ok: false, detail: e instanceof Error ? e.message : 'ошибка связи' } } }))
    }
  }
  const runPing = async (c: AiConfig) => {
    setPing((s) => ({ ...s, [c.id]: { busy: true } }))
    try {
      const res = await adapter.pingModel(c.id)
      setPing((s) => ({ ...s, [c.id]: { busy: false, result: res } }))
      if (!res.ok) pushToast(`«Проверка адреса модели»: ${res.detail}`, 'error')
    } catch (e) {
      setPing((s) => ({ ...s, [c.id]: { busy: false, result: { ok: false, detail: e instanceof Error ? e.message : 'ошибка связи' } } }))
    }
  }

  // выбор конфигурации сохраняется и реально используется новыми запусками (#4)
  const applySelection = (id: string) => {
    setSelectedAiConfigId(id)
    pushToast('Конфигурация выбрана: она будет использована следующим запуском (текущие прогоны не меняются).', 'ok')
  }

  const copyDigest = async (c: AiConfig) => {
    try {
      await navigator.clipboard.writeText(c.digest)
      setCopied(c.id)
      setTimeout(() => setCopied(null), 2000)
    } catch {
      pushToast('Буфер обмена недоступен — полный digest показан в поле выше.', 'info')
    }
  }

  if (!configs) return null

  return (
    <>
      <ScreenHead
        no="04 · Служебное"
        title="Настройки и диагностика"
        meta={<>Раздел — просмотр и проверка конфигураций: выбор применяется к новым запускам, редактирование и запись TOML через backend не реализованы. Паролей и API-ключей здесь нет: Hermes работает внутри приватной Docker-сети.</>}
      />

      <div className="space-y-5">
        {/* 01 · модель и сервер */}
        <section>
          <Overline>01 · Модель и сервер</Overline>
          <div className="mt-3.5 grid gap-5 lg:grid-cols-[1.4fr_1fr]">
            {configs.map((c) => (
              <Card key={c.id} className="bg-dim! shadow-none!">
                <div className="mb-2.5 flex items-center justify-between gap-3">
                  <span className="font-mono text-[13px] font-bold">{c.name}</span>
                  {c.present === false && <Chip tone="danger">модели нет на сервере</Chip>}
                  {c.present === true && <Chip tone="mint">доступна</Chip>}
                </div>
                {c.present === null && <Chip tone="smoke">наличие не проверено</Chip>}
                <NumRow k="Модель" v={c.model} mono />
                <div className="flex items-baseline justify-between gap-6 border-b border-line py-2.5">
                  <span className="shrink-0 text-[13px] text-ink3">digest (полный, фиксируется при прогоне)</span>
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="break-all text-right font-mono text-[11.5px] leading-snug">{c.digest}</span>
                    <button
                      type="button"
                      onClick={() => copyDigest(c)}
                      aria-label="Скопировать полный digest"
                      title="Скопировать полный digest"
                      className="pressable shrink-0 rounded-full p-1.5 text-ink3 transition-colors hover:bg-surface hover:text-ink"
                    >
                      <Icon name={copied === c.id ? 'check' : 'copy'} size={13} />
                    </button>
                  </span>
                </div>
                <NumRow k="Адрес сервера (внутренний)" v={c.server} />
                <NumRow k="Сеть" v={c.network} mono />
                <NumRow k="Контекст" v={`${c.contextTokens.toLocaleString('ru-RU')} токенов · минимум текущего Hermes — 64 000`} />
                <NumRow k="max_output_tokens" v={`${c.maxOutputTokens.toLocaleString('ru-RU')} токенов`} mono />
                <NumRow k="timeout_seconds" v={`${c.timeoutSeconds} с на вызов`} mono />
              </Card>
            ))}
          </div>
        </section>

        {/* 02 · проверки конфигурации */}
        <Card>
          <Overline>02 · Две раздельные проверки и выбор для новых запусков</Overline>
          <p className="mt-3 max-w-2xl text-[14px] leading-relaxed text-ink2">
            «Запись конфигурации валидна» и «адрес модели доступен» — разные проверки. Доступность порта не
            подтверждает модель, её digest или генерацию; полный валидатор ядра (ai_config.py) остаётся эталоном.
          </p>
          <div className="mt-5 max-w-3xl">
            <label className="mb-5 block max-w-sm">
              <span className="mb-1.5 block text-[13px] font-bold">Действует для новых запусков</span>
              <Select value={selectedAiConfigId} onChange={(e) => applySelection(e.target.value)}>
                <option value="">— выберите профиль —</option>
                {configs.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </Select>
              <span className="mt-1.5 block text-[12px] leading-snug text-ink3">
                выбор применяется в форме «Новый запуск»; идущие прогоны сохраняют свою конфигурацию
                {mode === 'demo' && ' (в деморежиме — для демо-прогонов)'}
              </span>
            </label>
            {configs.map((c) => (
              <div key={c.id} className="border-t border-line py-4 first-of-type:border-t-0 first-of-type:pt-1">
                <div className="mb-3.5 font-mono text-[13px] font-bold">{c.name}</div>
                <div className="flex flex-wrap items-center gap-x-10 gap-y-4">
                  <div>
                    <div className="mb-2 text-[13px] text-ink3">Запись конфигурации валидна</div>
                    <div className="flex items-center gap-3">
                      <Button variant="secondary" onClick={() => runValidate(c)} disabled={validate[c.id]?.busy}>
                        {validate[c.id]?.busy ? 'Проверяем…' : 'Проверить запись'}
                      </Button>
                      {validate[c.id]?.result && (
                        <Chip tone={validate[c.id].result!.ok ? 'mint' : 'danger'}>{validate[c.id].result!.ok ? 'валиден' : 'ошибка'}</Chip>
                      )}
                    </div>
                    {validate[c.id]?.result && <p className="mt-2 text-[12.5px] text-ink2">{validate[c.id].result!.detail}</p>}
                  </div>
                  <div>
                    <div className="mb-2 text-[13px] text-ink3">Адрес модели доступен</div>
                    <div className="flex items-center gap-3">
                      <Button variant="secondary" onClick={() => runPing(c)} disabled={ping[c.id]?.busy}>
                        {ping[c.id]?.busy ? 'Запрос…' : 'Проверить адрес'}
                      </Button>
                      {ping[c.id]?.result && (
                        <Chip tone={ping[c.id].result!.ok ? 'mint' : 'danger'}>{ping[c.id].result!.ok ? 'проверка пройдена' : 'недоступен'}</Chip>
                      )}
                    </div>
                    {ping[c.id]?.result && <p className="mt-2 text-[12.5px] text-ink2">{ping[c.id].result!.detail}</p>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* 03 · диагностика стенда */}
        <Card>
          <Overline>03 · Диагностика стенда</Overline>
          <div className="mt-3 max-w-3xl rounded-field bg-dim px-4 py-3">
            <NumRow k="CPU" v={diag?.cpu ?? 'нет данных'} />
            <NumRow k="Память" v={diag?.memory ?? 'нет данных'} />
            <NumRow k="GPU" v={diag?.gpu ?? 'нет данных'} />
            {diag?.uptime && <NumRow k="Сервер" v={diag.uptime} />}
          </div>
          {diag && (
            <div className="mt-4 max-w-3xl">
              <Note>{diag.note}</Note>
            </div>
          )}
        </Card>

        {/* 04 · правила */}
        <Card>
          <Overline>04 · Правила, которые не отключаются</Overline>
          <ul className="mt-4 max-w-3xl list-none space-y-2.5 text-[14px] text-ink2">
            {[
              'digest модели и образа фиксируется при прогоне и не подменяется интерфейсом',
              'лимит двух попыток Blue (включая корректирующие) соблюдается без исключений',
              'независимая проверка кандидата не заменяется эталонным исправлением',
              'политика не редактируется из UI и не ослабляется ради прохождения патча',
              'очистка контейнеров выполняется после каждого прогона',
            ].map((t) => (
              <li key={t} className="flex gap-3">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden="true" />
                {t}
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
