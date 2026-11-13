import type { ReactNode } from 'react'
import { Overline } from './ui'

/** Заголовок экрана: надзаголовок, крупный титул Manrope, мета-строка, действия. */
export function ScreenHead({ no, title, meta, actions }: { no: string; title: ReactNode; meta?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-9">
      <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
        <div className="max-w-2xl">
          <Overline>{no}</Overline>
          <h1 className="mt-2 text-[30px] font-extrabold leading-[1.12] tracking-[-0.035em] sm:text-[36px]">{title}</h1>
          {meta && <div className="mt-3 text-[14px] leading-relaxed text-ink2">{meta}</div>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2.5">{actions}</div>}
      </div>
    </header>
  )
}

export function Page({ children }: { children: ReactNode }) {
  return <div className="mx-auto w-full max-w-[1080px] px-5 py-8 sm:px-8 sm:py-10 lg:px-12">{children}</div>
}
