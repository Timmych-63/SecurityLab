import { useEffect, useState } from 'react'

/** Мобильный breakpoint согласован с таблицами: < 900px — пары «поле — значение». */
export function useIsMobile(): boolean {
  const [m, setM] = useState(() => window.innerWidth < 900)
  useEffect(() => {
    const onResize = () => setM(window.innerWidth < 900)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])
  return m
}
