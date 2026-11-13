import { useEffect, useState } from 'react'

/** Минимальный hash-роутер: работает и с http://, и с file://. */
export function useRoute(): { path: string; navigate: (to: string) => void } {
  const [path, setPath] = useState(() => currentPath())
  useEffect(() => {
    const onHash = () => setPath(currentPath())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  const navigate = (to: string) => {
    window.location.hash = to
    // скролл в начало после перехода
    requestAnimationFrame(() => window.scrollTo({ top: 0 }))
  }
  return { path, navigate }
}

function currentPath(): string {
  const h = window.location.hash.replace(/^#/, '')
  return h === '' ? '/projects' : h
}
