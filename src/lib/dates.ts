export function todayIso(now = new Date()): string {
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, '0')
  const day = String(now.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

export function addDaysIso(base: string, days: number): string {
  const [year, month, day] = base.split('-').map(Number)
  const date = new Date(year, month - 1, day)
  date.setDate(date.getDate() + days)
  return todayIso(date)
}

export function isOpenStatus(status: string): boolean {
  return status === 'Open' || status === 'In progress'
}

export function isOverdue(
  dueDate: string | null,
  status: string,
  today = todayIso(),
): boolean {
  if (!dueDate) return false
  if (!isOpenStatus(status)) return false
  return dueDate < today
}
