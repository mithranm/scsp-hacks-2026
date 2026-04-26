// Shared date utilities for the scrubber and date-driven views.

export const TIMELINE_START = "2021-09-15";
export const TIMELINE_END   = "2022-06-30";

export function toDate(s: string): Date {
  return new Date(s + "T00:00:00Z");
}

export function fromDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function addDays(s: string, n: number): string {
  const d = toDate(s);
  d.setUTCDate(d.getUTCDate() + n);
  return fromDate(d);
}

export function daysBetween(a: string, b: string): number {
  return Math.round((toDate(b).getTime() - toDate(a).getTime()) / 86400000);
}

export function timelineDayCount(start = TIMELINE_START, end = TIMELINE_END): number {
  return daysBetween(start, end);
}

export function dayIndexToDate(idx: number, start = TIMELINE_START): string {
  return addDays(start, idx);
}

export function dateToDayIndex(
  date: string,
  start = TIMELINE_START,
  end = TIMELINE_END,
): number {
  return Math.max(0, Math.min(timelineDayCount(start, end), daysBetween(start, date)));
}

/** Find the nearest BGP sample period for a given date. */
export function nearestPeriod<T extends { label: string; date: string }>(
  date: string,
  periods: T[],
): T {
  let best = periods[0];
  let bestAbs = Number.POSITIVE_INFINITY;
  for (const p of periods) {
    const d = Math.abs(daysBetween(date, p.date));
    if (d < bestAbs) {
      bestAbs = d;
      best = p;
    }
  }
  return best;
}

/** Format like "Feb 24, 2022" */
export function formatHumanDate(s: string): string {
  return toDate(s).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}
