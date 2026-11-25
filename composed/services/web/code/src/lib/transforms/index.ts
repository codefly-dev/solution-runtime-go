/**
 * Pure data transforms — zero React imports, fully testable.
 */

export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return "-";
  return new Date(date).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatNumber(n: number | null | undefined): string {
  if (n == null) return "-";
  return n.toLocaleString();
}

export function truncate(str: string | null | undefined, maxLength = 50): string {
  if (!str) return "-";
  return str.length > maxLength ? `${str.slice(0, maxLength)}...` : str;
}
