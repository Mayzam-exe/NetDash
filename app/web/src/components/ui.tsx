import type { ComponentChildren } from 'preact';

/* ---------------------------------------------------------------------------
   Phase 1 component primitives — maximalist classic-dark styling lives in
   tokens.css (`.eyebrow`, `.truth-chip`, `.status-dot`, `.card`).
   --------------------------------------------------------------------------- */

/** Letterspaced small-caps section header — the signature section marker. */
export function Eyebrow({ children }: { children?: ComponentChildren }) {
  return <span class="eyebrow">{children}</span>;
}

/** Card with the brass hairline top edge (solid fill, never glass). */
export function Card({
  children,
  className = '',
}: {
  children?: ComponentChildren;
  className?: string;
}) {
  return <section class={'card ' + className}>{children}</section>;
}

/**
 * Status dot: shape + label + colour (never colour alone, per the a11y rules).
 * online = filled circle, warning = filled + ring, offline = hollow, blocked = square.
 */
export function StatusDot({ state }: { state: string }) {
  return <span class={'status-dot ' + state} aria-hidden="true" />;
}

/**
 * TruthChip — the signature component.
 *
 * Makes "is this actually enforced, or just stored?" visible at a glance:
 *   enforced        → verdigris  (real, actively applied)
 *   reference       → brass      (stored/displayed, NOT applied)
 *   unavailable     → muted      (cannot be applied here — shows the reason)
 *   pending         → amber      (transitioning)
 */
export type TruthKind = 'enforced' | 'reference' | 'unavailable' | 'pending';

export function TruthChip({
  kind,
  label,
  reason,
}: {
  kind: TruthKind;
  label: string;
  reason?: string;
}) {
  const title = reason ? label + ' — ' + reason : label;
  return (
    <span class={'truth-chip ' + kind} title={title}>
      <span class="tc-mark" aria-hidden="true" />
      <span class="tc-label">{label}</span>
      {reason ? <span class="tc-reason">{reason}</span> : null}
    </span>
  );
}
