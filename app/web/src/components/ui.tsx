import type { ComponentChildren } from 'preact';

/** Letterspaced small-caps section header — the signature section marker. */
export function Eyebrow({ children }: { children?: ComponentChildren }) {
  return <span class="eyebrow">{children}</span>;
}
