// Utilitário para merge de classes Tailwind (shadcn/ui padrão)
export function cn(...inputs: (string | undefined | null | false)[]): string {
  return inputs.filter(Boolean).join(" ");
} 