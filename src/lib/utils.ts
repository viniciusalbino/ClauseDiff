import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

// Utilitário para merge de classes Tailwind (shadcn/ui padrão)
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
} 