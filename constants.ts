export const COLORS = {
  primary: '#1e40af', // Azul Jurídico (Tailwind: blue-800)
  secondary: '#374151', // Cinza Documento (Tailwind: gray-700)
  background: '#f3f4f6', // Cinza Claro (Tailwind: gray-100)
  surface: '#FFFFFF', // Branco (Tailwind: white)
  lightGray: '#cbd5e1', // Cinza Médio (Tailwind: slate-300)
  addition: '#16a34a', // Verde Adição (Tailwind: green-600)
  deletion: '#dc2626', // Vermelho Remoção (Tailwind: red-600)
  modification: '#FFC107', // Amarelo Modificação (Not directly used by diff-match-patch standard output)
  selection: '#3b82f6', // Azul Seleção (Tailwind: blue-500)
};

export const FONTS = {
  sans: 'Source Sans Pro, sans-serif',
  mono: 'Source Code Pro, monospace',
};

export const TEXT_SIZES = {
  title: 'text-2xl', // approx 24px
  subtitle: 'text-xl', // approx 20px
  body: 'text-base', // approx 16px
  contract: 'text-sm', // approx 14px, often combined with font-mono
  button: 'text-sm',
  micro: 'text-xs', // approx 12px
};
