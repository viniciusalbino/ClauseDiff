"use client";

import "./globals.css";
import { SessionProvider } from "next-auth/react";
import { Inter } from 'next/font/google';

// Configuração da fonte Inter
const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter', // Opcional: para usar como variável CSS se necessário
});

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={`${inter.variable} font-sans`}>
      <head>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
      </head>
      <body className="bg-gray-50 text-gray-900 min-h-screen">
        <SessionProvider basePath="/api/auth">
          {children}
        </SessionProvider>
      </body>
    </html>
  );
} 