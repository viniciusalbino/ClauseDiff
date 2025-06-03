"use client";

export default function GlobalError({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <html>
      <body className="min-h-screen flex flex-col items-center justify-center bg-gray-50 text-gray-900">
        <div className="max-w-md w-full bg-white shadow-lg rounded-xl p-8 flex flex-col items-center">
          <h2 className="text-2xl font-bold text-red-700 mb-4">Ocorreu um erro inesperado</h2>
          <pre className="bg-gray-100 text-red-800 p-4 rounded mb-4 w-full overflow-x-auto text-xs">{error.message}</pre>
          <button
            className="px-4 py-2 bg-blue-700 text-white rounded hover:bg-blue-800 transition"
            onClick={() => reset()}
          >
            Tentar novamente
          </button>
        </div>
      </body>
    </html>
  );
} 