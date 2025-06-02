import React from 'react';

interface LoadingSpinnerProps {
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ message = "Processando..." }) => {
  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex flex-col items-center justify-center z-50">
      <div className="w-16 h-16 border-4 border-dashed rounded-full animate-spin border-blue-800"></div>
      <p className="mt-4 text-lg font-semibold text-white">{message}</p>
    </div>
  );
};
