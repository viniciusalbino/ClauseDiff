import React, { useState } from 'react';
import { ComparisonResult, DIFF_INSERT, DIFF_EQUAL } from '../../types';
import { ChevronDownIcon } from './icons/ChevronDownIcon';
import { FONTS, TEXT_SIZES } from '../../constants';

interface DifferenceSummaryProps {
  summary: ComparisonResult['summary'];
  rawDiffs: ComparisonResult['rawDiffs'];
}

export const DifferenceSummary: React.FC<DifferenceSummaryProps> = ({ summary, rawDiffs }) => {
  const [isOpen, setIsOpen] = useState(true);

  if (!summary || !rawDiffs) {
    return null; 
  }

  const significantChanges = rawDiffs.filter(d => d.type !== DIFF_EQUAL && d.text.trim().length > 0).slice(0, 10);

  return (
    <div className="bg-white shadow-lg rounded-lg w-full md:w-80 lg:w-96 max-h-[calc(100vh-120px)] flex flex-col">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`w-full flex items-center justify-between p-3 bg-gray-700 text-white ${TEXT_SIZES.subtitle} font-['${FONTS.sans}'] font-semibold rounded-t-lg focus:outline-none`}
      >
        Resumo das Alterações
        <ChevronDownIcon size={20} className={`transform transition-transform duration-200 ${isOpen ? 'rotate-180' : ''} text-white`} />
      </button>
      {isOpen && (
        <div className="p-4 overflow-y-auto flex-grow">
          <div className="mb-4">
            <p className={`${TEXT_SIZES.body} font-semibold text-blue-800`}>Estatísticas Gerais:</p>
            <ul className="list-disc list-inside ml-2 text-sm text-gray-700">
              <li><span className="font-medium text-green-800">Adições:</span> {summary.additions} caracteres</li>
              <li><span className="font-medium text-red-800">Remoções:</span> {summary.deletions} caracteres</li>
              <li><span className="font-medium">Total de Blocos Diferentes:</span> {summary.totalDifferences}</li>
            </ul>
          </div>

          {significantChanges.length > 0 && (
             <div>
              <p className={`${TEXT_SIZES.body} font-semibold text-blue-800 mb-2`}>Principais Alterações:</p>
              <ul className={`space-y-2 text-xs font-mono`}>
                {significantChanges.map((change, index) => (
                  <li key={index} className={`p-2 rounded ${change.type === DIFF_INSERT ? 'bg-green-100' : 'bg-red-100'}`}>
                    <span className={`font-semibold ${change.type === DIFF_INSERT ? 'text-green-800' : 'text-red-800'}`}>
                      {change.type === DIFF_INSERT ? 'ADICIONADO: ' : 'REMOVIDO: '}
                    </span>
                    <span className="truncate block" title={change.text}>{change.text.length > 100 ? change.text.substring(0,100) + '...' : change.text}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {significantChanges.length === 0 && summary.totalDifferences === 0 && (
            <p className="text-sm text-gray-700 italic">Nenhuma diferença encontrada entre os documentos.</p>
          )}
           {significantChanges.length === 0 && summary.totalDifferences > 0 && (
            <p className="text-sm text-gray-700 italic">As diferenças encontradas são principalmente espaços em branco ou pequenas formatações.</p>
          )}
        </div>
      )}
    </div>
  );
};