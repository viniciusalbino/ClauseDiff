import React from 'react';
import { FONTS, TEXT_SIZES } from '../constants';

interface ComparisonViewProps {
  htmlContent1: string | null;
  htmlContent2: string | null;
  docName1?: string | null;
  docName2?: string | null;
}

export const ComparisonView: React.FC<ComparisonViewProps> = ({ htmlContent1, htmlContent2, docName1, docName2 }) => {
  if (!htmlContent1 && !htmlContent2) {
    return (
      <div className="flex-1 flex items-center justify-center text-gray-700 p-8">
        <p className="text-lg">Carregue dois documentos para iniciar a comparação.</p>
      </div>
    );
  }

  const Pane: React.FC<{ title: string | null | undefined, content: string | null, id: string }> = ({ title, content, id }) => (
    <div className="flex-1 p-4 bg-white shadow-md rounded-lg overflow-hidden">
      <h3 className={`font-['${FONTS.DEFAULT}'] ${TEXT_SIZES.XLARGE} font-semibold text-blue-800 mb-3 pb-2 border-b border-slate-300 truncate`}>
        {title || "Documento"}
      </h3>
      <div 
        id={id}
        className={`h-[calc(100vh-280px)] overflow-y-auto text-sm font-mono text-gray-800 p-3 bg-white rounded border border-gray-200`} 
        dangerouslySetInnerHTML={{ __html: content || "<p class='text-gray-500 italic p-2'>Nenhum conteúdo para exibir.</p>" }}
      />
    </div>
  );

  return (
    <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-4 p-4">
      <Pane title={docName1 || "Documento Original"} content={htmlContent1} id="comparison-pane-1" />
      <Pane title={docName2 || "Documento Modificado"} content={htmlContent2} id="comparison-pane-2" />
    </div>
  );
};