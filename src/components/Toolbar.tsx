import React from 'react';
import { CompareIcon } from './icons/CompareIcon';
import { CsvIcon } from './icons/CsvIcon';
import { FONTS, TEXT_SIZES } from '../constants';

interface ToolbarProps {
  onCompare: () => void;
  onExportPdf: () => void;
  onExportCsv: () => void;
  canCompare: boolean;
  canExport: boolean;
  isComparing: boolean;
}

const ActionButton: React.FC<{ onClick: () => void; disabled: boolean; icon: React.ReactNode; label: string; bgColor?: string; textColor?: string; hoverBgColor?: string; }> = 
  ({ onClick, disabled, icon, label, bgColor = 'bg-blue-800', textColor = 'text-white', hoverBgColor = 'hover:bg-blue-700' }) => ( // azul-juridico -> blue-800, branco -> white
  <button
    onClick={onClick}
    disabled={disabled}
    className={`flex items-center space-x-2 px-4 py-2 rounded-md ${TEXT_SIZES.BASE} font-['${FONTS.DEFAULT}'] font-semibold
                ${bgColor} ${textColor} ${disabled ? 'opacity-50 cursor-not-allowed' : `${hoverBgColor} transition-colors`}
                focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50`} // azul-selecao -> blue-500
  >
    {icon}
    <span>{label}</span>
  </button>
);

export const Toolbar: React.FC<ToolbarProps> = ({ onCompare, onExportCsv, canCompare, canExport, isComparing }) => {
  return (
    <div className="w-full bg-white shadow-md p-3 flex flex-col sm:flex-row items-center justify-between sticky top-0 z-10"> {/* branco -> white */}
      <h1 className={`font-['${FONTS.DEFAULT}'] ${TEXT_SIZES.XXLARGE} font-bold text-blue-800 mb-2 sm:mb-0`}> {/* azul-juridico -> blue-800 */}
        ClauseDiff
      </h1>
      <div className="flex items-center space-x-2 sm:space-x-3">
        <ActionButton
          onClick={onCompare}
          disabled={!canCompare || isComparing}
          icon={<CompareIcon size={18} className="text-white" />} // text-branco -> text-white
          label={isComparing ? "Comparando..." : "Comparar"}
        />
        <ActionButton
          onClick={onExportCsv}
          disabled={!canExport || isComparing}
          icon={<CsvIcon size={18} className="text-white" />} // text-branco -> text-white
          label="Exportar CSV"
          bgColor="bg-gray-700" // cinza-documento -> gray-700
          hoverBgColor="hover:bg-gray-600" // Standard hover for gray-700
        />
      </div>
    </div>
  );
};
