import { ComparisonResult, DIFF_INSERT, DIFF_DELETE, DIFF_EQUAL } from '../../types';

export const exportToPdf = async (elementId1: string, elementId2: string, filename: string = 'comparacao_documentos.pdf'): Promise<void> => {
  const pdf = new window.jspdf.jsPDF({
    orientation: 'p',
    unit: 'pt',
    format: 'a4',
  });

  const element1 = document.getElementById(elementId1);
  const element2 = document.getElementById(elementId2);

  if (!element1 || !element2) {
    console.error('Elementos para exportação PDF não encontrados.');
    alert('Erro ao gerar PDF: elementos não encontrados.');
    return;
  }
  
  try {
    console.log('Document readyState:', document.readyState);
    console.log('Verificando elementos para PDF:', { 
        el1Exists: !!element1, el1Id: element1.id,
        el2Exists: !!element2, el2Id: element2.id,
        el1Connected: element1.isConnected, 
        el2Connected: element2.isConnected,
        el1ScrollHeight: element1.scrollHeight, el1ScrollWidth: element1.scrollWidth,
        el2ScrollHeight: element2.scrollHeight, el2ScrollWidth: element2.scrollWidth,
        el1ComputedDisplay: window.getComputedStyle(element1).display,
        el2ComputedDisplay: window.getComputedStyle(element2).display,
    });

    // Log the beginning of the HTML content
    console.log('Element 1 innerHTML (first 200 chars):', element1.innerHTML.substring(0, 200));
    console.log('Element 2 innerHTML (first 200 chars):', element2.innerHTML.substring(0, 200));

    // Increased delay significantly
    await new Promise(resolve => setTimeout(resolve, 1500)); 

    const getCanvasOptions = (el: HTMLElement) => ({
        allowTaint: true, // Potentially helps with content that html2canvas might see as tainted
        useCORS: true, // Related to allowTaint
        logging: true, // CRITICAL: Check browser console for html2canvas specific logs
        backgroundColor: '#ffffff', 
        removeContainer: true, // Removes the cloned iframe from the DOM after processing
        taintTest: false, // Disable taint test

        // Explicitly set width and height to scroll dimensions
        width: el.scrollWidth,
        height: el.scrollHeight,
        
        // Window context for layouting
        windowWidth: el.scrollWidth,
        windowHeight: el.scrollHeight,

        // Ensure capture starts from the top-left of the scrollable content
        scrollX: -el.scrollLeft, 
        scrollY: -el.scrollTop,
        x: 0, 
        y: 0,
        scale: 1, // Using scale 1 for stability
    });

    console.log("Opções do Canvas para elemento 1:", getCanvasOptions(element1));
    const canvas1 = await window.html2canvas(element1, getCanvasOptions(element1));
    const imgData1 = canvas1.toDataURL('image/png');
    
    await new Promise(resolve => setTimeout(resolve, 300)); 

    console.log("Opções do Canvas para elemento 2:", getCanvasOptions(element2));
    const canvas2 = await window.html2canvas(element2, getCanvasOptions(element2));
    const imgData2 = canvas2.toDataURL('image/png');

    const imgProps1 = pdf.getImageProperties(imgData1);
    const pdfWidth = pdf.internal.pageSize.getWidth();
    const pdfHeight = pdf.internal.pageSize.getHeight();

    const margin = 40; 
    const availableWidth = (pdfWidth - 3 * margin) / 2;
    
    const imgHeight1 = (imgProps1.height * availableWidth) / imgProps1.width;
    const imgProps2 = pdf.getImageProperties(imgData2);
    const imgHeight2 = (imgProps2.height * availableWidth) / imgProps2.width;

    pdf.setFont('Source Sans Pro', 'bold'); 
    pdf.setFontSize(18);
    pdf.text('Relatório de Comparação de Documentos', pdfWidth / 2, margin, { align: 'center' });
    pdf.setFont('Source Sans Pro', 'normal');
    pdf.setFontSize(12);
    pdf.text('Documento Original (Esquerda) vs Documento Modificado (Direita)', pdfWidth / 2, margin + 20, {align: 'center'});

    const startY = margin + 40;
    const contentMaxHeightOnPage = pdfHeight - margin - startY;
    const tallerScaledHeight = Math.max(imgHeight1, imgHeight2);

    pdf.addImage(imgData1, 'PNG', margin, startY, availableWidth, Math.min(imgHeight1, contentMaxHeightOnPage), undefined, 'FAST');
    pdf.addImage(imgData2, 'PNG', margin + availableWidth + margin, startY, availableWidth, Math.min(imgHeight2, contentMaxHeightOnPage), undefined, 'FAST'); 
    
    if (tallerScaledHeight > contentMaxHeightOnPage) {
      console.warn("Conteúdo da imagem excedeu a altura da página. Considerar solução de paginação para PDF's muito longos.");
    }
    
    pdf.save(filename);

  } catch (error: any) {
    console.error('ERRO DETALHADO AO GERAR PDF:', error); 
    const errorName = error && error.name ? error.name : 'UnknownError';
    const errorMessage = error && error.message ? error.message : 'No message';
    const errorStack = error && error.stack ? error.stack.substring(0, 300) : 'No stack';
    
    const alertMsg = `ERRO AO GERAR PDF: ${errorName} - ${errorMessage}. \n\n***IMPORTANTE: Verifique o CONSOLE DO NAVEGADOR (F12) para MENSAGENS DE ERRO ADICIONAIS DIRETAMENTE DO 'html2canvas' (ativado com logging:true). Essas mensagens são CRUCIAIS para o diagnóstico.***\n\nStack (início): ${errorStack}`;
    alert(alertMsg);
  }
};

export const exportToCsv = (diffs: ComparisonResult['rawDiffs'], filename: string = 'relatorio_alteracoes.csv'): void => {
  if (!diffs || diffs.length === 0) {
    alert('Nenhuma alteração para exportar.');
    return;
  }

  let csvContent = 'Tipo,Texto\n';

  diffs.forEach(chunk => {
    if (chunk.type !== DIFF_EQUAL && chunk.text.trim() !== '') {
      let type = '';
      if (chunk.type === DIFF_INSERT) type = 'Adição';
      else if (chunk.type === DIFF_DELETE) type = 'Remoção';
      
      const sanitizedText = `"${chunk.text.replace(/"/g, '""').replace(/\n/g, ' ')}"`;
      csvContent += `${type},${sanitizedText}\n`;
    }
  });

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  if (link.download !== undefined) {
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url); 
  } else {
    alert('Seu navegador não suporta download direto.');
  }
};
