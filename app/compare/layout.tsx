import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Document Comparison - ClauseDiff',
  description: 'Advanced document comparison tool with side-by-side and inline diff views. Perfect for legal documents, contracts, and technical documentation.',
  keywords: ['document comparison', 'diff tool', 'legal documents', 'contract analysis', 'text comparison'],
  openGraph: {
    title: 'Document Comparison Tool',
    description: 'Compare documents with advanced algorithms and beautiful visualizations',
    type: 'website',
  }
};

export default function CompareLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
} 