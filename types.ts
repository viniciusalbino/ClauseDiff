// Global type declarations for CDN libraries
declare global {
  interface Window {
    mammoth: {
      extractRawText: (options: { arrayBuffer: ArrayBuffer }) => Promise<{ value: string }>;
      convertToHtml: (options: { arrayBuffer: ArrayBuffer }) => Promise<{ value: string }>;
    };
    diff_match_patch: new () => {
      diff_main(text1: string, text2: string): Array<[number, string]>;
      diff_cleanupSemantic(diffs: Array<[number, string]>): void;
      DIFF_DELETE: -1;
      DIFF_INSERT: 1;
      DIFF_EQUAL: 0;
    };
    jspdf: {
      jsPDF: new (options?: any) => any; 
    };
    html2canvas: (element: HTMLElement, options?: any) => Promise<HTMLCanvasElement>;
    pdfjsLib: { // For PDF.js
      GlobalWorkerOptions: {
        workerSrc: string;
      };
      getDocument: (src: string | Uint8Array | { data: ArrayBuffer }) => {
        promise: Promise<any>; // Replace 'any' with more specific PDFDocumentProxy if detailed types are needed
      };
    };
  }
}

// Constants for diff operations, aligned with diff-match-patch library values
export const DIFF_DELETE = 'delete';
export const DIFF_INSERT = 'insert';
export const DIFF_EQUAL = 'equal';

// Type for the diff-match-patch library's numeric operation codes
export type DiffOperation = -1 | 0 | 1;

export type DiffType = typeof DIFF_INSERT | typeof DIFF_DELETE | typeof DIFF_EQUAL;

export interface Diff {
  type: DiffType;
  value: string;
}

export interface DocumentData {
  content: string;
  name: string;
  type: string;
  originalFile?: File;
}

export interface DiffResult {
  diffs: Diff[];
  summary: {
    insertions: number;
    deletions: number;
    changes: number;
  };
}

export interface ComparisonResult {
  html1: string;
  html2: string;
  summary: {
    additions: number;
    deletions: number;
    totalDifferences: number;
  };
  rawDiffs: Array<{
    type: 'insert' | 'delete' | 'equal';
    text: string;
  }>;
}

// NextAuth type augmentations
import type { DefaultSession, DefaultUser } from "next-auth";
import type { DefaultJWT } from "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
      firstName?: string | null;
      lastName?: string | null;
      emailVerified?: string | Date | null;
      role?: string | null; // Use string instead of Prisma enum to avoid import issues
    } & DefaultSession["user"];
    accessToken?: string;
    // Debug information (only in development)
    debug?: {
      tokenIat?: number;
      tokenExp?: number;
      timeUntilExpiry?: number;
    };
  }

  interface User extends DefaultUser {
    id: string;
    name?: string | null;
    email?: string | null;
    image?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    emailVerified?: string | Date | null;
    role?: string | null; // Use string instead of Prisma enum
  }
}

declare module "next-auth/jwt" {
  interface JWT extends DefaultJWT {
    id: string;
    name?: string | null;
    email?: string | null;
    picture?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    emailVerified?: string | Date | null;
    role?: string | null; // Use string instead of Prisma enum
    accessToken?: string;
  }
}

// You can also define other global types for your application below
// For example:
// export interface MyCustomType {
//   property: string;
// }

// Ensure this file is treated as a module.
export {};