export interface DocumentMetadata {
  name: string;
  size: number;
  type: string;
  lastModified?: Date;
  hash?: string;
}

export interface ComparisonConfig {
  algorithm: 'diff-match-patch' | 'myers' | 'semantic';
  chunkSize?: number;
  enableCache?: boolean;
  timeout?: number;
}

export class DocumentComparison {
  public readonly id: string;
  public readonly originalDocument: DocumentMetadata;
  public readonly modifiedDocument: DocumentMetadata;
  public readonly config: ComparisonConfig;
  public readonly createdAt: Date;
  public status: 'pending' | 'processing' | 'completed' | 'failed';
  public progress: number;
  public error?: string;

  constructor(
    id: string,
    originalDocument: DocumentMetadata,
    modifiedDocument: DocumentMetadata,
    config: ComparisonConfig = { algorithm: 'diff-match-patch' }
  ) {
    this.id = id;
    this.originalDocument = originalDocument;
    this.modifiedDocument = modifiedDocument;
    this.config = config;
    this.createdAt = new Date();
    this.status = 'pending';
    this.progress = 0;
  }

  public updateStatus(status: 'pending' | 'processing' | 'completed' | 'failed'): void {
    this.status = status;
  }

  public updateProgress(progress: number): void {
    if (progress < 0 || progress > 100) {
      throw new Error('Progress must be between 0 and 100');
    }
    this.progress = progress;
    
    if (progress === 100 && this.status === 'processing') {
      this.status = 'completed';
    }
  }

  public setError(error: string): void {
    this.error = error;
    this.status = 'failed';
  }

  public isCompleted(): boolean {
    return this.status === 'completed';
  }

  public isFailed(): boolean {
    return this.status === 'failed';
  }

  public getDuration(): number | null {
    if (this.status !== 'completed') {
      return null;
    }
    return Date.now() - this.createdAt.getTime();
  }

  public validateDocuments(): boolean {
    const maxSize = 5 * 1024 * 1024; // 5MB
    const allowedTypes = ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

    return (
      this.originalDocument.size <= maxSize &&
      this.modifiedDocument.size <= maxSize &&
      allowedTypes.includes(this.originalDocument.type) &&
      allowedTypes.includes(this.modifiedDocument.type)
    );
  }
} 