export type DiffOperation = 'insert' | 'delete' | 'equal' | 'modify';

export interface DiffChunk {
  operation: DiffOperation;
  text: string;
  originalIndex?: number;
  modifiedIndex?: number;
  lineNumber?: number;
  metadata?: Record<string, any>;
}

export interface SimilarityMetrics {
  jaccard: number;
  levenshtein: number;
  cosine: number;
  overall: number;
}

export interface DiffStatistics {
  totalChanges: number;
  additions: number;
  deletions: number;
  modifications: number;
  charactersAdded: number;
  charactersDeleted: number;
  linesAdded: number;
  linesDeleted: number;
  similarity: SimilarityMetrics;
  processingTime: number;
}

export interface ChangeSection {
  startLine: number;
  endLine: number;
  changeType: DiffOperation;
  intensity: 'low' | 'medium' | 'high';
}

export class DiffResult {
  public readonly id: string;
  public readonly comparisonId: string;
  public readonly algorithm: string;
  public readonly chunks: DiffChunk[];
  public readonly statistics: DiffStatistics;
  public readonly changeSections: ChangeSection[];
  public readonly createdAt: Date;
  public readonly version: string = '1.0';

  constructor(
    id: string,
    comparisonId: string,
    algorithm: string,
    chunks: DiffChunk[],
    statistics: DiffStatistics,
    changeSections: ChangeSection[] = []
  ) {
    this.id = id;
    this.comparisonId = comparisonId;
    this.algorithm = algorithm;
    this.chunks = chunks;
    this.statistics = statistics;
    this.changeSections = changeSections;
    this.createdAt = new Date();
  }

  public getChangesByType(operation: DiffOperation): DiffChunk[] {
    return this.chunks.filter(chunk => chunk.operation === operation);
  }

  public getAdditions(): DiffChunk[] {
    return this.getChangesByType('insert');
  }

  public getDeletions(): DiffChunk[] {
    return this.getChangesByType('delete');
  }

  public getModifications(): DiffChunk[] {
    return this.getChangesByType('modify');
  }

  public getOverallSimilarity(): number {
    return this.statistics.similarity.overall;
  }

  public hasSignificantChanges(threshold: number = 0.1): boolean {
    return this.getOverallSimilarity() < (1 - threshold);
  }

  public getMostChangedSections(limit: number = 5): ChangeSection[] {
    return this.changeSections
      .filter(section => section.intensity === 'high')
      .slice(0, limit);
  }

  public getTotalChangeCount(): number {
    return this.statistics.totalChanges;
  }

  public getProcessingTime(): number {
    return this.statistics.processingTime;
  }

  public exportSummary(): {
    id: string;
    algorithm: string;
    totalChanges: number;
    similarity: number;
    processingTime: number;
    createdAt: string;
  } {
    return {
      id: this.id,
      algorithm: this.algorithm,
      totalChanges: this.getTotalChangeCount(),
      similarity: this.getOverallSimilarity(),
      processingTime: this.getProcessingTime(),
      createdAt: this.createdAt.toISOString()
    };
  }

  public toJSON(): object {
    return {
      id: this.id,
      comparisonId: this.comparisonId,
      algorithm: this.algorithm,
      chunks: this.chunks,
      statistics: this.statistics,
      changeSections: this.changeSections,
      createdAt: this.createdAt.toISOString(),
      version: this.version
    };
  }

  public static fromJSON(data: any): DiffResult {
    return new DiffResult(
      data.id,
      data.comparisonId,
      data.algorithm,
      data.chunks,
      data.statistics,
      data.changeSections || []
    );
  }
} 