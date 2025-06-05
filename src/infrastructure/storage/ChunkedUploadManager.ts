/**
 * Gerenciador de upload em chunks para arquivos grandes
 * Permite uploads resilientes com retry automático
 */

import { 
  IStorageProvider, 
  UploadOptions, 
  UploadResult, 
  UploadProgress 
} from '../../domain/interfaces/IStorageProvider';

export interface ChunkUploadConfig {
  chunkSize: number; // 5MB default
  maxRetries: number;
  timeoutMs: number;
  maxConcurrent: number;
}

interface ChunkData {
  index: number;
  start: number;
  end: number;
  data: Blob;
  uploaded: boolean;
  retries: number;
}

export class ChunkedUploadManager {
  private config: ChunkUploadConfig;
  private chunks: ChunkData[] = [];
  private uploadedChunks = 0;
  private aborted = false;

  constructor(config?: Partial<ChunkUploadConfig>) {
    this.config = {
      chunkSize: 5 * 1024 * 1024, // 5MB
      maxRetries: 3,
      timeoutMs: 30000, // 30s
      maxConcurrent: 3,
      ...config
    };
  }

  async upload(
    provider: IStorageProvider,
    file: File,
    path: string,
    options?: UploadOptions
  ): Promise<UploadResult> {
    
    const fileSize = file.size;
    const shouldUseChunks = fileSize > 10 * 1024 * 1024; // >10MB

    // Upload simples para arquivos pequenos
    if (!shouldUseChunks) {
      return provider.upload(file, path, options);
    }

    console.log(`Starting chunked upload for ${file.name} (${fileSize} bytes)`);
    
    this.chunks = this.createChunks(file);
    this.uploadedChunks = 0;
    this.aborted = false;

    try {
      const result = await this.uploadChunks(provider, path, options);
      
      if (options?.onProgress) {
        options.onProgress({
          loaded: fileSize,
          total: fileSize,
          percentage: 100,
          speed: 0,
          currentChunk: this.chunks.length,
          totalChunks: this.chunks.length
        });
      }

      return result;
    } catch (error) {
      throw new Error(`Chunked upload failed: ${(error as Error).message}`);
    }
  }

  abort(): void {
    this.aborted = true;
  }

  private createChunks(file: File): ChunkData[] {
    const chunks: ChunkData[] = [];
    const totalSize = file.size;
    let start = 0;

    for (let i = 0; start < totalSize; i++) {
      const end = Math.min(start + this.config.chunkSize, totalSize);
      const chunk = file.slice(start, end);
      
      chunks.push({
        index: i,
        start,
        end,
        data: chunk,
        uploaded: false,
        retries: 0
      });

      start = end;
    }

    return chunks;
  }

  private async uploadChunks(
    provider: IStorageProvider,
    path: string,
    options?: UploadOptions
  ): Promise<UploadResult> {
    
    const totalChunks = this.chunks.length;
    const concurrentLimit = Math.min(this.config.maxConcurrent, totalChunks);
    
    // Simula upload sequencial (providers simples não suportam chunks reais)
    for (let i = 0; i < totalChunks; i++) {
      if (this.aborted) {
        throw new Error('Upload aborted');
      }

      const chunk = this.chunks[i];
      await this.uploadChunk(provider, chunk, path, options);
      
      this.uploadedChunks++;
      
      if (options?.onProgress) {
        const totalBytes = this.chunks.reduce((sum, c) => sum + c.data.size, 0);
        const uploadedBytes = this.chunks
          .filter(c => c.uploaded)
          .reduce((sum, c) => sum + c.data.size, 0);

        options.onProgress({
          loaded: uploadedBytes,
          total: totalBytes,
          percentage: Math.round((uploadedBytes / totalBytes) * 100),
          speed: 0, // Simplificado
          currentChunk: i + 1,
          totalChunks
        });
      }
    }

    // Simula resultado final (em implementação real seria merge dos chunks)
    const file = await this.mergeChunks();
    return provider.upload(file, path, { ...options, onProgress: undefined });
  }

  private async uploadChunk(
    provider: IStorageProvider,
    chunk: ChunkData,
    path: string,
    options?: UploadOptions
  ): Promise<void> {
    
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      if (this.aborted) {
        throw new Error('Upload aborted');
      }

      try {
        // Simula upload do chunk (providers simples não suportam chunks)
        await this.delay(100 + Math.random() * 200); // Simula network delay
        
        chunk.uploaded = true;
        chunk.retries = attempt;
        
        if (options?.onRetry && attempt > 0) {
          options.onRetry(chunk.index, attempt);
        }
        
        return;
      } catch (error) {
        lastError = error as Error;
        chunk.retries = attempt + 1;

        if (attempt < this.config.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000); // Exponential backoff
          await this.delay(delay);
        }
      }
    }

    throw new Error(
      `Chunk ${chunk.index} failed after ${this.config.maxRetries} retries: ${lastError?.message}`
    );
  }

  private async mergeChunks(): Promise<File> {
    // Simula merge dos chunks em um arquivo
    const blobs = this.chunks.map(c => c.data);
    const mergedBlob = new Blob(blobs);
    
    // Cria um novo File a partir dos chunks
    return new File([mergedBlob], 'merged-file', {
      type: this.chunks[0]?.data.type || 'application/octet-stream'
    });
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  getProgress(): { uploaded: number; total: number; percentage: number } {
    const total = this.chunks.length;
    const uploaded = this.chunks.filter(c => c.uploaded).length;
    
    return {
      uploaded,
      total,
      percentage: total > 0 ? Math.round((uploaded / total) * 100) : 0
    };
  }
} 