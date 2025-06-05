/**
 * Provider local simples para desenvolvimento e testes
 * Simula operações de storage sem persistência real
 */

import { 
  IStorageProvider, 
  StorageProviderType, 
  UploadOptions, 
  UploadResult, 
  DownloadOptions, 
  StorageFileInfo,
  StorageProviderConfig,
  StorageCapabilities 
} from '../../domain/interfaces/IStorageProvider';

export class LocalStorageProvider implements IStorageProvider {
  readonly type: StorageProviderType = 'local';
  private storedFiles = new Map<string, { data: Buffer; info: StorageFileInfo }>();

  async initialize(config: StorageProviderConfig): Promise<void> {
    console.log('LocalStorage initialized');
  }

  async upload(file: File | Buffer, path: string, options?: UploadOptions): Promise<UploadResult> {
    const fileName = file instanceof File ? file.name : 'buffer-upload';
    const fileType = file instanceof File ? file.type : 'application/octet-stream';
    const fileSize = file instanceof File ? file.size : file.length;
    
    const fileId = `local_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const data = file instanceof File ? Buffer.from(await file.arrayBuffer()) : file;
    const now = Date.now();
    const etag = Math.random().toString(36);
    
    const fileInfo: StorageFileInfo = {
      fileId,
      name: fileName,
      size: fileSize,
      contentType: fileType,
      etag,
      createdAt: now,
      lastModified: now,
      metadata: options?.metadata || {}
    };
    
    this.storedFiles.set(fileId, { data, info: fileInfo });

    return {
      fileId,
      etag,
      size: fileSize,
      uploadedAt: now,
      metadata: fileInfo.metadata,
      provider: 'local'
    };
  }

  async download(fileId: string, options?: DownloadOptions): Promise<Buffer> {
    const stored = this.storedFiles.get(fileId);
    if (!stored) {
      throw new Error(`File ${fileId} not found`);
    }
    return stored.data;
  }

  async getFileInfo(fileId: string): Promise<StorageFileInfo> {
    const stored = this.storedFiles.get(fileId);
    if (!stored) {
      throw new Error(`File ${fileId} not found`);
    }
    return stored.info;
  }

  async exists(fileId: string): Promise<boolean> {
    return this.storedFiles.has(fileId);
  }

  async delete(fileId: string): Promise<boolean> {
    return this.storedFiles.delete(fileId);
  }

  async listFiles(prefix?: string, limit?: number, offset?: number): Promise<StorageFileInfo[]> {
    const files = Array.from(this.storedFiles.values()).map(f => f.info);
    return files.slice(offset || 0, (offset || 0) + (limit || files.length));
  }

  async getSignedUrl(fileId: string, expiresIn: number, action?: 'read' | 'write'): Promise<string> {
    return `local://signed/${fileId}?expires=${Date.now() + expiresIn * 1000}`;
  }

  async getPublicUrl(fileId: string): Promise<string | null> {
    return `local://public/${fileId}`;
  }

  getCapabilities(): StorageCapabilities {
    return {
      supportsChunkedUpload: false,
      supportsRetry: false,
      supportsEncryption: false,
      supportsSignedUrls: true,
      supportsPublicUrls: true,
      supportsMetadata: true,
      supportsVersioning: false,
      maxFileSize: 50 * 1024 * 1024,
      maxChunkSize: 0,
      maxConcurrentChunks: 0
    };
  }

  async cleanup(): Promise<void> {
    this.storedFiles.clear();
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }
} 