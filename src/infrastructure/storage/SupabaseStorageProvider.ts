/**
 * Provider para Supabase Storage para produção
 * Integra com storage nativo do Supabase
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
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

export interface SupabaseStorageConfig {
  url: string;
  anonKey: string;
  bucketName: string;
  maxFileSize?: number;
}

export class SupabaseStorageProvider implements IStorageProvider {
  readonly type: StorageProviderType = 'supabase';
  private client?: SupabaseClient;
  private config?: SupabaseStorageConfig;
  private bucketName = 'files';

  async initialize(config: StorageProviderConfig): Promise<void> {
    this.config = {
      url: process.env.NEXT_PUBLIC_SUPABASE_URL || '',
      anonKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '',
      bucketName: config.bucket || 'files',
      maxFileSize: config.maxFileSize || 50 * 1024 * 1024
    };

    if (!this.config.url || !this.config.anonKey) {
      throw new Error('Supabase URL and anon key are required');
    }

    this.client = createClient(this.config.url, this.config.anonKey);
    this.bucketName = this.config.bucketName;

    // Tenta criar bucket se não existir
    await this.ensureBucketExists();
  }

  async upload(file: File | Buffer, path: string, options?: UploadOptions): Promise<UploadResult> {
    if (!this.client || !this.config) {
      throw new Error('Provider not initialized');
    }

    const fileName = file instanceof File ? file.name : 'buffer-upload';
    const fileSize = file instanceof File ? file.size : file.length;
    
    // Validação de tamanho
    if (fileSize > (this.config.maxFileSize || 50 * 1024 * 1024)) {
      throw new Error(`File size exceeds limit`);
    }

    const filePath = `${path}/${Date.now()}-${fileName}`;
    
    try {
      const { data, error } = await this.client.storage
        .from(this.bucketName)
        .upload(filePath, file, {
          cacheControl: '3600',
          upsert: options?.overwrite || false
        });

      if (error) {
        throw new Error(`Upload failed: ${error.message}`);
      }

      const now = Date.now();
      return {
        fileId: data.path,
        etag: data.id || '',
        size: fileSize,
        uploadedAt: now,
        metadata: options?.metadata || {},
        provider: 'supabase',
        publicUrl: await this.getPublicUrl(data.path)
      };
    } catch (error) {
      throw new Error(`Supabase upload failed: ${(error as Error).message}`);
    }
  }

  async download(fileId: string, options?: DownloadOptions): Promise<Buffer> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { data, error } = await this.client.storage
        .from(this.bucketName)
        .download(fileId);

      if (error) {
        throw new Error(`Download failed: ${error.message}`);
      }

      return Buffer.from(await data.arrayBuffer());
    } catch (error) {
      throw new Error(`Supabase download failed: ${(error as Error).message}`);
    }
  }

  async getFileInfo(fileId: string): Promise<StorageFileInfo> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { data, error } = await this.client.storage
        .from(this.bucketName)
        .list(fileId.split('/').slice(0, -1).join('/'), {
          search: fileId.split('/').pop()
        });

      if (error || !data.length) {
        throw new Error(`File not found: ${fileId}`);
      }

      const fileData = data[0];
      return {
        fileId,
        name: fileData.name,
        size: fileData.metadata?.size || 0,
        contentType: fileData.metadata?.mimetype || 'application/octet-stream',
        etag: fileData.id || '',
        createdAt: new Date(fileData.created_at).getTime(),
        lastModified: new Date(fileData.updated_at).getTime(),
        metadata: fileData.metadata || {}
      };
    } catch (error) {
      throw new Error(`Failed to get file info: ${(error as Error).message}`);
    }
  }

  async exists(fileId: string): Promise<boolean> {
    try {
      await this.getFileInfo(fileId);
      return true;
    } catch {
      return false;
    }
  }

  async delete(fileId: string): Promise<boolean> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { error } = await this.client.storage
        .from(this.bucketName)
        .remove([fileId]);

      return !error;
    } catch {
      return false;
    }
  }

  async listFiles(prefix?: string, limit?: number, offset?: number): Promise<StorageFileInfo[]> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { data, error } = await this.client.storage
        .from(this.bucketName)
        .list(prefix, {
          limit: limit || 100,
          offset: offset || 0
        });

      if (error) {
        throw new Error(`List failed: ${error.message}`);
      }

      return data.map(file => ({
        fileId: `${prefix}/${file.name}`,
        name: file.name,
        size: file.metadata?.size || 0,
        contentType: file.metadata?.mimetype || 'application/octet-stream',
        etag: file.id || '',
        createdAt: new Date(file.created_at).getTime(),
        lastModified: new Date(file.updated_at).getTime(),
        metadata: file.metadata || {}
      }));
    } catch (error) {
      throw new Error(`Failed to list files: ${(error as Error).message}`);
    }
  }

  async getSignedUrl(fileId: string, expiresIn: number, action: 'read' | 'write' = 'read'): Promise<string> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { data, error } = await this.client.storage
        .from(this.bucketName)
        .createSignedUrl(fileId, expiresIn);

      if (error) {
        throw new Error(`Signed URL creation failed: ${error.message}`);
      }

      return data.signedUrl;
    } catch (error) {
      throw new Error(`Failed to create signed URL: ${(error as Error).message}`);
    }
  }

  async getPublicUrl(fileId: string): Promise<string | null> {
    if (!this.client) {
      throw new Error('Provider not initialized');
    }

    try {
      const { data } = this.client.storage
        .from(this.bucketName)
        .getPublicUrl(fileId);

      return data.publicUrl;
    } catch {
      return null;
    }
  }

  getCapabilities(): StorageCapabilities {
    return {
      supportsChunkedUpload: false, // Supabase não suporta nativamente
      supportsRetry: true,
      supportsEncryption: false,
      supportsSignedUrls: true,
      supportsPublicUrls: true,
      supportsMetadata: true,
      supportsVersioning: false,
      maxFileSize: 50 * 1024 * 1024, // 50MB default
      maxChunkSize: 0,
      maxConcurrentChunks: 0
    };
  }

  async cleanup(): Promise<void> {
    // Não há cleanup específico necessário para Supabase
  }

  async healthCheck(): Promise<boolean> {
    if (!this.client) {
      return false;
    }

    try {
      const { data, error } = await this.client.storage.listBuckets();
      return !error;
    } catch {
      return false;
    }
  }

  private async ensureBucketExists(): Promise<void> {
    if (!this.client) return;

    try {
      // Tenta listar bucket - se falhar, tenta criar
      const { error: listError } = await this.client.storage
        .from(this.bucketName)
        .list('', { limit: 1 });

      if (listError && listError.message.includes('not found')) {
        const { error: createError } = await this.client.storage
          .createBucket(this.bucketName, {
            public: false,
            allowedMimeTypes: [
              'text/plain',
              'application/pdf',
              'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
              'application/msword'
            ],
            fileSizeLimit: this.config?.maxFileSize
          });

        if (createError) {
          console.warn(`Could not create bucket: ${createError.message}`);
        }
      }
    } catch (error) {
      console.warn(`Bucket setup failed: ${(error as Error).message}`);
    }
  }
} 