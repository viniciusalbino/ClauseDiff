/**
 * Factory para criação de providers de storage
 * Implementa padrão Factory para escolha dinâmica de provider
 */

import { 
  IStorageProvider, 
  StorageProviderType, 
  StorageProviderConfig 
} from '../../domain/interfaces/IStorageProvider';
import { LocalStorageProvider } from './LocalStorageProvider';

export interface StorageConfig {
  provider: StorageProviderType;
  bucket: string;
  maxFileSize?: number;
  region?: string;
  pathPrefix?: string;
}

export class StorageFactory {
  static async createProvider(config: StorageConfig): Promise<IStorageProvider> {
    let provider: IStorageProvider;

    switch (config.provider) {
      case 'local':
        provider = new LocalStorageProvider();
        break;
      
      case 'supabase':
        // Importação dinâmica para evitar dependências desnecessárias
        const { SupabaseStorageProvider } = await import('./SupabaseStorageProvider');
        provider = new SupabaseStorageProvider();
        break;
      
      default:
        throw new Error(`Unsupported storage provider: ${config.provider}`);
    }

    // Inicializa o provider
    await provider.initialize({
      type: config.provider,
      bucket: config.bucket,
      maxFileSize: config.maxFileSize,
      region: config.region,
      pathPrefix: config.pathPrefix
    });

    return provider;
  }

  static getDefaultConfig(): StorageConfig {
    const env = process.env.NODE_ENV || 'development';
    
    return {
      provider: env === 'production' ? 'supabase' : 'local',
      bucket: 'clausediff-files',
      maxFileSize: 50 * 1024 * 1024, // 50MB
      pathPrefix: `uploads/${env}`
    };
  }

  static async createDefaultProvider(): Promise<IStorageProvider> {
    const config = this.getDefaultConfig();
    return this.createProvider(config);
  }
} 