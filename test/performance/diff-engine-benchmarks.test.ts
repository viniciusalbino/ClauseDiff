import { performance } from 'perf_hooks';

// Interfaces simples para benchmark
interface BenchmarkResult {
  name: string;
  iterations: number;
  totalTime: number;
  averageTime: number;
  minTime: number;
  maxTime: number;
  opsPerSecond: number;
  memoryUsage?: number;
}

interface BenchmarkSuite {
  name: string;
  results: BenchmarkResult[];
  summary: {
    fastest: string;
    slowest: string;
    totalTime: number;
  };
}

/**
 * Classe para execução de benchmarks de performance
 */
class DiffBenchmark {
  private results: BenchmarkResult[] = [];

  /**
   * Executa benchmark de uma função
   */
  public async benchmark<T>(
    name: string,
    fn: () => T | Promise<T>,
    iterations = 100
  ): Promise<BenchmarkResult> {
    const times: number[] = [];
    let totalTime = 0;

    // Warm-up
    for (let i = 0; i < 5; i++) {
      await fn();
    }

    // Benchmark real
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      await fn();
      const end = performance.now();
      
      const time = end - start;
      times.push(time);
      totalTime += time;
    }

    const averageTime = totalTime / iterations;
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);
    const opsPerSecond = 1000 / averageTime;

    const result: BenchmarkResult = {
      name,
      iterations,
      totalTime,
      averageTime,
      minTime,
      maxTime,
      opsPerSecond
    };

    this.results.push(result);
    return result;
  }

  /**
   * Gera relatório dos resultados
   */
  public generateReport(): BenchmarkSuite {
    const fastest = this.results.reduce((a, b) => 
      a.averageTime < b.averageTime ? a : b
    );
    
    const slowest = this.results.reduce((a, b) => 
      a.averageTime > b.averageTime ? a : b
    );

    return {
      name: 'Diff Engine Benchmarks',
      results: this.results,
      summary: {
        fastest: fastest.name,
        slowest: slowest.name,
        totalTime: this.results.reduce((sum, r) => sum + r.totalTime, 0)
      }
    };
  }

  /**
   * Limpa resultados
   */
  public clear(): void {
    this.results = [];
  }
}

// Dados de teste simulados
const generateTestContent = (size: 'small' | 'medium' | 'large') => {
  const baseText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(10);
  
  switch (size) {
    case 'small':
      return {
        original: baseText.repeat(10), // ~5KB
        modified: baseText.repeat(10).replace(/Lorem/g, 'MODIFIED')
      };
    case 'medium':
      return {
        original: baseText.repeat(100), // ~50KB  
        modified: baseText.repeat(100).replace(/Lorem/g, 'MODIFIED').replace(/ipsum/g, 'CHANGED')
      };
    case 'large':
      return {
        original: baseText.repeat(1000), // ~500KB
        modified: baseText.repeat(1000).replace(/Lorem/g, 'MODIFIED').replace(/ipsum/g, 'CHANGED').replace(/dolor/g, 'UPDATED')
      };
  }
};

// Algoritmos simulados simples para benchmark
const simpleDiffAlgorithm = (original: string, modified: string) => {
  const originalLines = original.split('\n');
  const modifiedLines = modified.split('\n');
  
  let changes = 0;
  const maxLines = Math.max(originalLines.length, modifiedLines.length);
  
  for (let i = 0; i < maxLines; i++) {
    if (originalLines[i] !== modifiedLines[i]) {
      changes++;
    }
  }
  
  return { changes, similarity: 1 - (changes / maxLines) };
};

const wordDiffAlgorithm = (original: string, modified: string) => {
  const originalWords = original.split(/\s+/);
  const modifiedWords = modified.split(/\s+/);
  
  let changes = 0;
  const maxWords = Math.max(originalWords.length, modifiedWords.length);
  
  for (let i = 0; i < maxWords; i++) {
    if (originalWords[i] !== modifiedWords[i]) {
      changes++;
    }
  }
  
  return { changes, similarity: 1 - (changes / maxWords) };
};

const characterDiffAlgorithm = (original: string, modified: string) => {
  let changes = 0;
  const maxLength = Math.max(original.length, modified.length);
  
  for (let i = 0; i < maxLength; i++) {
    if (original[i] !== modified[i]) {
      changes++;
    }
  }
  
  return { changes, similarity: 1 - (changes / maxLength) };
};

describe('Diff Engine Benchmarks', () => {
  let benchmark: DiffBenchmark;

  beforeEach(() => {
    benchmark = new DiffBenchmark();
  });

  describe('Small Documents (~5KB)', () => {
    const testData = generateTestContent('small');

    test('Simple Line Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Simple Line Diff (Small)',
        () => simpleDiffAlgorithm(testData.original, testData.modified),
        50
      );

      expect(result.averageTime).toBeLessThan(100); // < 100ms
      expect(result.opsPerSecond).toBeGreaterThan(10);
    });

    test('Word Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Word Diff (Small)',
        () => wordDiffAlgorithm(testData.original, testData.modified),
        50
      );

      expect(result.averageTime).toBeLessThan(150); // < 150ms
      expect(result.opsPerSecond).toBeGreaterThan(6);
    });

    test('Character Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Character Diff (Small)',
        () => characterDiffAlgorithm(testData.original, testData.modified),
        50
      );

      expect(result.averageTime).toBeLessThan(200); // < 200ms
      expect(result.opsPerSecond).toBeGreaterThan(5);
    });
  });

  describe('Medium Documents (~50KB)', () => {
    const testData = generateTestContent('medium');

    test('Simple Line Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Simple Line Diff (Medium)',
        () => simpleDiffAlgorithm(testData.original, testData.modified),
        20
      );

      expect(result.averageTime).toBeLessThan(500); // < 500ms
      expect(result.opsPerSecond).toBeGreaterThan(2);
    });

    test('Word Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Word Diff (Medium)',
        () => wordDiffAlgorithm(testData.original, testData.modified),
        20
      );

      expect(result.averageTime).toBeLessThan(1000); // < 1s
      expect(result.opsPerSecond).toBeGreaterThan(1);
    });
  });

  describe('Large Documents (~500KB)', () => {
    const testData = generateTestContent('large');

    test('Simple Line Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Simple Line Diff (Large)',
        () => simpleDiffAlgorithm(testData.original, testData.modified),
        5
      );

      expect(result.averageTime).toBeLessThan(2000); // < 2s
      expect(result.opsPerSecond).toBeGreaterThan(0.5);
    }, 15000); // timeout de 15s

    test('Word Diff Performance', async () => {
      const result = await benchmark.benchmark(
        'Word Diff (Large)',
        () => wordDiffAlgorithm(testData.original, testData.modified),
        3
      );

      expect(result.averageTime).toBeLessThan(5000); // < 5s
      expect(result.opsPerSecond).toBeGreaterThan(0.2);
    }, 20000); // timeout de 20s
  });

  describe('Comparative Performance', () => {
    test('Compare all algorithms with medium data', async () => {
      const testData = generateTestContent('medium');

      await benchmark.benchmark(
        'Line Diff',
        () => simpleDiffAlgorithm(testData.original, testData.modified),
        10
      );

      await benchmark.benchmark(
        'Word Diff',
        () => wordDiffAlgorithm(testData.original, testData.modified),
        10
      );

      await benchmark.benchmark(
        'Character Diff',
        () => characterDiffAlgorithm(testData.original, testData.modified),
        10
      );

      const report = benchmark.generateReport();
      
      expect(report.results).toHaveLength(3);
      expect(report.summary.fastest).toBeDefined();
      expect(report.summary.slowest).toBeDefined();

      console.log('Performance Report:', JSON.stringify(report, null, 2));
    });
  });

  describe('Memory Usage Tests', () => {
    test('Memory efficiency with large documents', async () => {
      const testData = generateTestContent('large');
      
      const initialMemory = process.memoryUsage();
      
      for (let i = 0; i < 5; i++) {
        simpleDiffAlgorithm(testData.original, testData.modified);
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Verificar que o aumento de memória é razoável (< 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });
  });

  describe('Scalability Tests', () => {
    test('Performance scales predictably with document size', async () => {
      const small = generateTestContent('small');
      const medium = generateTestContent('medium');
      
      const smallResult = await benchmark.benchmark(
        'Small Scale Test',
        () => simpleDiffAlgorithm(small.original, small.modified),
        20
      );
      
      benchmark.clear();
      
      const mediumResult = await benchmark.benchmark(
        'Medium Scale Test',
        () => simpleDiffAlgorithm(medium.original, medium.modified),
        20
      );
      
      // Documentos médios devem levar mais tempo, mas não exponencialmente
      const scaleFactor = mediumResult.averageTime / smallResult.averageTime;
      expect(scaleFactor).toBeGreaterThan(1);
      expect(scaleFactor).toBeLessThan(50); // Não deve ser mais de 50x mais lento
    });
  });
});

// Utilitários para execução manual de benchmarks
export { DiffBenchmark, generateTestContent, simpleDiffAlgorithm, wordDiffAlgorithm, characterDiffAlgorithm }; 