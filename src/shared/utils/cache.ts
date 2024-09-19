export class CacheUtils {
  static getCacheKey(key: string, value: string): string {
    return `${key}:${value}`;
  }
}
