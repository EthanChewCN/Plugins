import { Plugin } from "@utils/pluginBase";
import { Api } from "telegram";
import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import * as http from "http";
import Database from "better-sqlite3";

const CONFIG_KEYS = {
  AI_API_KEY: "ai_api_key",
  AI_BASE_URL: "ai_base_url", 
  AI_CHAT_MODEL: "ai_chat_model",
  AI_SEARCH_MODEL: "ai_search_model",
  AI_IMAGE_MODEL: "ai_image_model",
  AI_TTS_MODEL: "ai_tts_model",
  AI_TTS_VOICE: "ai_tts_voice",
  AI_CHAT_ACTIVE_PROMPT: "ai_chat_active_prompt",
  AI_SEARCH_ACTIVE_PROMPT: "ai_search_active_prompt",
  AI_TTS_ACTIVE_PROMPT: "ai_tts_active_prompt",
  AI_MAX_TOKENS: "ai_max_tokens",
  AI_PROMPTS: "ai_prompts",
  AI_CONTEXT_ENABLED: "ai_context_enabled",
  AI_CHAT_HISTORY: "ai_chat_history",
  AI_TELEGRAPH_ENABLED: "ai_telegraph_enabled",
  AI_TELEGRAPH_LIMIT: "ai_telegraph_limit",
  AI_TELEGRAPH_TOKEN: "ai_telegraph_token",
  AI_TELEGRAPH_POSTS: "ai_telegraph_posts",
  AI_COLLAPSIBLE_QUOTE_ENABLED: "ai_collapsible_quote_enabled",
  // 多服务商配置
  AI_KEYS: "ai_keys", // { gemini?: string, openai?: string, claude?: string, deepseek?: string, grok?: string, thirdparty?: string }
  AI_BASE_URLS: "ai_base_urls", // { thirdparty?: string, openai?: string, ... }
  AI_MODELS: "ai_models", // { chat?: string, search?: string, image?: string, tts?: string }
  AI_THIRD_PARTY_COMPAT: "ai_thirdparty_compat", // openai|gemini|claude|deepseek|grok
  AI_ACTIVE_PROVIDER: "ai_active_provider" // gemini|openai|claude|deepseek|grok|thirdparty
};

const DEFAULT_CONFIG = {
  [CONFIG_KEYS.AI_BASE_URL]: "https://generativelanguage.googleapis.com",
  [CONFIG_KEYS.AI_CHAT_MODEL]: "gemini-2.0-flash",
  [CONFIG_KEYS.AI_SEARCH_MODEL]: "gemini-2.0-flash",
  [CONFIG_KEYS.AI_IMAGE_MODEL]: "gemini-2.0-flash-preview-image-generation",
  [CONFIG_KEYS.AI_TTS_MODEL]: "gemini-2.5-flash-preview-tts",
  [CONFIG_KEYS.AI_TTS_VOICE]: "Kore",
  [CONFIG_KEYS.AI_MAX_TOKENS]: "0",
  [CONFIG_KEYS.AI_PROMPTS]: "{}",
  [CONFIG_KEYS.AI_CONTEXT_ENABLED]: "off",
  [CONFIG_KEYS.AI_CHAT_HISTORY]: "[]",
  [CONFIG_KEYS.AI_TELEGRAPH_ENABLED]: "off",
  [CONFIG_KEYS.AI_TELEGRAPH_LIMIT]: "0",
  [CONFIG_KEYS.AI_TELEGRAPH_POSTS]: "{}",
  [CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED]: "off",
  // 新增默认
  [CONFIG_KEYS.AI_KEYS]: "{}",
  [CONFIG_KEYS.AI_BASE_URLS]: "{}",
  [CONFIG_KEYS.AI_MODELS]: "{}",
  [CONFIG_KEYS.AI_THIRD_PARTY_COMPAT]: ""
};

const CONFIG_DB_PATH = path.join((globalThis as any).process?.cwd?.() || ".", "assets", "ai_config.db");

if (!fs.existsSync(path.dirname(CONFIG_DB_PATH))) {
  fs.mkdirSync(path.dirname(CONFIG_DB_PATH), { recursive: true });
}

class ConfigManager {
  private static db: Database.Database;
  private static initialized = false;
  // 配置缓存
  private static cache = new Map<string, { value: string; timestamp: number }>();
  private static allConfigCache: { data: { [key: string]: string }; timestamp: number } | null = null;
  // 缓存过期时间（毫秒）
  private static readonly CACHE_TTL = 5 * 60 * 1000; // 5分钟
  // 缓存大小限制
  private static readonly MAX_CACHE_SIZE = 1000;
  // 批量操作缓存
  private static pendingWrites = new Map<string, string>();
  private static writeTimer: NodeJS.Timeout | null = null;
  private static readonly BATCH_WRITE_DELAY = 1000; // 1秒
  // 定期清理定时器
  private static cleanupTimer: NodeJS.Timeout | null = null;
  private static readonly CLEANUP_INTERVAL = 10 * 60 * 1000; // 10分钟

  private static init(): void {
    if (this.initialized) return;
    try {
      this.db = new Database(CONFIG_DB_PATH);
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS config (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      this.initialized = true;
    } catch (error) {
      console.error("初始化配置数据库失败:", error);
    }
  }

  private static isCacheValid(timestamp: number): boolean {
    return Date.now() - timestamp < this.CACHE_TTL;
  }

  private static invalidateCache(key?: string): void {
    if (key) {
      this.cache.delete(key);
    } else {
      this.cache.clear();
    }
    this.allConfigCache = null;
  }

  /**
   * 清理过期缓存项
   */
  private static cleanupExpiredCache(): void {
    const now = Date.now();
    const expiredKeys: string[] = [];
    
    for (const [key, { timestamp }] of this.cache) {
      if (now - timestamp >= this.CACHE_TTL) {
        expiredKeys.push(key);
      }
    }
    
    expiredKeys.forEach(key => this.cache.delete(key));
    
    // 清理全量缓存如果过期
    if (this.allConfigCache && now - this.allConfigCache.timestamp >= this.CACHE_TTL) {
      this.allConfigCache = null;
    }
    
    if (expiredKeys.length > 0) {
      console.debug(`[ConfigManager] 清理了 ${expiredKeys.length} 个过期缓存项`);
    }
  }

  /**
   * 限制缓存大小，移除最旧的项
   */
  private static limitCacheSize(): void {
    if (this.cache.size <= this.MAX_CACHE_SIZE) return;
    
    const entries = Array.from(this.cache.entries())
      .sort(([, a], [, b]) => a.timestamp - b.timestamp);
    
    const toRemove = entries.slice(0, this.cache.size - this.MAX_CACHE_SIZE);
    toRemove.forEach(([key]) => this.cache.delete(key));
    
    console.debug(`[ConfigManager] 缓存大小限制，移除了 ${toRemove.length} 个最旧的缓存项`);
  }

  /**
   * 启动定期清理任务
   */
  private static startCleanupTimer(): void {
    if (this.cleanupTimer) return;
    
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredCache();
      this.limitCacheSize();
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * 停止定期清理任务
   */
  private static stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  private static executeBatchWrites(): void {
    if (this.pendingWrites.size === 0) return;
    
    this.init();
    try {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO config (key, value, updated_at) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
      `);
      
      const transaction = this.db.transaction(() => {
        for (const [key, value] of this.pendingWrites) {
          stmt.run(key, value);
        }
      });
      
      transaction();
      this.pendingWrites.clear();
    } catch (error) {
      console.error("批量保存配置失败:", error);
    }
  }

  static get(key: string, defaultValue?: string): string {
    // 检查缓存
    const cached = this.cache.get(key);
    if (cached && this.isCacheValid(cached.timestamp)) {
      return cached.value;
    }

    this.init();
    this.startCleanupTimer(); // 启动清理任务
    
    try {
      const stmt = this.db.prepare("SELECT value FROM config WHERE key = ?");
      const row = stmt.get(key) as { value: string } | undefined;
      
      if (row) {
        // 更新缓存
        this.cache.set(key, { value: row.value, timestamp: Date.now() });
        this.limitCacheSize(); // 检查缓存大小
        return row.value;
      }
    } catch (error) {
      console.error("读取配置失败:", error);
    }
    
    const defaultVal = defaultValue || DEFAULT_CONFIG[key] || "";
    // 缓存默认值
    this.cache.set(key, { value: defaultVal, timestamp: Date.now() });
    this.limitCacheSize(); // 检查缓存大小
    return defaultVal;
  }

  static set(key: string, value: string): void {
    // 立即更新缓存
    this.cache.set(key, { value, timestamp: Date.now() });
    this.invalidateCache(); // 清除全量缓存
    
    // 添加到批量写入队列
    this.pendingWrites.set(key, value);
    
    // 设置批量写入定时器
    if (this.writeTimer) {
      clearTimeout(this.writeTimer);
    }
    
    this.writeTimer = setTimeout(() => {
      this.executeBatchWrites();
      this.writeTimer = null;
    }, this.BATCH_WRITE_DELAY);
  }

  static getAll(): { [key: string]: string } {
    // 检查全量缓存
    if (this.allConfigCache && this.isCacheValid(this.allConfigCache.timestamp)) {
      return { ...this.allConfigCache.data };
    }

    this.init();
    try {
      const stmt = this.db.prepare("SELECT key, value FROM config");
      const rows = stmt.all() as { key: string; value: string }[];
      
      const config: { [key: string]: string } = {};
      rows.forEach(row => {
        config[row.key] = row.value;
        // 同时更新单项缓存
        this.cache.set(row.key, { value: row.value, timestamp: Date.now() });
      });
      
      // 更新全量缓存
      this.allConfigCache = { data: config, timestamp: Date.now() };
      return { ...config };
    } catch (error) {
      console.error("读取所有配置失败:", error);
      return {};
    }
  }

  static delete(key: string): void {
    this.invalidateCache(key);
    
    this.init();
    try {
      const stmt = this.db.prepare("DELETE FROM config WHERE key = ?");
      stmt.run(key);
    } catch (error) {
      console.error("删除配置失败:", error);
    }
  }

  static close(): void {
    // 停止定期清理任务
    this.stopCleanupTimer();
    
    // 执行剩余的批量写入
    if (this.writeTimer) {
      clearTimeout(this.writeTimer);
      this.executeBatchWrites();
    }
    
    if (this.db) {
      this.db.close();
    }
    
    // 清理缓存
    this.cache.clear();
    this.allConfigCache = null;
    
    console.debug('[ConfigManager] 资源已清理，数据库连接已关闭');
  }

  // 手动刷新缓存
  static flushCache(): void {
    this.invalidateCache();
  }

  // 立即执行待写入的配置
  static flush(): void {
    if (this.writeTimer) {
      clearTimeout(this.writeTimer);
      this.writeTimer = null;
    }
    this.executeBatchWrites();
  }

  /**
   * 获取缓存统计信息
   */
  static getCacheStats(): {
    cacheSize: number;
    maxCacheSize: number;
    allConfigCached: boolean;
    pendingWrites: number;
    memoryUsageEstimate: string;
  } {
    // 估算内存使用（粗略计算）
    let memoryBytes = 0;
    for (const [key, { value }] of this.cache) {
      memoryBytes += (key.length + value.length) * 2; // UTF-16 字符
      memoryBytes += 16; // 时间戳和对象开销
    }
    
    if (this.allConfigCache) {
      const dataStr = JSON.stringify(this.allConfigCache.data);
      memoryBytes += dataStr.length * 2 + 16;
    }
    
    const memoryKB = Math.round(memoryBytes / 1024);
    const memoryUsageEstimate = memoryKB > 1024 
      ? `${Math.round(memoryKB / 1024 * 100) / 100} MB`
      : `${memoryKB} KB`;
    
    return {
      cacheSize: this.cache.size,
      maxCacheSize: this.MAX_CACHE_SIZE,
      allConfigCached: this.allConfigCache !== null,
      pendingWrites: this.pendingWrites.size,
      memoryUsageEstimate
    };
  }

  /**
   * 手动触发缓存清理
   */
  static performMaintenance(): void {
    const beforeSize = this.cache.size;
    this.cleanupExpiredCache();
    this.limitCacheSize();
    const afterSize = this.cache.size;
    
    console.info(`[ConfigManager] 缓存维护完成: ${beforeSize} -> ${afterSize} 项`);
  }
}

class Utils {
  static censorUrl(url: string | null): string {
    if (!url) return "默认";
    return url.replace(/(?<=\/\/)[^\/]+/, '***');
  }

  static getUtf16Length(text: string): number {
    return Buffer.from(text, 'utf16le').length / 2;
  }

  static removeAiFooter(text: string): string {
    const lines = text.split('\n');
    if (lines.length > 0 && /Powered by /i.test(lines[lines.length - 1])) {
      lines.pop();
    }
    return lines.join('\n');
  }

  // 根据模型名推断提供商显示名
  static getProviderByModel(model?: string | null): string {
    const m = (model || '').toLowerCase();
    if (!m) return 'Google Gemini';
    if (m.includes('gemini')) return 'Google Gemini';
    if (m.includes('gpt') || m.includes('o1') || m.includes('o3')) return 'OpenAI';
    if (m.includes('claude')) return 'Anthropic Claude';
    if (m.includes('deepseek')) return 'DeepSeek';
    if (m.includes('grok') || m.includes('xai')) return 'xAI Grok';
    return 'AI';
  }

  // 渲染统一格式的页脚文案
  static renderPoweredByFooter(opts: { model?: string | null; withSearch?: boolean; kind?: 'chat'|'search'|'image'|'tts'|'audio'; voiceName?: string; errorText?: string } = {}): string {
    const provider = Utils.getProviderByModel(opts.model);
    const searchSuffix = opts.withSearch ? ' with Google Search' : '';

    if (opts.errorText) {
      return `\n\n<i>Powered by ${provider}${searchSuffix} (${opts.errorText}，仅显示文本)</i>`;
    }
    if (opts.kind === 'tts') {
      return `\n\n<i>Powered by ${provider} TTS (${opts.voiceName || ''})</i>`;
    }
    if (opts.kind === 'audio') {
      return `\n\n<i>Powered by ${provider}${searchSuffix} Audio (${opts.voiceName || ''})</i>`;
    }
    return `\n\n<i>Powered by ${provider}${searchSuffix}</i>`;
  }

  static escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '<')
      .replace(/>/g, '>')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  static sanitizeHtmlForTelegraph(htmlContent: string): string {
    const allowedTags = new Set([
      'a', 'aside', 'b', 'blockquote', 'br', 'code', 'em', 'figcaption',
      'figure', 'h3', 'h4', 'hr', 'i', 'iframe', 'img', 'li', 'ol', 'p',
      'pre', 's', 'strong', 'u', 'ul', 'video'
    ]);

    return htmlContent.replace(/<(\/?)[\w\d]+([^>]*)>/g, (match) => {
      const tagName = match.match(/<\/?([\w\d]+)/)?.[1];
      if (tagName && allowedTags.has(tagName.toLowerCase())) {
        return match;
      }
      return '';
    });
  }

  static removeEmoji(text: string): string {
    // 简单的emoji移除方法
    return text
      .replace(/[\u2600-\u27BF]/g, '') // 杂项符号
      .replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '') // 代理对（包含大部分emoji）
      .replace(/[\uFE0F\u200D]/g, '') // 变体选择器和零宽连接符
      .trim();
  }

  static validateConfig(key: string, value: string): { isValid: boolean; error?: string } {
    if (value.length > 10000) {
      return { isValid: false, error: "输入值过长，最大允许10000字符" };
    }

    const validators = {
      [CONFIG_KEYS.AI_API_KEY]: (v: string) => {
        if (!v || v.trim().length === 0) return "API密钥不能为空";
        if (v.length < 10) return "API密钥格式无效";
        if (!/^[A-Za-z0-9_-]+$/.test(v)) return "API密钥包含无效字符";
        return null;
      },
      [CONFIG_KEYS.AI_MAX_TOKENS]: (v: string) => {
        const tokens = parseInt(v);
        if (isNaN(tokens) || tokens < 0) return "Token数量必须为非负整数";
        if (tokens > 1000000) return "Token数量过大，最大允许1000000";
        return null;
      },
      [CONFIG_KEYS.AI_BASE_URL]: (v: string) => {
        if (v && !v.startsWith('http')) return "URL必须以http://或https://开头";
        if (v && v.length > 500) return "URL长度过长";

        if (v) {
          try {
            new URL(v);
          } catch {
            return "URL格式无效";
          }
        }
        return null;
      },
      [CONFIG_KEYS.AI_TELEGRAPH_LIMIT]: (v: string) => {
        const limit = parseInt(v);
        if (isNaN(limit) || limit < 0) return "限制必须为非负整数";
        if (limit > 100000) return "限制值过大，最大允许100000";
        return null;
      },
      [CONFIG_KEYS.AI_CONTEXT_ENABLED]: (v: string) => {
        if (v !== "on" && v !== "off") return "值必须为 'on' 或 'off'";
        return null;
      },
      [CONFIG_KEYS.AI_TELEGRAPH_ENABLED]: (v: string) => {
        if (v !== "on" && v !== "off") return "值必须为 'on' 或 'off'";
        return null;
      },
      [CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED]: (v: string) => {
        if (v !== "on" && v !== "off") return "值必须为 'on' 或 'off'";
        return null;
      }
    };
    const validator = validators[key];
    if (validator) {
      const error = validator(value);
      return error ? { isValid: false, error } : { isValid: true };
    }
    return { isValid: true };
  }

  static getAudioExtension(mimeType?: string): string {
    if (!mimeType) return 'mp3';
    if (mimeType.includes('wav')) return 'wav';
    if (mimeType.includes('mp3')) return 'mp3';
    if (mimeType.includes('ogg')) return 'ogg';
    if (mimeType.includes('m4a')) return 'm4a';
    return 'mp3';
  }

  static async sendImageBuffer(
    msg: Api.Message,
    imageData: Buffer,
    caption: string
  ): Promise<void> {
    const imageFile = Object.assign(imageData, {
      name: 'ai.png'
    });
    
    await msg.client?.sendFile(msg.peerId, {
      file: imageFile,
      caption,
      parseMode: "html",
      replyTo: msg.id
    });
  }

  static async sendAudioBuffer(
    msg: Api.Message,
    audioData: Buffer,
    caption: string,
    mimeType?: string
  ): Promise<void> {
    let processedAudio = audioData;
    if (mimeType && mimeType.includes('L16') && mimeType.includes('pcm')) {
      processedAudio = this.convertToWav(audioData, mimeType);
    }
    const audioFile = Object.assign(processedAudio, {
      name: 'ai.ogg'
    });

    await msg.client?.sendFile(msg.peerId, {
      file: audioFile,
      caption,
      parseMode: "html",
      replyTo: msg.id,
      attributes: [new Api.DocumentAttributeAudio({
        duration: 0,
        voice: true
      })]
    });
  }

  static convertToWav(rawData: string | Buffer, mimeType: string): Buffer {
    const options = this.parseMimeType(mimeType);
    const buffer = typeof rawData === 'string' ? Buffer.from(rawData, 'base64') : rawData;
    const wavHeader = this.createWavHeader(buffer.length, options);
    return Buffer.concat([wavHeader, buffer]);
  }

  static parseMimeType(mimeType: string): WavConversionOptions {
    const [fileType, ...params] = mimeType.split(';').map(s => s.trim());
    const [_, format] = fileType.split('/');

    const options: Partial<WavConversionOptions> = {
      numChannels: 1,
      sampleRate: 24000,
      bitsPerSample: 16
    };

    if (format && format.startsWith('L')) {
      const bits = parseInt(format.slice(1), 10);
      if (!isNaN(bits)) {
        options.bitsPerSample = bits;
      }
    }

    for (const param of params) {
      const [key, value] = param.split('=').map(s => s.trim());
      if (key === 'rate') {
        options.sampleRate = parseInt(value, 10);
      }
    }

    return options as WavConversionOptions;
  }

  static createWavHeader(dataLength: number, options: WavConversionOptions): Buffer {
    const { numChannels, sampleRate, bitsPerSample } = options;
    const byteRate = sampleRate * numChannels * bitsPerSample / 8;
    const blockAlign = numChannels * bitsPerSample / 8;
    const buffer = Buffer.alloc(44);

    buffer.write('RIFF', 0);                      
    buffer.writeUInt32LE(36 + dataLength, 4);     
    buffer.write('WAVE', 8);                      
    buffer.write('fmt ', 12);                     
    buffer.writeUInt32LE(16, 16);                 
    buffer.writeUInt16LE(1, 20);                  
    buffer.writeUInt16LE(numChannels, 22);        
    buffer.writeUInt32LE(sampleRate, 24);         
    buffer.writeUInt32LE(byteRate, 28);           
    buffer.writeUInt16LE(blockAlign, 32);         
    buffer.writeUInt16LE(bitsPerSample, 34);      
    buffer.write('data', 36);                     
    buffer.writeUInt32LE(dataLength, 40);         

    return buffer;
  }

  /**
   * 标准化错误处理工具
   * @param error 错误对象
   * @param context 错误上下文
   * @param options 处理选项
   * @returns 格式化的用户友好错误消息
   */
  static handleError(error: any, context: string, options: {
    logLevel?: 'error' | 'warn' | 'info';
    includeStack?: boolean;
    customMessage?: string;
    showTechnicalDetails?: boolean;
  } = {}): string {
    const {
      logLevel = 'error',
      includeStack = process.env.NODE_ENV === 'development',
      customMessage,
      showTechnicalDetails = false
    } = options;

    const timestamp = new Date().toISOString();
    const errorMessage = error?.message || '未知错误';
    const errorStack = error?.stack || '';
    const errorCode = error?.code || error?.status || '';

    // 记录详细错误信息到控制台
    const logMessage = `[${timestamp}] [${context}] 错误: ${errorMessage}`;
    if (logLevel === 'error') {
      console.error(logMessage);
    } else if (logLevel === 'warn') {
      console.warn(logMessage);
    } else {
      console.info(logMessage);
    }

    if (includeStack && errorStack) {
      console.error(`[${timestamp}] [${context}] 堆栈: ${errorStack}`);
    }

    if (errorCode) {
      console.error(`[${timestamp}] [${context}] 错误代码: ${errorCode}`);
    }

    // 如果提供了自定义消息，直接使用
    if (customMessage) {
      return `❌ ${context}失败: ${customMessage}`;
    }

    // 根据错误类型提供用户友好的消息
    let userMessage = this.getUserFriendlyMessage(error, errorMessage);

    // 是否显示技术细节
    if (showTechnicalDetails && errorCode) {
      userMessage += ` (错误代码: ${errorCode})`;
    }

    return `❌ ${context}失败: ${userMessage}`;
  }

  /**
   * 获取用户友好的错误消息
   */
  private static getUserFriendlyMessage(error: any, originalMessage: string): string {
    const errorCode = error?.code || error?.status;
    const message = originalMessage.toLowerCase();

    // 文件系统错误
    if (errorCode === 'ENOENT') {
      return '文件不存在或无法访问';
    }
    if (errorCode === 'EACCES') {
      return '权限不足，无法访问文件';
    }
    if (errorCode === 'EMFILE' || errorCode === 'ENFILE') {
      return '系统文件句柄不足，请稍后重试';
    }
    if (errorCode === 'ENOSPC') {
      return '磁盘空间不足';
    }

    // 网络错误
    if (message.includes('timeout') || message.includes('超时')) {
      return '操作超时，请检查网络连接';
    }
    if (message.includes('network') || message.includes('网络') || 
        message.includes('connection') || errorCode === 'ECONNREFUSED') {
      return '网络连接失败，请检查网络设置';
    }
    if (message.includes('dns') || errorCode === 'ENOTFOUND') {
      return 'DNS解析失败，请检查网络连接';
    }

    // API错误
    if (errorCode === 401 || message.includes('unauthorized')) {
      return 'API密钥无效或已过期';
    }
    if (errorCode === 403 || message.includes('forbidden')) {
      return '访问被拒绝，请检查权限设置';
    }
    if (errorCode === 404 || message.includes('not found')) {
      return '请求的资源不存在';
    }
    if (errorCode === 429 || message.includes('rate limit') || message.includes('too many requests')) {
      return '请求过于频繁，请稍后重试';
    }
    if (errorCode === 500 || message.includes('internal server error')) {
      return '服务器内部错误，请稍后重试';
    }
    if (errorCode === 502 || errorCode === 503 || errorCode === 504) {
      return '服务暂时不可用，请稍后重试';
    }

    // Telegram API特定错误
    if (message.includes('flood_wait')) {
      const waitTime = originalMessage.match(/\d+/)?.[0] || '60';
      return `请求过于频繁，需要等待 ${waitTime} 秒后重试`;
    }
    if (message.includes('message_too_long')) {
      return '消息过长，请减少内容长度';
    }
    if (message.includes('chat_not_found')) {
      return '聊天不存在或无法访问';
    }
    if (message.includes('user_not_found')) {
      return '用户不存在或无法访问';
    }

    // AI服务特定错误
    if (message.includes('quota') || message.includes('配额')) {
      return 'API配额已用完，请检查账户余额';
    }
    if (message.includes('model') && message.includes('not found')) {
      return '指定的AI模型不存在或不可用';
    }

    // 默认返回原始消息（但进行适当清理）
    return originalMessage.length > 100 ? 
      originalMessage.substring(0, 100) + '...' : 
      originalMessage;
  }

  /**
   * 处理异步操作的错误重试
   */
  static async withRetry<T>(
    operation: () => Promise<T>,
    context: string,
    maxRetries: number = 3,
    delayMs: number = 1000
  ): Promise<T> {
    let lastError: any;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        
        // 对于某些错误类型，不进行重试
        if (this.shouldNotRetry(error)) {
          throw error;
        }
        
        if (attempt < maxRetries) {
          console.warn(`[${context}] 第 ${attempt} 次尝试失败，${delayMs}ms 后重试: ${(error as any)?.message}`);
          await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
        }
      }
    }
    
    throw lastError;
  }

  /**
   * 判断错误是否不应该重试
   */
  private static shouldNotRetry(error: any): boolean {
    const code = error?.code || error?.status;
    const message = error?.message?.toLowerCase() || '';
    
    // 客户端错误通常不应该重试
    if (code >= 400 && code < 500) {
      return true;
    }
    
    // 特定错误类型不重试
    if (code === 'ENOENT' || code === 'EACCES' || 
        message.includes('unauthorized') || 
        message.includes('forbidden')) {
      return true;
    }
    
    return false;
   }
 }

interface HttpResponse {
  status: number;
  data: any;
  headers: any;
}

interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  data?: any;
  timeout?: number;
}

interface WavConversionOptions {
  numChannels: number;
  sampleRate: number;
  bitsPerSample: number;
}

class HttpClient {

  static cleanResponseText(text: string): string {
    if (!text) return text;
    return text
      .replace(/^\uFEFF/, '')
      .replace(/\uFFFD/g, '')
      .replace(/[\uFFFC\uFFFF\uFFFE]/g, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .replace(/[\uDC00-\uDFFF]/g, '')
      .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, '')
      .normalize('NFKC')
      .normalize('NFKC');
  }

  static async makeRequest(url: string, options: HttpRequestOptions = {}): Promise<HttpResponse> {
    return new Promise((resolve, reject) => {
      try {
        const parsedUrl = new URL(url);
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
          reject(new Error('不支持的协议'));
          return;
        }
      } catch {
        reject(new Error('无效的URL'));
        return;
      }

      const { method = 'GET', headers = {}, data, timeout = 30000 } = options;
      const isHttps = url.startsWith('https:');
      const client = isHttps ? https : http;
      
      const req = client.request(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'TeleBox/1.0',
          ...headers
        },
        timeout
      }, (res: any) => {

        res.setEncoding('utf8');
        let body = '';
        let dataLength = 0;
        const maxResponseSize = 10 * 1024 * 1024;

        res.on('data', (chunk: string) => {
          dataLength += chunk.length;
          if (dataLength > maxResponseSize) {
            req.destroy();
            reject(new Error('响应数据过大'));
            return;
          }
          body += chunk;
        });
        
        res.on('end', () => {
          try {

            const cleanBody = HttpClient.cleanResponseText(body);
            const parsedData = cleanBody ? JSON.parse(cleanBody) : {};
            resolve({
              status: res.statusCode || 0,
              data: parsedData,
              headers: res.headers
            });
          } catch (error) {

            resolve({
              status: res.statusCode || 0,
              data: HttpClient.cleanResponseText(body),
              headers: res.headers
            });
          }
        });
      });

      req.on('error', (error) => {
        reject(new Error(`网络请求失败: ${error.message}`));
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('请求超时'));
      });

      if (data) {
        if (typeof data === 'object') {
          const jsonData = JSON.stringify(data);
          if (jsonData.length > 1024 * 1024) {
            reject(new Error('请求体过大'));
            return;
          }
          req.write(jsonData);
        } else if (typeof data === 'string') {
          if (data.length > 1024 * 1024) {
            reject(new Error('请求体过大'));
            return;
          }
          req.write(data);
        }
      }

      req.end();
    });
  }
}

class TelegraphClient {
  private accessToken: string | null = null;

  async getAccessToken(): Promise<string> {
    if (this.accessToken) return this.accessToken;

    const token = ConfigManager.get(CONFIG_KEYS.AI_TELEGRAPH_TOKEN);
    if (token) {
      this.accessToken = token;
      return token;
    }

    const response = await HttpClient.makeRequest('https://api.telegra.ph/createAccount', {
      method: 'POST',
      data: {
        short_name: 'Telebox-AI'
      }
    });

    if (response.status === 200 && response.data.ok) {
      const accessToken = response.data.result.access_token;
      this.accessToken = accessToken;
      ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_TOKEN, accessToken);
      return accessToken;
    }

    throw new Error('Failed to create Telegraph account');
  }

  async createPage(title: string, htmlContent: string): Promise<{ url: string; path: string }> {
    const token = await this.getAccessToken();
    
    const response = await HttpClient.makeRequest('https://api.telegra.ph/createPage', {
      method: 'POST',
      data: {
        access_token: token,
        title,
        content: [{ tag: 'div', children: [htmlContent] }]
      }
    });

    if (response.status === 200 && response.data.ok) {
      return {
        url: response.data.result.url || '',
        path: response.data.result.path || ''
      };
    }

    throw new Error('Failed to create Telegraph page');
  }

  async editPage(path: string, title: string, htmlContent: string): Promise<boolean> {
    try {
      const token = await this.getAccessToken();
      
      const response = await HttpClient.makeRequest('https://api.telegra.ph/editPage', {
        method: 'POST',
        data: {
          access_token: token,
          path,
          title,
          content: [{ tag: 'div', children: [htmlContent] }]
        }
      });

      return response.status === 200 && response.data.ok;
    } catch {
      return false;
    }
  }
}

class AiClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, baseUrl?: string | null) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl ?? DEFAULT_CONFIG[CONFIG_KEYS.AI_BASE_URL];
  }

  async generateContent(params: {
    model: string;
    contents: any[];
    systemInstruction?: string;
    safetySettings?: any[];
    maxOutputTokens?: number;
    tools?: any[];
  }): Promise<{ text: string; candidates: any[] }> {
    const url = `${this.baseUrl}/v1beta/models/${params.model}:generateContent`;
    
    const headers: Record<string, string> = {
      'x-goog-api-key': this.apiKey
    };

    const requestData: any = {
      contents: params.contents,
      generationConfig: {}
    };

    if (params.systemInstruction) {
      requestData.systemInstruction = { parts: [{ text: params.systemInstruction }] };
    }

    if (params.safetySettings) {
      requestData.safetySettings = params.safetySettings;
    }

    if (params.maxOutputTokens && params.maxOutputTokens > 0) {
      requestData.generationConfig.maxOutputTokens = params.maxOutputTokens;
    }

    if (params.tools) {
      requestData.tools = params.tools;
    }

    const response = await HttpClient.makeRequest(url, {
      method: 'POST',
      headers,
      data: requestData
    });

    if (response.status !== 200 || response.data?.error) {

      
      const errorMessage = response.data?.error?.message || 
                          response.data?.error || 
                          `HTTP错误: ${response.status} Bad Request`;
      // 隐藏可能包含API密钥的敏感信息
      const sanitizedMsg = String(errorMessage).replace(/api_key:[A-Za-z0-9_-]+/g, 'api_key:***');
      throw new Error(sanitizedMsg);
    }

    const rawText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const text = HttpClient.cleanResponseText(rawText);
    return {
      text,
      candidates: response.data?.candidates || []
    };
  }

  async generateImage(params: {
    model: string;
    contents: any[];
  }): Promise<{ text?: string; imageData?: Buffer }> {
    const url = `${this.baseUrl}/v1beta/models/${params.model}:generateContent`;
    
    const headers: Record<string, string> = {
      'x-goog-api-key': this.apiKey
    };

    const requestData = {
      contents: params.contents,
      generationConfig: {
        responseModalities: ['TEXT', 'IMAGE']
      }
    };

    const response = await HttpClient.makeRequest(url, {
      method: 'POST',
      headers,
      data: requestData
    });

    if (response.status !== 200 || response.data?.error) {
      const errorMsg = response.data?.error?.message || JSON.stringify(response.data);
      // 隐藏可能包含API密钥的敏感信息
      const sanitizedMsg = errorMsg.replace(/api_key:[A-Za-z0-9_-]+/g, 'api_key:***');
      throw new Error(`API Error: ${response.status} - ${sanitizedMsg}`);
    }

    const parts = response.data?.candidates?.[0]?.content?.parts || [];
    let text: string | undefined;
    let imageData: Buffer | undefined;

    for (const part of parts) {
      if (part?.text) {
        text = HttpClient.cleanResponseText(part.text);
      } else if (part?.inlineData?.data) {
        imageData = Buffer.from(part.inlineData.data, 'base64');
      }
    }

    return { text, imageData };
  }

  async generateTTS(params: {
    model: string;
    contents: any[];
    voiceName?: string;
  }): Promise<{ audioData?: Buffer[]; audioMimeType?: string }> {

    const url = `${this.baseUrl}/v1beta/models/${params.model}:generateContent`;
    
    const headers: Record<string, string> = {
      'x-goog-api-key': this.apiKey,
      'Content-Type': 'application/json'
    };

    const voiceName = params.voiceName || DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE];
    
    const textContent = params.contents[0]?.parts?.[0]?.text || '';
    if (!textContent.trim()) {
      throw new Error('TTS 需要有效的文本内容');
    }

    const requestData = {
      contents: [{
        role: 'user',
        parts: [{ text: textContent }]
      }],
      generationConfig: {
        responseModalities: ['AUDIO'],
        speechConfig: {
          voiceConfig: {
            prebuiltVoiceConfig: {
              voiceName: voiceName
            }
          }
        }
      }
    };

    const response = await HttpClient.makeRequest(url, {
      method: 'POST',
      headers,
      data: requestData,
      timeout: 60000
    });

    if (response.status !== 200) {
      const errorMsg = response.data?.error?.message || 'Unknown error';
      if (response.status === 429) {
        throw new Error('API配额已用完，请检查您的计费详情');
      }
      const sanitizedMsg = errorMsg.replace(/api_key:[A-Za-z0-9_-]+/g, 'api_key:***');
      throw new Error(`HTTP错误 ${response.status}: ${sanitizedMsg}`);
    }

    if (response.data?.error) {
      const errorMsg = response.data.error.message || JSON.stringify(response.data.error);
      const sanitizedMsg = errorMsg.replace(/api_key:[A-Za-z0-9_-]+/g, 'api_key:***');
      throw new Error(`API错误: ${sanitizedMsg}`);
    }

    const candidate = response.data?.candidates?.[0];
    
    if (candidate) {
      const part = candidate?.content?.parts?.[0];
      if (part?.inlineData?.data) {
        const audioBuffer = Buffer.from(part.inlineData.data, 'base64');
        const audioMimeType = part.inlineData.mimeType || 'audio/wav';
        return { audioData: [audioBuffer], audioMimeType };
      }
    }

    if (response.data?.candidates?.[0]?.finishReason === 'OTHER') {
      throw new Error('TTS服务暂时不可用，请稍后重试');
    }
    
    throw new Error('TTS服务返回了无效的响应格式');
  }

  async listModels(): Promise<string[]> {
    const url = `${this.baseUrl}/v1beta/models`;
    
    const headers: Record<string, string> = {
      'x-goog-api-key': this.apiKey
    };

    const response = await HttpClient.makeRequest(url, {
      method: 'GET',
      headers
    });

    if (response.status !== 200 || response.data?.error) {
      const errorMsg = response.data?.error?.message || JSON.stringify(response.data);
      const sanitizedMsg = errorMsg.replace(/api_key:[A-Za-z0-9_-]+/g, 'api_key:***');
      throw new Error(`API Error: ${response.status} - ${sanitizedMsg}`);
    }

    return (response.data?.models || []).map((model: any) => 
      model.name?.replace('models/', '') || model.name
    );
  }
}

const CONFIG_MAP = {
  'apikey': { key: CONFIG_KEYS.AI_API_KEY, name: 'API Key' },
  'baseurl': { key: CONFIG_KEYS.AI_BASE_URL, name: '基础 URL' },
  'maxtokens': { key: CONFIG_KEYS.AI_MAX_TOKENS, name: '最大Token数' },
  'chatmodel': { key: CONFIG_KEYS.AI_CHAT_MODEL, name: '聊天模型' },
  'searchmodel': { key: CONFIG_KEYS.AI_SEARCH_MODEL, name: '搜索模型' },
  'imagemodel': { key: CONFIG_KEYS.AI_IMAGE_MODEL, name: '图片模型' },
  'ttsmodel': { key: CONFIG_KEYS.AI_TTS_MODEL, name: 'TTS模型' },
  'ttsvoice': { key: CONFIG_KEYS.AI_TTS_VOICE, name: 'TTS语音' },
  'context': { key: CONFIG_KEYS.AI_CONTEXT_ENABLED, name: '上下文' },
  'telegraph': { key: CONFIG_KEYS.AI_TELEGRAPH_ENABLED, name: 'Telegraph' },
  'collapse': { key: CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED, name: '折叠引用' }
};

const MODEL_TYPE_MAP = {
  'chat': { key: CONFIG_KEYS.AI_CHAT_MODEL, name: '聊天' },
  'search': { key: CONFIG_KEYS.AI_SEARCH_MODEL, name: '搜索' },
  'image': { key: CONFIG_KEYS.AI_IMAGE_MODEL, name: '图片' },
  'tts': { key: CONFIG_KEYS.AI_TTS_MODEL, name: 'TTS' }
};

const PROMPT_TYPE_MAP = {
  'chat': { key: CONFIG_KEYS.AI_CHAT_ACTIVE_PROMPT, name: '聊天' },
  'search': { key: CONFIG_KEYS.AI_SEARCH_ACTIVE_PROMPT, name: '搜索' },
  'tts': { key: CONFIG_KEYS.AI_TTS_ACTIVE_PROMPT, name: 'TTS' }
};

// 多服务商解析与第三方兼容辅助
function getJsonConfig<T = any>(key: string, fallbackJson = "{}"): T {
  try {
    return JSON.parse(getConfig(key, fallbackJson)) as T;
  } catch {
    return JSON.parse(fallbackJson) as T;
  }
}

function getThirdPartyCompat(): string {
  return (getConfig(CONFIG_KEYS.AI_THIRD_PARTY_COMPAT, "") || "").toLowerCase();
}

// 根据模型名称推断服务商
function getProviderFromModel(modelName: string): 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty' | null {
  if (!modelName) return null;
  
  const model = modelName.toLowerCase();
  
  if (model.includes('gemini')) return 'gemini';
  if (model.includes('gpt') || model.includes('dall-e') || model.includes('tts-1') || model.includes('whisper')) return 'openai';
  if (model.includes('claude')) return 'claude';
  if (model.includes('deepseek')) return 'deepseek';
  if (model.includes('grok')) return 'grok';
  
  // 如果无法从模型名推断，检查是否是第三方设置的模型
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, '{}');
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, '{}');
  
  // 如果配置了第三方服务商且模型不属于其他官方服务商，则认为是第三方
  if (baseUrls?.thirdparty && (keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY))) {
    return 'thirdparty';
  }
  
  return null;
}

// 智能服务商选择 - 根据功能需求和质量评分选择最佳服务商
function getActiveProviderFor(feature: 'chat' | 'search' | 'image' | 'tts'): 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty' {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const compat = getThirdPartyCompat();
  
  // 首先检查用户是否通过ai select设置了活跃服务商
  const activeProvider = getConfig(CONFIG_KEYS.AI_ACTIVE_PROVIDER, "") as 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty';
  if (activeProvider && checkProviderApiKey(activeProvider) && isFeatureSupported(activeProvider, feature)) {
    return activeProvider;
  }
  
  // 其次检查用户是否通过模型设置了首选服务商
  const models = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, '{}');
  const currentModel = models[feature];
  if (currentModel) {
    // 根据当前模型推断服务商
    const preferredProvider = getProviderFromModel(currentModel);
    if (preferredProvider && checkProviderApiKey(preferredProvider) && isFeatureSupported(preferredProvider, feature)) {
      return preferredProvider;
    }
  }
  
  // 定义各服务商在不同功能上的质量评分 (1-10)
  const providerQualityScores: Record<string, Record<string, number>> = {
    'gemini': { chat: 9, search: 10, image: 8, tts: 7 },
    'openai': { chat: 10, search: 6, image: 9, tts: 9 },
    'claude': { chat: 10, search: 7, image: 8, tts: 5 },
    'deepseek': { chat: 8, search: 6, image: 6, tts: 5 },
    'grok': { chat: 7, search: 6, image: 5, tts: 4 },
    'thirdparty': { chat: 8, search: 7, image: 7, tts: 7 }
  };
  
  // 收集可用的服务商
  const availableProviders: Array<{provider: string, score: number}> = [];
  
  // 检查各官方服务商
  const providers = ['gemini', 'openai', 'claude', 'deepseek', 'grok'] as const;
  for (const provider of providers) {
    if (keys[provider] && isFeatureSupported(provider, feature)) {
      const score = providerQualityScores[provider]?.[feature] || 5;
      availableProviders.push({ provider, score });
    }
  }
  
  // 检查第三方服务商
  if (baseUrls?.thirdparty && (keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY))) {
    const effectiveCompat = compat || 'openai';
    if (isFeatureSupported('thirdparty', feature)) {
      const score = providerQualityScores['thirdparty']?.[feature] || 6;
      availableProviders.push({ provider: 'thirdparty', score });
    }
  }
  
  // 按质量评分排序，选择最佳服务商
  if (availableProviders.length > 0) {
    availableProviders.sort((a, b) => b.score - a.score);
    return availableProviders[0].provider as 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty';
  }
  
  // 向后兼容：老的 AI_API_KEY 即走 gemini
  const legacyKey = getConfig(CONFIG_KEYS.AI_API_KEY, "");
  if (legacyKey) {
    // 检查gemini是否支持该功能
    if (isFeatureSupported('gemini', feature)) {
      return 'gemini';
    }
  }
  
  // 没有可用的服务商，抛出错误而不是默认返回gemini
  throw new Error('未设置 API 密钥。请使用 ai apikey <provider> <密钥> 命令设置，如：ai apikey gemini <密钥>');
}

// 智能模型匹配算法 - 增强版
function classifyModelByName(modelName: string): ('chat' | 'search' | 'image' | 'tts')[] {
  const name = modelName.toLowerCase();
  const features: ('chat' | 'search' | 'image' | 'tts')[] = [];
  
  // 图片生成模型识别 - 扩展模式匹配
  const imagePatterns = [
    'dall-e', 'dalle', 'image', 'vision', 'midjourney', 'stable-diffusion',
    'flux', 'playground', 'sd-', 'sdxl', 'firefly', 'imagen', 'parti',
    'draw', 'paint', 'art', 'generate', 'create', 'visual'
  ];
  if (imagePatterns.some(pattern => name.includes(pattern))) {
    features.push('image');
  }
  
  // TTS模型识别 - 扩展语音模型
  const ttsPatterns = [
    'tts', 'speech', 'voice', 'audio', 'whisper', 'eleven', 'bark',
    'tortoise', 'coqui', 'espeak', 'festival', 'mary', 'speak', 'say'
  ];
  if (ttsPatterns.some(pattern => name.includes(pattern))) {
    features.push('tts');
  }
  
  // 搜索专用模型识别 - 增强搜索检测
  const searchPatterns = [
    'search', 'web', 'browse', 'internet', 'online', 'perplexity',
    'tavily', 'serp', 'google', 'bing', 'duckduckgo'
  ];
  if (searchPatterns.some(pattern => name.includes(pattern))) {
    features.push('search');
  }
  
  // 聊天模型识别 - 通用对话模型
  const chatPatterns = [
    'gpt', 'claude', 'gemini', 'llama', 'mistral', 'deepseek', 'grok',
    'chat', 'instruct', 'turbo', 'davinci', 'curie', 'babbage', 'ada',
    'text-', 'conversation', 'dialog', 'assistant'
  ];
  
  // 如果没有匹配到专门功能，且包含聊天关键词，则认为是聊天模型
  if (features.length === 0 || chatPatterns.some(pattern => name.includes(pattern))) {
    features.push('chat');
  }
  
  // 多模态模型可能支持多种功能
  const multimodalPatterns = ['gpt-4', 'claude-3', 'gemini-pro', 'vision'];
  if (multimodalPatterns.some(pattern => name.includes(pattern))) {
    if (!features.includes('chat')) features.push('chat');
    if (!features.includes('search')) features.push('search');
  }
  
  return features;
}

// 获取第三方API可用模型列表
async function fetchThirdPartyModels(baseUrl: string, apiKey: string, compatMode: string): Promise<string[]> {
  try {
    let modelsUrl = '';
    const headers: Record<string, string> = {};
    
    // 根据兼容模式设置请求参数
    switch (compatMode) {
      case 'openai':
        modelsUrl = `${baseUrl}/v1/models`;
        headers['Authorization'] = `Bearer ${apiKey}`;
        break;
      case 'gemini':
        modelsUrl = `${baseUrl}/v1beta/models?key=${apiKey}`;
        break;
      case 'claude':
        modelsUrl = `${baseUrl}/v1/models`;
        headers['x-api-key'] = apiKey;
        headers['anthropic-version'] = '2023-06-01';
        break;
      case 'deepseek':
      case 'grok':
        modelsUrl = `${baseUrl}/v1/models`;
        headers['Authorization'] = `Bearer ${apiKey}`;
        break;
      default:
        // 默认尝试OpenAI格式
        modelsUrl = `${baseUrl}/v1/models`;
        headers['Authorization'] = `Bearer ${apiKey}`;
    }
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch(modelsUrl, {
      method: 'GET',
      headers,
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unable to read error response');
      const debugInfo = [
        `Status: ${response.status}`,
        `URL: ${Utils.censorUrl(modelsUrl)}`,
        `API Key: ${apiKey ? 'Set' : 'Not set'}`,
        `Compat Mode: ${compatMode}`,
        `Error: ${errorText}`
      ];
      console.warn(`Failed to fetch models - ${debugInfo.join(', ')}`);
      return [];
    }
    
    const data = await response.json();
    
    // 解析不同API格式的响应
    let models: string[] = [];
    if (compatMode === 'gemini' && data.models) {
      models = data.models.map((m: any) => m.name?.replace('models/', '') || m.id).filter(Boolean);
    } else if (data.data && Array.isArray(data.data)) {
      models = data.data.map((m: any) => m.id || m.name).filter(Boolean);
    } else if (data.models && Array.isArray(data.models)) {
      models = data.models.map((m: any) => m.id || m.name).filter(Boolean);
    }
    
    return models;
  } catch (error) {
    console.warn('Error fetching third-party models:', error);
    return [];
  }
}

// 自动匹配第三方模型到功能
function autoAssignThirdPartyModels(models: string[]): Record<string, string> {
  const assignments: Record<string, string> = {};
  const candidates = {
    chat: [] as string[],
    search: [] as string[],
    image: [] as string[],
    tts: [] as string[]
  };
  
  // 分类所有模型
  for (const model of models) {
    const features = classifyModelByName(model);
    for (const feature of features) {
      candidates[feature].push(model);
    }
  }
  
  // 为每个功能选择最佳模型
  const featurePriority = {
    chat: ['gpt-4', 'claude-3', 'gemini', 'deepseek', 'grok', 'llama'],
    search: ['gpt-4', 'claude-3', 'gemini', 'deepseek', 'perplexity'],
    image: ['dall-e-3', 'dall-e-2', 'midjourney', 'stable-diffusion', 'flux'],
    tts: ['tts-1', 'eleven', 'speech', 'voice']
  };
  
  for (const [feature, modelList] of Object.entries(candidates)) {
    if (modelList.length > 0) {
      // 根据优先级选择最佳模型
      const priority = featurePriority[feature as keyof typeof featurePriority];
      let bestModel = modelList[0];
      
      for (const priorityPattern of priority) {
        const match = modelList.find(m => m.toLowerCase().includes(priorityPattern));
        if (match) {
          bestModel = match;
          break;
        }
      }
      
      assignments[feature] = bestModel;
    }
  }
  
  return assignments;
}

// 根据TTS模型自动选择音色
// 根据provider获取默认TTS语音
function getDefaultVoiceForProvider(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty'): string {
  const providerVoiceMap: Record<string, string> = {
    'gemini': 'Kore',
    'openai': 'alloy',
    'claude': 'alloy',
    'deepseek': 'alloy', 
    'grok': 'alloy',
    'thirdparty': 'alloy' // 第三方默认使用OpenAI兼容的alloy
  };
  
  return providerVoiceMap[provider] || 'Kore';
}

// 获取当前TTS功能应该使用的默认语音
function getDefaultVoiceForCurrentTTS(): string {
  const ttsProvider = getActiveProviderFor('tts');
  return getDefaultVoiceForProvider(ttsProvider);
}

// 自动更新TTS语音以匹配当前provider
function autoUpdateTTSVoice(): void {
  const currentVoice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
  const defaultVoice = getDefaultVoiceForCurrentTTS();
  
  // 如果当前语音是默认的Kore，或者为空，则自动更新为provider对应的默认语音
  if (!currentVoice || currentVoice === 'Kore' || currentVoice === DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]) {
    ConfigManager.set(CONFIG_KEYS.AI_TTS_VOICE, defaultVoice);
  }
}

function getDefaultVoiceForTTSModel(modelName: string): string {
  const name = modelName.toLowerCase();
  
  // OpenAI TTS模型音色映射
  if (name.includes('tts-1')) {
    return 'Kore'; // 默认音色
  }
  
  // ElevenLabs音色映射
  if (name.includes('eleven')) {
    return 'Achernar';
  }
  
  // 其他TTS模型的默认音色
  if (name.includes('speech') || name.includes('voice')) {
    return 'Algenib';
  }
  
  // 默认音色
  return 'Kore';
}

// 执行自动模型匹配
async function performAutoModelAssignment(baseUrl: string, forceUpdate: boolean = false): Promise<string> {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, '{}');
  const apiKey = keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY);
  const compatMode = getConfig(CONFIG_KEYS.AI_THIRD_PARTY_COMPAT) || 'openai';
  
  if (!apiKey) {
    return '⚠️ 未设置第三方API密钥，无法自动匹配模型';
  }
  
  const models = await fetchThirdPartyModels(baseUrl, apiKey, compatMode);
  
  if (models.length === 0) {
    return '⚠️ 无法获取第三方API模型列表，请检查配置';
  }
  
  const assignments = autoAssignThirdPartyModels(models);
  
  if (Object.keys(assignments).length === 0) {
    return '⚠️ 未找到可匹配的模型';
  }
  
  // 保存自动分配的模型
  const currentModels = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, '{}');
  let updated = false;
  const updatedFeatures: string[] = [];
  
  for (const [feature, model] of Object.entries(assignments)) {
    // 根据forceUpdate决定是否更新已有设置
    if (forceUpdate || !currentModels[feature] || currentModels[feature].trim() === '') {
      currentModels[feature] = model;
      updated = true;
      updatedFeatures.push(feature);
      
      // 如果是TTS模型，同时设置对应的音色
      if (feature === 'tts') {
        const currentVoice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
        if (forceUpdate || !currentVoice || currentVoice === DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]) {
          // 使用基于provider的语音选择，而不是基于模型名称
          const defaultVoice = getDefaultVoiceForCurrentTTS();
          ConfigManager.set(CONFIG_KEYS.AI_TTS_VOICE, defaultVoice);
        }
      }
    }
  }
  
  if (updated) {
    ConfigManager.set(CONFIG_KEYS.AI_MODELS, JSON.stringify(currentModels));
    
    const assignmentText = updatedFeatures
      .map(feature => {
        const featureNames = { chat: '聊天', search: '搜索', image: '图片', tts: '语音' };
        let text = `${featureNames[feature as keyof typeof featureNames]}: ${assignments[feature]}`;
        
        // 如果是TTS模型，显示对应的音色
        if (feature === 'tts') {
          const voice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
          text += ` (音色: ${voice})`;
        }
        
        return text;
      })
      .join('\n');
    
    const prefix = forceUpdate ? '🔄 已重新匹配模型:' : '🤖 已自动匹配模型:';
    return `${prefix}\n${assignmentText}`;
  } else {
    const existingText = Object.entries(assignments)
      .map(([feature, model]) => {
        const featureNames = { chat: '聊天', search: '搜索', image: '图片', tts: '语音' };
        const current = currentModels[feature] || '未设置';
        return `${featureNames[feature as keyof typeof featureNames]}: ${current} (建议: ${model})`;
      })
      .join('\n');
    
    return `✅ 所有功能已有模型设置:\n${existingText}\n\n💡 使用 \`ai model auto\` 可强制重新匹配`;
  }
}

// 官方API的默认模型配置
const OFFICIAL_API_MODELS = {
  gemini: {
    chat: 'gemini-2.0-flash',
    search: 'gemini-2.0-flash', 
    image: 'gemini-2.0-flash-preview-image-generation',
    tts: 'gemini-2.5-flash-preview-tts'
  },
  openai: {
    chat: 'gpt-4o',
    search: 'gpt-4o',
    image: 'dall-e-3',
    tts: 'tts-1'
  },
  claude: {
    chat: 'claude-3-5-sonnet-20241022',
    search: 'claude-3-5-sonnet-20241022',
    image: '', // Claude不支持图片生成
    tts: '' // Claude不支持TTS
  },
  deepseek: {
    chat: 'deepseek-chat',
    search: 'deepseek-chat',
    image: '', // DeepSeek不支持图片生成
    tts: '' // DeepSeek不支持TTS
  },
  grok: {
    chat: 'grok-beta',
    search: 'grok-beta',
    image: '', // Grok不支持图片生成
    tts: '' // Grok不支持TTS
  }
};

// 官方API的默认语音配置
const OFFICIAL_API_VOICES = {
  gemini: 'Kore',
  openai: 'alloy',
  claude: '',
  deepseek: '',
  grok: ''
};

/**
 * 为官方API执行自动模型配置
 * @param provider 服务商名称
 * @param forceUpdate 是否强制更新已有配置
 * @returns 配置结果消息
 */
async function performOfficialAutoModelAssignment(
  provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok',
  forceUpdate: boolean = false
): Promise<string> {
  const providerModels = OFFICIAL_API_MODELS[provider];
  if (!providerModels) {
    return `⚠️ 不支持的服务商: ${provider}`;
  }

  // 获取当前模型配置
  const currentModels = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, '{}');
  let updated = false;
  const updatedFeatures: string[] = [];

  // 为每个功能设置默认模型
  for (const [feature, model] of Object.entries(providerModels)) {
    if (model && (forceUpdate || !currentModels[feature] || currentModels[feature].trim() === '')) {
      currentModels[feature] = model;
      updated = true;
      updatedFeatures.push(feature);
    }
  }

  // 设置TTS语音
  const defaultVoice = OFFICIAL_API_VOICES[provider];
  if (defaultVoice) {
    const currentVoice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
    if (forceUpdate || !currentVoice || currentVoice === 'Kore' || currentVoice === 'alloy') {
      ConfigManager.set(CONFIG_KEYS.AI_TTS_VOICE, defaultVoice);
      if (updatedFeatures.includes('tts')) {
        // TTS模型已更新，语音也需要更新
      } else if (providerModels.tts) {
        updatedFeatures.push('voice');
        updated = true;
      }
    }
  }

  if (updated) {
    ConfigManager.set(CONFIG_KEYS.AI_MODELS, JSON.stringify(currentModels));

    const featureNames = { 
      chat: '聊天', 
      search: '搜索', 
      image: '图片', 
      tts: '语音',
      voice: '音色'
    };

    const assignmentText = updatedFeatures
      .map(feature => {
        if (feature === 'voice') {
          const voice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
          return `${featureNames[feature]}: ${voice}`;
        } else {
          let text = `${featureNames[feature as keyof typeof featureNames]}: ${providerModels[feature as keyof typeof providerModels]}`;
          
          // 如果是TTS模型，显示对应的音色
          if (feature === 'tts' && defaultVoice) {
            text += ` (音色: ${defaultVoice})`;
          }
          
          return text;
        }
      })
      .join('\n');

    const prefix = forceUpdate ? '🔄 已重新配置模型:' : '🤖 已自动配置模型:';
    return `${prefix}\n${assignmentText}`;
  } else {
    // 显示当前所有功能的配置状态
    const statusLines: string[] = [];
    const featureNames = { chat: '聊天', search: '搜索', image: '图片', tts: '语音' };
    
    for (const [feature, model] of Object.entries(providerModels)) {
      if (model) { // 只显示支持的功能
        const current = currentModels[feature] || '未设置';
        const featureName = featureNames[feature as keyof typeof featureNames];
        statusLines.push(`${featureName}: ${current}`);
        
        // 如果是TTS功能，同时显示音色设置
        if (feature === 'tts' && defaultVoice) {
          const currentVoice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
          statusLines.push(`音色: ${currentVoice}`);
        }
      }
    }

    return `✅ ${provider.toUpperCase()} 功能配置状态:\n${statusLines.join('\n')}\n\n💡 使用 \`ai model auto\` 可强制重新配置`;
  }
}

function getActiveModelFor(feature: 'chat' | 'search' | 'image' | 'tts'): string {
  // 获取当前选择的提供商
  let provider: string;
  try {
    provider = getActiveProviderFor(feature);
  } catch {
    provider = 'gemini'; // 默认使用gemini
  }
  
  const models = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, "{}");
  if (models && models[feature]) {
    const configuredModel = models[feature];
    // 如果选择的是Gemini提供商，但配置的模型不是Gemini兼容的，使用默认Gemini模型
     if (provider === 'gemini' && configuredModel && !configuredModel.startsWith('gemini-')) {
       const defaultKey = `ai_${feature}_model`;
       return DEFAULT_CONFIG[defaultKey] || getConfig(defaultKey);
     }
    return configuredModel;
  }
  
  // 兼容旧键
  const legacyModel = (() => {
    switch (feature) {
      case 'chat': return getConfig(CONFIG_KEYS.AI_CHAT_MODEL);
      case 'search': return getConfig(CONFIG_KEYS.AI_SEARCH_MODEL);
      case 'image': return getConfig(CONFIG_KEYS.AI_IMAGE_MODEL);
      case 'tts': return getConfig(CONFIG_KEYS.AI_TTS_MODEL);
    }
  })();
  
  // 如果选择的是Gemini提供商，但旧配置的模型不是Gemini兼容的，使用默认Gemini模型
   if (provider === 'gemini' && legacyModel && !legacyModel.startsWith('gemini-')) {
     const defaultKey = `ai_${feature}_model`;
     return DEFAULT_CONFIG[defaultKey] || legacyModel;
   }
  
  return legacyModel;
}

// 适配层接口与能力矩阵
type IProviderAdapter = {
  chat(params: {
    model: string;
    contents: any[];
    systemInstruction?: string;
    maxOutputTokens?: number;
    tools?: any[];
  }): Promise<{ text: string }>;
  image(params: {
    model: string;
    contents: any[];
  }): Promise<{ text?: string; imageData?: Buffer }>;
  tts(params: {
    model: string;
    contents: any[];
    voiceName?: string;
  }): Promise<{ audioData?: Buffer[]; audioMimeType?: string }>;
  search?(params: {
    model: string;
    contents: any[];
    systemInstruction?: string;
    maxOutputTokens?: number;
  }): Promise<{ text: string }>;
};

function getProviderCaps() {
  const compat = getThirdPartyCompat();
  // 如果没有设置兼容模式，默认使用 openai 兼容
  const effectiveCompat = compat || 'openai';
  
  // 支持的兼容模式列表
  const supportedCompats = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
  const isValidCompat = supportedCompats.includes(effectiveCompat);
  
  // 根据兼容模式确定第三方API的功能支持
  let thirdpartyFeatures = { chat: false, search: false, image: false, tts: false };
  if (isValidCompat) {
    switch (effectiveCompat) {
      case 'gemini':
        thirdpartyFeatures = { chat: true, search: true, image: true, tts: true };
        break;
      case 'openai':
        thirdpartyFeatures = { chat: true, search: true, image: true, tts: true };
        break;
      case 'claude':
        thirdpartyFeatures = { chat: true, search: true, image: true, tts: false };
        break;
      case 'deepseek':
        thirdpartyFeatures = { chat: true, search: true, image: false, tts: false };
        break;
      case 'grok':
        thirdpartyFeatures = { chat: true, search: true, image: false, tts: false };
        break;
    }
  }
  
  return {
    gemini: { chat: true, search: true, image: true, tts: true },
    openai: { chat: true, search: false, image: true, tts: true },
    claude: { chat: true, search: false, image: true, tts: false },
    deepseek: { chat: true, search: false, image: false, tts: false },
    grok: { chat: true, search: false, image: false, tts: false },
    thirdparty: thirdpartyFeatures,
  } as Record<'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty', { chat: boolean; search: boolean; image: boolean; tts: boolean }>;
}

function isFeatureSupported(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty', feature: 'chat' | 'search' | 'image' | 'tts'): boolean {
  const caps = getProviderCaps();
  return !!caps[provider]?.[feature];
}

// 获取支持指定功能的所有可用服务商，按优先级排序
function getAvailableProvidersForFeature(feature: 'chat' | 'search' | 'image' | 'tts'): ('gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty')[] {
  const allProviders: ('gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty')[] = 
    ['gemini', 'openai', 'claude', 'deepseek', 'grok', 'thirdparty'];
  
  const availableProviders: ('gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty')[] = [];
  
  // 首先尝试当前活跃的服务商
  try {
    const activeProvider = getActiveProviderFor(feature);
    if (isFeatureSupported(activeProvider, feature)) {
      availableProviders.push(activeProvider);
    }
  } catch (error) {
    // 如果获取活跃服务商失败，继续检查其他服务商
  }
  
  // 然后添加其他支持该功能且有API密钥的服务商
  for (const provider of allProviders) {
    if (availableProviders.includes(provider)) continue; // 跳过已添加的
    
    if (isFeatureSupported(provider, feature)) {
      // 检查是否有API密钥
      try {
        const hasApiKey = checkProviderApiKey(provider);
        if (hasApiKey) {
          availableProviders.push(provider);
        }
      } catch (error) {
        // 如果检查API密钥失败，跳过该服务商
        continue;
      }
    }
  }
  
  return availableProviders;
}

// 检查服务商是否有有效的API密钥
function checkProviderApiKey(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty'): boolean {
  const keys = JSON.parse(getConfig(CONFIG_KEYS.AI_KEYS, "{}"));
  
  // 对于第三方服务商，还需要检查向后兼容的AI_API_KEY
  if (provider === 'thirdparty') {
    return !!(keys[provider] || getConfig(CONFIG_KEYS.AI_API_KEY));
  }
  
  return !!keys[provider];
}

// 动态功能检测 - 实时检测服务商功能可用性
function checkProviderAvailability(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty'): {
  available: boolean;
  features: ('chat' | 'search' | 'image' | 'tts')[];
  reason?: string;
} {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  
  // 检查第三方服务商
  if (provider === 'thirdparty') {
    const hasBaseUrl = !!baseUrls?.thirdparty;
    const hasApiKey = !!(keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY));
    
    if (!hasBaseUrl) {
      return { available: false, features: [], reason: '未设置第三方API基础URL' };
    }
    if (!hasApiKey) {
      return { available: false, features: [], reason: '未设置第三方API密钥' };
    }
    
    const compat = getThirdPartyCompat() || 'openai';
    const caps = getProviderCaps().thirdparty;
    const availableFeatures: ('chat' | 'search' | 'image' | 'tts')[] = [];
    
    (['chat', 'search', 'image', 'tts'] as const).forEach(feature => {
      if (caps[feature]) availableFeatures.push(feature);
    });
    
    return {
      available: true,
      features: availableFeatures,
      reason: `兼容模式: ${compat}`
    };
  }
  
  // 检查官方服务商
  const hasApiKey = !!keys[provider];
  if (!hasApiKey) {
    return { available: false, features: [], reason: `未设置${provider.toUpperCase()}API密钥` };
  }
  
  const caps = getProviderCaps()[provider];
  const availableFeatures: ('chat' | 'search' | 'image' | 'tts')[] = [];
  
  (['chat', 'search', 'image', 'tts'] as const).forEach(feature => {
    if (caps[feature]) availableFeatures.push(feature);
  });
  
  return {
    available: true,
    features: availableFeatures
  };
}

// 获取所有可用服务商的状态报告
function getProvidersStatusReport(): string {
  const providers = ['gemini', 'openai', 'claude', 'deepseek', 'grok', 'thirdparty'] as const;
  const statusLines: string[] = [];
  
  statusLines.push('<b>🔍 服务商状态检测</b>\n');
  
  providers.forEach(provider => {
    const status = checkProviderAvailability(provider);
    const providerName = provider === 'thirdparty' ? '第三方API' : provider.toUpperCase();
    
    if (status.available) {
      const featureIcons = {
        chat: '💬',
        search: '🔍', 
        image: '🖼️',
        tts: '🔊'
      };
      
      const featureList = status.features.map(f => featureIcons[f]).join(' ');
      statusLines.push(`✅ <b>${providerName}</b>: ${featureList}`);
      
      if (status.reason) {
        statusLines.push(`   └ ${status.reason}`);
      }
    } else {
      statusLines.push(`❌ <b>${providerName}</b>: ${status.reason}`);
    }
  });
  
  return statusLines.join('\n');
}

// 通用辅助函数：提取文本内容
function extractTextFromContents(contents: any[], fallbackText?: string): string {
  const text = contents?.map((content: any) => 
    content.parts?.map((part: any) => part.text || '').join('') || ''
  ).join('') || fallbackText || '';
  
  if (!text.trim()) {
    throw new Error('❌文本内容为空，无法生成语音');
  }
  
  return text;
}

// 通用辅助函数：检查功能支持
function checkFeatureSupport(provider: string, feature: string, caps: any): void {
  if (!caps[feature]) {
    const providerName = provider === 'thirdparty' ? '当前兼容模式' : provider.toUpperCase();
    const featureNames: { [key: string]: string } = {
      chat: '聊天功能',
      image: '图片生成功能', 
      tts: '语音合成功能',
      search: '搜索功能'
    };
    throw new Error(`❌${providerName}不支持${featureNames[feature] || feature}`);
  }
}

// 通用辅助函数：创建标准适配器
function createStandardAdapter(
  provider: 'openai' | 'claude' | 'deepseek' | 'grok',
  caps: any
): IProviderAdapter {
  return {
    async chat(params) {
      checkFeatureSupport(provider, 'chat', caps);
      return await chatViaProvider(provider, {
        model: params.model,
        contents: params.contents,
        systemInstruction: params.systemInstruction,
        maxOutputTokens: params.maxOutputTokens,
      });
    },
    async image(params) {
      checkFeatureSupport(provider, 'image', caps);
      const result = await imageViaProvider(provider, {
        model: params.model,
        contents: params.contents
      });
      return { text: result.imageUrl };
    },
    async tts(params) {
      checkFeatureSupport(provider, 'tts', caps);
      const text = extractTextFromContents(params.contents, (params as any).text);
      
      const result = await ttsViaProvider(provider, {
        model: params.model,
        text: text,
        voiceName: (params as any).voiceName
      });
      return { 
        audioData: result.audioData, 
        audioMimeType: result.audioMimeType 
      };
    },
    async search(params) {
      checkFeatureSupport(provider, 'search', caps);
      return await searchViaProvider(provider, {
        model: params.model,
        contents: params.contents,
        systemInstruction: params.systemInstruction,
        maxOutputTokens: params.maxOutputTokens,
      });
    }
  };
}

function getAdapter(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty'): IProviderAdapter {
  if (provider === 'thirdparty') {
    const compat = getThirdPartyCompat();
    const effectiveCompat = compat || 'openai';
    const caps = getProviderCaps().thirdparty;
    
    return {
      async chat(params) {
        checkFeatureSupport('thirdparty', 'chat', caps);
        return await chatViaThirdParty({
          model: params.model,
          contents: params.contents,
          systemInstruction: params.systemInstruction,
          maxOutputTokens: params.maxOutputTokens,
          compat: effectiveCompat
        });
      },
      async image(params) {
        checkFeatureSupport('thirdparty', 'image', caps);
        const result = await imageViaThirdParty({
          model: params.model,
          contents: params.contents,
          compat: effectiveCompat
        });
        return { text: result.imageUrl };
      },
      async tts(params) {
        checkFeatureSupport('thirdparty', 'tts', caps);
        const text = extractTextFromContents(params.contents, (params as any).text);
        
        const result = await ttsViaThirdParty({
           model: params.model,
           text: text,
           compat: effectiveCompat,
           voiceName: (params as any).voiceName
         });
        return { 
          audioData: result.audioData, 
          audioMimeType: result.audioMimeType 
        };
      },
      async search(params) {
        checkFeatureSupport('thirdparty', 'search', caps);
        return await searchViaThirdParty({
          model: params.model,
          contents: params.contents,
          systemInstruction: params.systemInstruction,
          maxOutputTokens: params.maxOutputTokens,
          compat: effectiveCompat
        });
      }
    };
  }
  
  // 使用通用适配器创建标准服务商适配
  if (provider === 'openai') {
    return createStandardAdapter('openai', getProviderCaps().openai);
  }
  
  if (provider === 'claude') {
    return createStandardAdapter('claude', getProviderCaps().claude);
  }
  
  if (provider === 'deepseek') {
    return createStandardAdapter('deepseek', getProviderCaps().deepseek);
  }
  
  if (provider === 'grok') {
    return createStandardAdapter('grok', getProviderCaps().grok);
  }
  
  // 默认 Gemini 适配
  return {
    async chat(params) {
      const client = await getAiClient();
      return await client.generateContent({
        model: params.model,
        contents: params.contents,
        systemInstruction: params.systemInstruction,
        safetySettings: createSafetySettings(),
        maxOutputTokens: params.maxOutputTokens,
        tools: params.tools
      });
    },
    async image(params) {
      const client = await getAiClient();
      return await client.generateImage({
        model: params.model,
        contents: params.contents
      });
    },
    async tts(params) {
      const client = await getAiClient();
      return await client.generateTTS({
        model: params.model,
        contents: params.contents,
        voiceName: params.voiceName
      });
    },
    async search(params) {
       const client = await getAiClient();
       return await client.generateContent({
         model: params.model,
         contents: params.contents,
         systemInstruction: params.systemInstruction,
         safetySettings: createSafetySettings(),
         maxOutputTokens: params.maxOutputTokens,
         tools: (params as any).tools
       });
     }
  };
}

async function chatViaThirdParty(params: {
  model: string;
  contents: any[]; // [{ role: 'user'|'model', parts: [{text}] }]
  systemInstruction?: string;
  maxOutputTokens?: number;
  compat: string;
}): Promise<{ text: string }> {
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const effectiveCompat = params.compat;
  const supportedCompats = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
  if (!supportedCompats.includes(effectiveCompat)) {
    throw new Error(`❌不支持的兼容模式: ${effectiveCompat}`);
  }

  const apiKey = keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY);
  if (!apiKey) {
    throw new Error('未设置 API 密钥。请使用 ai apikey <provider> <密钥> 命令设置，如：ai apikey thirdparty <密钥>');
  }
  const baseUrl = (baseUrls?.thirdparty || getConfig(CONFIG_KEYS.AI_BASE_URL) || '').replace(/\/$/, '');
  const url = `${baseUrl}/v1/chat/completions`;

  const messages: any[] = [];
  if (params.systemInstruction) {
    messages.push({ role: 'system', content: params.systemInstruction });
  }
  for (const item of params.contents || []) {
    let role = item.role === 'model' ? 'assistant' : (item.role || 'user');
    const text = (item.parts || []).map((p: any) => p?.text || '').join('\n');
    if (text && role) messages.push({ role, content: text });
  }

  const body: any = {
    model: params.model,
    messages,
    stream: false
  };
  if (params.maxOutputTokens && params.maxOutputTokens > 0) {
    body.max_tokens = params.maxOutputTokens;
  }

  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };

  const resp = await HttpClient.makeRequest(url, { method: 'POST', headers, data: JSON.stringify(body) });
  if (resp.status !== 200 || !resp.data) {
    const errorMsg = resp.data?.error?.message || resp.data?.message || JSON.stringify(resp.data || resp);
    const debugInfo = [
      `状态码: ${resp.status}`,
      `请求URL: ${Utils.censorUrl(url)}`,
      `API密钥状态: ${apiKey ? '已设置' : '未设置'}`,
      `兼容模式: ${effectiveCompat}`,
      `模型: ${params.model}`,
      `错误详情: ${errorMsg}`
    ].join('\n');
    throw new Error(`❌ 第三方API调用失败\n\n${debugInfo}`);
  }
  const text = resp.data?.choices?.[0]?.message?.content || '';
  return { text };
}

async function searchViaThirdParty(params: {
  model: string;
  contents: any[];
  systemInstruction?: string;
  maxOutputTokens?: number;
  compat: string;
}): Promise<{ text: string }> {
  // 搜索功能使用与聊天相同的API接口，但添加搜索相关的系统指令
  const searchSystemInstruction = params.systemInstruction || '';
  const enhancedSystemInstruction = searchSystemInstruction + 
    '\n\n你是一个智能搜索助手。请根据用户的问题提供准确、相关的信息。如果需要，可以提供多个角度的答案。';
  
  return await chatViaThirdParty({
    ...params,
    systemInstruction: enhancedSystemInstruction
  });
}

async function searchViaProvider(provider: string, params: {
  model: string;
  contents: any[];
  systemInstruction?: string;
  maxOutputTokens?: number;
}): Promise<{ text: string }> {
  // 搜索功能的系统指令增强
  const searchSystemInstruction = params.systemInstruction || '';
  const enhancedSystemInstruction = searchSystemInstruction + 
    '\n\n你是一个智能搜索助手。请根据用户的问题提供准确、相关的信息。如果需要，可以提供多个角度的答案。';
  
  // 对于所有服务商，搜索功能都通过聊天接口实现
  return await chatViaProvider(provider, {
    ...params,
    systemInstruction: enhancedSystemInstruction
  });
}

async function imageViaThirdParty(params: {
  model: string;
  contents: any[];
  compat: string;
}): Promise<{ imageUrl: string }> {
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const effectiveCompat = params.compat;
  const supportedCompats = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
  if (!supportedCompats.includes(effectiveCompat)) {
    throw new Error(`❌不支持的兼容模式: ${effectiveCompat}`);
  }

  const apiKey = keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY);
  if (!apiKey) {
    throw new Error('未设置 API 密钥。请使用 ai apikey <provider> <密钥> 命令设置，如：ai apikey thirdparty <密钥>');
  }
  const baseUrl = (baseUrls?.thirdparty || getConfig(CONFIG_KEYS.AI_BASE_URL) || '').replace(/\/$/, '');
  
  // 根据兼容模式选择不同的API端点
  let url: string;
  let body: any;
  
  switch (effectiveCompat) {
    case 'openai':
      url = `${baseUrl}/v1/images/generations`;
      const prompt = (params.contents || []).map((item: any) => 
        (item.parts || []).map((p: any) => p?.text || '').join('\n')
      ).join('\n');
      body = {
        model: params.model,
        prompt: prompt,
        n: 1,
        size: "1024x1024"
      };
      break;
    case 'gemini':
      // Gemini 使用不同的图片生成接口
      url = `${baseUrl}/v1/models/${params.model}:generateContent`;
      const geminiPrompt = (params.contents || []).map((item: any) => 
        (item.parts || []).map((p: any) => p?.text || '').join('\n')
      ).join('\n');
      body = {
        contents: [{
          parts: [{ text: `请生成图片：${geminiPrompt}` }]
        }]
      };
      break;
    case 'claude':
      // Claude 通过消息接口生成图片描述，然后转换为图片
      url = `${baseUrl}/v1/messages`;
      const claudePrompt = (params.contents || []).map((item: any) => 
        (item.parts || []).map((p: any) => p?.text || '').join('\n')
      ).join('\n');
      body = {
        model: params.model,
        max_tokens: 1024,
        messages: [{
          role: "user",
          content: `请生成图片：${claudePrompt}`
        }]
      };
      break;
    case 'deepseek':
    case 'grok':
      // DeepSeek 和 Grok 使用 OpenAI 兼容接口
      url = `${baseUrl}/v1/images/generations`;
      const compatPrompt = (params.contents || []).map((item: any) => 
        (item.parts || []).map((p: any) => p?.text || '').join('\n')
      ).join('\n');
      body = {
        model: params.model,
        prompt: compatPrompt,
        n: 1,
        size: "1024x1024"
      };
      break;
    default:
      throw new Error(`❌图片功能暂不支持 ${effectiveCompat} 兼容模式`);
  }

  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };

  const resp = await HttpClient.makeRequest(url, { method: 'POST', headers, data: JSON.stringify(body) });
  if (resp.status !== 200 || !resp.data) {
    const errorMsg = resp.data?.error?.message || JSON.stringify(resp.data || resp);
    const debugInfo = [
      `状态码: ${resp.status}`,
      `请求URL: ${Utils.censorUrl(url)}`,
      `API密钥: ${apiKey ? '已设置' : '未设置'}`,
      `兼容模式: ${effectiveCompat}`,
      `模型: ${params.model}`,
      `错误详情: ${errorMsg}`
    ];
    throw new Error(`❌ 第三方图片生成失败\n${debugInfo.join('\n')}`);
  }
  
  let imageUrl = '';
  switch (effectiveCompat) {
    case 'openai':
    case 'deepseek':
    case 'grok':
      imageUrl = resp.data?.data?.[0]?.url || '';
      break;
    case 'gemini':
      // Gemini 返回的是文本内容，需要从中提取图片URL或生成图片
      const geminiText = resp.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      // 这里应该包含图片生成逻辑，暂时返回文本描述
      imageUrl = geminiText;
      break;
    case 'claude':
      // Claude 返回的是消息内容
      const claudeText = resp.data?.content?.[0]?.text || '';
      // 这里应该包含图片生成逻辑，暂时返回文本描述
      imageUrl = claudeText;
      break;
    default:
      imageUrl = resp.data?.data?.[0]?.url || '';
  }
  
  return { imageUrl };
}

async function ttsViaThirdParty(params: {
  model: string;
  text: string;
  compat: string;
  voiceName?: string;
}): Promise<{ audioData: Buffer[]; audioMimeType: string }> {
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const effectiveCompat = params.compat;
  const supportedCompats = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
  if (!supportedCompats.includes(effectiveCompat)) {
    throw new Error(`❌不支持的兼容模式: ${effectiveCompat}`);
  }

  const apiKey = keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY);
  if (!apiKey) throw new Error('未设置第三方 API 密钥');
  const baseUrl = (baseUrls?.thirdparty || getConfig(CONFIG_KEYS.AI_BASE_URL) || '').replace(/\/$/, '');
  
  // 根据兼容模式选择不同的API端点
  let url: string;
  let body: any;
  
  // 音色映射：将Gemini音色映射为OpenAI支持的音色
  const mapVoiceForOpenAI = (voiceName: string): string => {
    const voiceMap: Record<string, string> = {
      'Kore': 'alloy',
      'Aoede': 'echo', 
      'Charon': 'fable',
      'Fenrir': 'onyx',
      'Puck': 'nova',
      'Algenib': 'shimmer'
    };
    return voiceMap[voiceName] || 'alloy';
  };

  switch (effectiveCompat) {
    case 'openai':
      url = `${baseUrl}/v1/audio/speech`;
      // 如果没有指定语音，使用当前provider的默认语音
      const defaultVoice = params.voiceName || getDefaultVoiceForCurrentTTS();
      // 只有当语音来自Gemini provider时才需要映射，否则直接使用
      const currentTTSProvider = getActiveProviderFor('tts');
      const finalVoice = currentTTSProvider === 'gemini' ? mapVoiceForOpenAI(defaultVoice) : defaultVoice;
      body = {
        model: params.model,
        input: params.text,
        voice: finalVoice
      };
      break;
    case 'gemini':
      // Gemini 使用原生TTS接口，直接使用Gemini语音名称
      url = `${baseUrl}/v1/models/${params.model}:generateContent`;
      const geminiVoice = params.voiceName || 'Kore';
      body = {
        contents: [{
          parts: [{ text: params.text }]
        }],
        generationConfig: {
          voiceName: geminiVoice
        }
      };
      break;
    case 'claude':
      // Claude 不直接支持TTS，通过文本转换
      url = `${baseUrl}/v1/messages`;
      body = {
        model: params.model,
        max_tokens: 1024,
        messages: [{
          role: "user",
          content: `请将以下文本转换为语音描述：${params.text}`
        }]
      };
      break;
    case 'deepseek':
    case 'grok':
      // DeepSeek 和 Grok 使用 OpenAI 兼容接口
      url = `${baseUrl}/v1/audio/speech`;
      const compatVoice = params.voiceName || mapVoiceForOpenAI(params.voiceName || 'Kore');
      body = {
        model: params.model,
        input: params.text,
        voice: compatVoice
      };
      break;
    default:
      throw new Error(`❌语音功能暂不支持 ${effectiveCompat} 兼容模式`);
  }

  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };

  // 使用fetch直接获取音频数据
  const controller = new AbortController();
  // 根据文本长度动态调整超时时间：基础60秒 + 每100字符增加5秒
  const textLength = params.text.length;
  const dynamicTimeout = Math.max(60000, 60000 + Math.floor(textLength / 100) * 5000);
  const timeoutId = setTimeout(() => controller.abort(), dynamicTimeout);
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text();
      let errorMsg;
      try {
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error?.message || errorText;
      } catch {
        errorMsg = errorText;
      }
      const debugInfo = [
        `状态码: ${response.status}`,
        `请求URL: ${Utils.censorUrl(url)}`,
        `API密钥: ${apiKey ? '已设置' : '未设置'}`,
        `兼容模式: ${effectiveCompat}`,
        `模型: ${params.model}`,
        `语音: ${params.voiceName || '默认'}`,
        `错误详情: ${errorMsg}`
      ];
      throw new Error(`❌ 第三方TTS生成失败\n${debugInfo.join('\n')}`);
    }
    
    // 根据不同的兼容模式处理响应
    switch (effectiveCompat) {
      case 'openai':
      case 'deepseek':
      case 'grok':
        // 直接返回音频数据
        const audioBuffer = await response.arrayBuffer();
        const audioData = [Buffer.from(audioBuffer)];
        const audioMimeType = response.headers.get('content-type') || 'audio/mpeg';
        return { audioData, audioMimeType };
        
      case 'gemini':
      case 'claude':
        // 这些服务商不直接支持TTS，返回文本描述
        const textResponse = await response.text();
        let responseData;
        try {
          responseData = JSON.parse(textResponse);
        } catch {
          responseData = { text: textResponse };
        }
        
        // 创建一个简单的音频占位符（实际应用中可能需要调用其他TTS服务）
        const placeholderText = effectiveCompat === 'gemini' 
          ? (responseData?.candidates?.[0]?.content?.parts?.[0]?.text || params.text)
          : (responseData?.content?.[0]?.text || params.text);
        
        // 返回文本作为音频描述（实际应用中应该转换为真实音频）
        const textBuffer = Buffer.from(placeholderText, 'utf-8');
        return { 
          audioData: [textBuffer], 
          audioMimeType: 'text/plain' 
        };
        
      default:
        const defaultBuffer = await response.arrayBuffer();
        return { 
          audioData: [Buffer.from(defaultBuffer)], 
          audioMimeType: response.headers.get('content-type') || 'audio/mpeg' 
        };
    }
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('请求超时');
    }
    // 如果不是超时错误，添加调试信息
    if (error.name !== 'AbortError') {
      const debugInfo = [
        `请求URL: ${Utils.censorUrl(url)}`,
        `API密钥: ${apiKey ? '已设置' : '未设置'}`,
        `兼容模式: ${effectiveCompat}`,
        `模型: ${params.model}`,
        `语音: ${params.voiceName || '默认'}`,
        `错误详情: ${error.message}`
      ];
      throw new Error(`❌ 第三方TTS请求失败\n${debugInfo.join('\n')}`);
    }
    throw error;
  }
}

async function listModelsThirdPartyOpenAI(): Promise<string[]> {
  const compat = getThirdPartyCompat();
  // 如果没有设置兼容模式，默认使用 openai 兼容
  const effectiveCompat = compat || 'openai';
  console.log(`[DEBUG] compat: '${compat}', effectiveCompat: '${effectiveCompat}'`);
  if (effectiveCompat !== 'openai') throw new Error(`第三方兼容类型不是 openai，当前值: '${effectiveCompat}'`);
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const apiKey = keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY);
  if (!apiKey) throw new Error('未设置第三方 API 密钥');
  const baseUrl = (baseUrls?.thirdparty || getConfig(CONFIG_KEYS.AI_BASE_URL) || '').replace(/\/$/, '');
  const url = `${baseUrl}/v1/models`;
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };
  const resp = await HttpClient.makeRequest(url, { method: 'GET', headers });
  if (resp.status !== 200) {
    const msg = resp.data?.error?.message || JSON.stringify(resp.data || resp);
    throw new Error(`获取第三方模型失败: ${resp.status} - ${msg}`);
  }
  const items = resp.data?.data || [];
  return items.map((x: any) => x.id).filter(Boolean);
}

async function chatViaProviderOpenAI(provider: string, params: {
  model: string;
  contents: any[];
  systemInstruction?: string;
  maxOutputTokens?: number;
}): Promise<{ text: string }> {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  
  const apiKey = keys[provider];
  if (!apiKey) throw new Error(`未设置 ${provider} API 密钥`);
  
  // 获取各服务商的基础URL
  const providerBaseUrls: Record<string, string> = {
    openai: 'https://api.openai.com',
    claude: 'https://api.anthropic.com',
    deepseek: 'https://api.deepseek.com',
    grok: 'https://api.x.ai'
  };
  
  const baseUrl = baseUrls[provider] || providerBaseUrls[provider] || '';
  const url = `${baseUrl.replace(/\/$/, '')}/v1/chat/completions`;
  
  const messages: any[] = [];
  if (params.systemInstruction) {
    messages.push({ role: 'system', content: params.systemInstruction });
  }
  for (const item of params.contents || []) {
    let role = item.role === 'model' ? 'assistant' : (item.role || 'user');
    const text = (item.parts || []).map((p: any) => p?.text || '').join('\n');
    if (text && role) messages.push({ role, content: text });
  }
  
  const body: any = {
    model: params.model,
    messages,
    stream: false
  };
  if (params.maxOutputTokens && params.maxOutputTokens > 0) {
    body.max_tokens = params.maxOutputTokens;
  }
  
  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  };
  
  // Claude使用不同的认证头
  if (provider === 'claude') {
    headers['x-api-key'] = apiKey;
    headers['anthropic-version'] = '2023-06-01';
    delete headers['Authorization'];
  }
  
  const resp = await HttpClient.makeRequest(url, { method: 'POST', headers, data: JSON.stringify(body) });
  if (resp.status !== 200 || !resp.data) {
    const msg = resp.data?.error?.message || JSON.stringify(resp.data || resp);
    throw new Error(`${provider} 接口错误: ${resp.status} - ${msg}`);
  }
  const text = resp.data?.choices?.[0]?.message?.content || '';
  return { text };
}

// 添加新的官方服务商API调用函数
async function chatViaProvider(provider: string, params: {
  model: string;
  contents: any[];
  systemInstruction?: string;
  maxOutputTokens?: number;
}) {
  return await chatViaProviderOpenAI(provider, params);
}

// 图片生成函数
async function imageViaProvider(provider: string, params: {
  model: string;
  contents: any[];
}) {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  
  const apiKey = keys[provider];
  if (!apiKey) throw new Error(`未设置 ${provider} API 密钥`);
  
  // 获取各服务商的基础URL
  const providerBaseUrls: Record<string, string> = {
    openai: 'https://api.openai.com',
    claude: 'https://api.anthropic.com',
    deepseek: 'https://api.deepseek.com',
    grok: 'https://api.x.ai'
  };
  
  const baseUrl = baseUrls[provider] || providerBaseUrls[provider] || '';
  
  // 提取图片生成提示
  const prompt = params.contents?.map((content: any) => 
    content.parts?.map((part: any) => part.text || '').join('') || ''
  ).join('') || '';
  
  if (!prompt.trim()) {
    throw new Error('❌图片生成提示为空');
  }
  
  const url = `${baseUrl.replace(/\/$/, '')}/v1/images/generations`;
  const body = {
    model: params.model,
    prompt: prompt,
    n: 1,
    size: '1024x1024',
    response_format: 'url'
  };
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKey}`
  };
  
  const resp = await HttpClient.makeRequest(url, { method: 'POST', headers, data: JSON.stringify(body) });
  if (resp.status !== 200 || !resp.data) {
    const msg = resp.data?.error?.message || JSON.stringify(resp.data || resp);
    throw new Error(`❌图片生成失败: ${resp.status} ${msg}`);
  }
  
  const imageUrl = resp.data.data?.[0]?.url;
  if (!imageUrl) {
    throw new Error('❌未能获取生成的图片URL');
  }
  
  return { imageUrl };
}

// TTS语音合成函数
async function ttsViaProvider(provider: string, params: {
  model: string;
  text: string;
  voiceName?: string;
}) {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  
  const apiKey = keys[provider];
  if (!apiKey) throw new Error(`未设置 ${provider} API 密钥`);
  
  // 获取各服务商的基础URL
  const providerBaseUrls: Record<string, string> = {
    openai: 'https://api.openai.com',
    claude: 'https://api.anthropic.com',
    deepseek: 'https://api.deepseek.com',
    grok: 'https://api.x.ai'
  };
  
  const baseUrl = baseUrls[provider] || providerBaseUrls[provider] || '';
  
  if (!params.text.trim()) {
    throw new Error('❌文本内容为空，无法生成语音');
  }
  
  // 获取默认语音
   const voice = params.voiceName || getDefaultVoiceForProvider(provider as 'openai' | 'gemini' | 'claude' | 'deepseek' | 'grok' | 'thirdparty');
  
  const url = `${baseUrl.replace(/\/$/, '')}/v1/audio/speech`;
  const body = {
    model: params.model,
    input: params.text,
    voice: voice,
    response_format: 'mp3'
  };
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${apiKey}`
  };
  
  // 使用fetch直接获取音频数据
  const controller = new AbortController();
  // 根据文本长度动态调整超时时间：基础90秒 + 每100字符增加10秒
  const textLength = params.text.length;
  const dynamicTimeout = Math.max(90000, 90000 + Math.floor(textLength / 100) * 10000);
  const timeoutId = setTimeout(() => controller.abort(), dynamicTimeout);
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`❌语音合成失败: ${response.status} ${errorText}`);
    }
    
    const audioBuffer = await response.arrayBuffer();
    const audioData = [Buffer.from(audioBuffer)];
    const audioMimeType = response.headers.get('content-type') || 'audio/mpeg';
    
    return { audioData, audioMimeType };
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('❌请求超时，请稍后重试');
    }
    throw error;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getConfig(key: string, defaultValue?: string): string {
  return ConfigManager.get(key, defaultValue || DEFAULT_CONFIG[key] || "");
}

function createSafetySettings(): any[] {
  return [
    'HARM_CATEGORY_HATE_SPEECH',
    'HARM_CATEGORY_DANGEROUS_CONTENT', 
    'HARM_CATEGORY_HARASSMENT',
    'HARM_CATEGORY_SEXUALLY_EXPLICIT',
    'HARM_CATEGORY_CIVIC_INTEGRITY'
  ].map(category => ({ category, threshold: 'BLOCK_NONE' }));
}

function markdownToHtml(text: string): string {
  let result = text;

  const htmlTags: string[] = [];
  let tagIndex = 0;
  result = result.replace(/<\/?[a-zA-Z][^>]*>/g, (match) => {
    htmlTags.push(match);
    return `__HTML_TAG_${tagIndex++}__`;
  });
  
  result = result
    .replace(/&/g, "&amp;")
    .replace(/</g, "<")
    .replace(/>/g, ">");
  
  htmlTags.forEach((tag, index) => {
    result = result.replace(`__HTML_TAG_${index}__`, tag);
  });
  
  result = result
    .replace(/```(\w+)?\n([\s\S]*?)```/g, (_match, _lang, code) => {
      const escapedCode = code.replace(/</g, '<').replace(/>/g, '>').replace(/&amp;/g, '&');
      return `<pre><code>${Utils.escapeHtml(escapedCode)}</code></pre>`;
    })
    .replace(/`([^`]+)`/g, (_match, code) => {
      const escapedCode = code.replace(/</g, '<').replace(/>/g, '>').replace(/&amp;/g, '&');
      return `<code>${Utils.escapeHtml(escapedCode)}</code>`;
    })
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\*([^*\n]+)\*/g, '<i>$1</i>')
    .replace(/__([^_]+)__/g, '<b>$1</b>')
    .replace(/_([^_\n]+)_/g, '<i>$1</i>')
    .replace(/~~([^~]+)~~/g, '<s>$1</s>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
    .replace(/^### (.+)$/gm, '<b>$1</b>')
    .replace(/^## (.+)$/gm, '<b>$1</b>')
    .replace(/^# (.+)$/gm, '<b>$1</b>')
    .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>');
  return result;
}

async function getAiClient(): Promise<AiClient> {
  const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
  const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
  const apiKey = keys?.gemini || getConfig(CONFIG_KEYS.AI_API_KEY);
  if (!apiKey) {
    throw new Error("未设置 API 密钥。请使用 ai apikey <provider> <密钥> 命令设置，如：ai apikey gemini <密钥>");
  }
  const baseUrl = baseUrls?.gemini || getConfig(CONFIG_KEYS.AI_BASE_URL) || null;
  return new AiClient(apiKey, baseUrl);
}

/**
 * 调用AI聊天服务的核心函数
 * 
 * 该函数实现了智能故障转移机制，会按优先级尝试所有可用的AI服务商，
 * 直到找到一个可用的服务或所有服务都失败为止。
 * 
 * @param prompt - 用户输入的提示文本
 * @param useSearch - 是否启用搜索功能（默认false）
 * @param imageData - 可选的图片数据（base64编码）
 * @returns Promise<string> - AI的响应文本
 * @throws Error - 当所有服务商都不可用时抛出错误
 * 
 * 功能特性：
 * - 智能故障转移：自动尝试多个AI服务商
 * - 上下文管理：支持聊天历史记录
 * - 多模态支持：支持文本和图片输入
 * - 搜索集成：可选的Google搜索工具
 * - 配置驱动：基于用户配置选择模型和提示词
 */
async function callAiChat(
  prompt: string,
  useSearch: boolean = false,
  imageData?: string
): Promise<string> {
  // 根据功能类型确定使用聊天还是搜索模式
  const feature: 'chat' | 'search' = useSearch ? 'search' : 'chat';
  
  // 获取当前活跃的服务商
  const activeProvider = getActiveProviderFor(feature);
  
  // 检查服务商是否有API密钥
  if (!checkProviderApiKey(activeProvider)) {
    throw new Error(`❌当前活跃服务商 ${activeProvider.toUpperCase()} 未配置API密钥`);
  }
  
  // 根据功能类型获取对应的系统提示词配置
  const activePromptKey = useSearch ? CONFIG_KEYS.AI_SEARCH_ACTIVE_PROMPT : CONFIG_KEYS.AI_CHAT_ACTIVE_PROMPT;
  const systemPromptName = getConfig(activePromptKey);
  const prompts = JSON.parse(getConfig(CONFIG_KEYS.AI_PROMPTS, "{}"));
  // 使用自定义提示词或默认提示词
  const systemPrompt = systemPromptName ? prompts[systemPromptName] || "你是一个乐于助人的人工智能助手。" : "你是一个乐于助人的人工智能助手。";

  // 构建基础消息内容（文本 + 可选图片）
  const baseParts: any[] = [{ text: prompt }];
  if (imageData) {
    // 添加图片数据到消息中（多模态支持）
    baseParts.push({ inlineData: { mimeType: "image/png", data: imageData } });
  }
  let contents: any[] = [{ role: "user", parts: baseParts }];

  // 处理聊天上下文（仅在聊天模式下，搜索模式不使用历史记录）
  if (getConfig(CONFIG_KEYS.AI_CONTEXT_ENABLED) === "on" && !useSearch) {
    const history = JSON.parse(getConfig(CONFIG_KEYS.AI_CHAT_HISTORY, "[]"));
    
    // 过滤并清理历史记录，确保数据格式正确
    const cleanHistory = history.filter((item: any) => {
      return item.role && item.parts && item.parts.every((part: any) => 
        part.text && typeof part.text === 'string' && !part.inlineData
      );
    });
    
    // 检查历史记录完整性，如果发现损坏的记录则重置
    if (history.length > 0 && history.some((item: any) => !item.role)) {
      ConfigManager.set(CONFIG_KEYS.AI_CHAT_HISTORY, "[]");
    } else {
      // 将清理后的历史记录添加到当前对话中
      contents = [...cleanHistory, ...contents];
    }
  }

  // 获取最大输出令牌数配置
  const maxTokens = parseInt(getConfig(CONFIG_KEYS.AI_MAX_TOKENS, "0"));
  // 根据是否使用搜索功能配置工具
  const tools = useSearch ? [{ googleSearch: {} }] : undefined;

  // 获取当前功能对应的活跃模型
  const modelName = getActiveModelFor(feature);
  // 获取服务商对应的适配器
  const adapter = getAdapter(activeProvider);
  
  console.log(`[AI] 使用服务商: ${activeProvider} (模型: ${modelName})`);
  
  try {
    // 调用AI服务
    const response = await adapter.chat({
      model: modelName,
      contents,
      systemInstruction: systemPrompt,
      maxOutputTokens: maxTokens > 0 ? maxTokens : undefined,
      tools
    });
    
    console.log(`[AI] ✅ 成功使用服务商: ${activeProvider}`);
    
    // 保存对话历史（仅在启用上下文且非搜索模式时）
    if (getConfig(CONFIG_KEYS.AI_CONTEXT_ENABLED) === "on" && !useSearch) {
      const currentHistory = JSON.parse(getConfig(CONFIG_KEYS.AI_CHAT_HISTORY, "[]"));
      
      // 添加用户消息和AI回复到历史记录
      const userMessage = { role: "user", parts: [{ text: prompt }] };
      const assistantMessage = { role: "model", parts: [{ text: response.text }] };
      
      currentHistory.push(userMessage, assistantMessage);
      
      // 限制历史记录长度（保留最近20轮对话，即40条消息）
      const maxHistoryLength = 40;
      if (currentHistory.length > maxHistoryLength) {
        currentHistory.splice(0, currentHistory.length - maxHistoryLength);
      }
      
      ConfigManager.set(CONFIG_KEYS.AI_CHAT_HISTORY, JSON.stringify(currentHistory));
    }
    
    return response.text;
    
  } catch (error: any) {
    console.error(`[AI] ❌ 服务商 ${activeProvider} 调用失败: ${error.message}`);
    throw new Error(`❌ ${activeProvider.toUpperCase()} 服务调用失败: ${error.message}`);
  }
}

async function formatResponse(question: string, answer: string): Promise<string> {
  const isCollapsibleEnabled = getConfig(CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED) === "on";
  const isTelegraphEnabled = getConfig(CONFIG_KEYS.AI_TELEGRAPH_ENABLED) === "on";
  const telegraphLimit = parseInt(getConfig(CONFIG_KEYS.AI_TELEGRAPH_LIMIT, "0"));
  
  let finalText = "";

  if (question.trim()) {
    const htmlQuestion = markdownToHtml(question);
    const quoteTag = isCollapsibleEnabled ? "<blockquote expandable>" : "<blockquote>";
    finalText += `<b>Q:</b>\n${quoteTag}${htmlQuestion}</blockquote>\n\n`;
  }

  const htmlAnswer = markdownToHtml(answer);
  const quoteTag = isCollapsibleEnabled ? "<blockquote expandable>" : "<blockquote>";
  finalText += `<b>A:</b>\n${quoteTag}${htmlAnswer}</blockquote>`;

  // 检查是否需要使用Telegraph
  if (isTelegraphEnabled && telegraphLimit > 0 && Utils.getUtf16Length(finalText) > telegraphLimit) {
    try {
      const telegraphClient = new TelegraphClient();
      const title = question.trim() ? 
        `AI回答: ${question.substring(0, 50)}${question.length > 50 ? '...' : ''}` : 
        `AI回答 - ${new Date().toLocaleString()}`;
      
      const sanitizedContent = Utils.sanitizeHtmlForTelegraph(finalText);
      const result = await telegraphClient.createPage(title, sanitizedContent);
      
      // 保存Telegraph文章记录
      const posts = JSON.parse(getConfig(CONFIG_KEYS.AI_TELEGRAPH_POSTS, "{}"));
      const postId = Date.now().toString();
      posts[postId] = {
        url: result.url,
        path: result.path,
        title: title,
        created: new Date().toISOString()
      };
      ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_POSTS, JSON.stringify(posts));
      
      // 返回简化的消息和Telegraph链接
      const shortAnswer = answer.substring(0, 500) + (answer.length > 500 ? "..." : "");
      const shortHtmlAnswer = markdownToHtml(shortAnswer);
      let shortText = "";
      
      if (question.trim()) {
        const htmlQuestion = markdownToHtml(question);
        const shortQuoteTag = isCollapsibleEnabled ? "<blockquote expandable>" : "<blockquote>";
        shortText += `<b>Q:</b>\n${shortQuoteTag}${htmlQuestion}</blockquote>\n\n`;
      }
      
      const shortQuoteTag = isCollapsibleEnabled ? "<blockquote expandable>" : "<blockquote>";
      shortText += `<b>A:</b>\n${shortQuoteTag}${shortHtmlAnswer}</blockquote>\n\n`;
      shortText += `📄 <b>完整回答已发布到Telegraph:</b>\n<a href="${result.url}">${Utils.escapeHtml(title)}</a>`;
      
      return shortText;
    } catch (error) {
      // Telegraph创建失败，返回原始格式
      console.error('Telegraph创建失败:', error);
    }
  }

  return finalText;
}

async function downloadAndProcessImage(
  client: any,
  message: Api.Message,
  infoMessage: Api.Message
): Promise<string> {
  await infoMessage.edit({ text: "下载图片..." });
  let mediaMsg = message;
  const replyMsg = await message.getReplyMessage();
  if (!message.media && replyMsg?.media) {
    mediaMsg = replyMsg;
  }

  if (!mediaMsg.media) {
    throw new Error("未找到图片");
  }

  const buffer = await client.downloadMedia(mediaMsg.media, { 
    workers: 1,
    progressCallback: (received: number, total: number) => {
      const percent = (received * 100 / total);
      infoMessage.edit({
        text: `下载图片 ${percent.toFixed(1)}%`
      }).catch(() => {});
    }
  });

  if (!buffer) {
    throw new Error("图片下载失败");
  }

  await infoMessage.edit({ text: "下载图片 100%" });

  return (buffer as Buffer).toString('base64');
}

function extractQuestionFromArgs(args: string[], replyMsg?: Api.Message | null): { userQuestion: string; displayQuestion: string; apiQuestion: string } {
  const userQuestion = args.join(" ");
  
  if (!userQuestion && replyMsg?.text) {
    const replyText = Utils.removeEmoji(replyMsg.text.trim());
    return {
      userQuestion: "",
      displayQuestion: replyText,
      apiQuestion: replyText
    };
  } else if (userQuestion && replyMsg?.text) {
    const cleanUserQuestion = Utils.removeEmoji(userQuestion);
    const replyText = Utils.removeEmoji(replyMsg.text.trim());
    return {
      userQuestion: cleanUserQuestion,
      displayQuestion: cleanUserQuestion,
      apiQuestion: `原消息内容: ${replyText}\n\n问题: ${cleanUserQuestion}`
    };
  } else {
    const cleanUserQuestion = Utils.removeEmoji(userQuestion);
    return {
      userQuestion: cleanUserQuestion,
      displayQuestion: cleanUserQuestion,
      apiQuestion: cleanUserQuestion
    };
  }
}

async function handleSearch(msg: Api.Message, args: string[]): Promise<void> {
  // 检查当前服务商是否支持搜索功能
  const provider = getActiveProviderFor('search');
  if (!isFeatureSupported(provider, 'search')) {
    await msg.edit({ text: "❌当前自定义的服务暂时不支持此功能" });
    return;
  }
  
  const replyMsg = await msg.getReplyMessage();
  const { userQuestion, displayQuestion, apiQuestion } = extractQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    await msg.edit({ text: "❌ 请提供搜索查询或回复一条有文字内容的消息" });
    return;
  }

  await msg.edit({ text: "🔍 搜索中..." });
  const answer = await callAiChat(apiQuestion, true);
  const formattedText = await formatResponse(displayQuestion, answer);
  
  if (replyMsg) {
    await msg.client?.sendMessage(msg.peerId, {
      message: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('search'), withSearch: true, kind: 'search' }),
      linkPreview: false,
      parseMode: "html",
      replyTo: replyMsg.id
    });

    try {
      await msg.delete();
    } catch {}
  } else {
    await msg.edit({ 
      text: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('search'), withSearch: true, kind: 'search' }),
      linkPreview: false,
      parseMode: "html"
    });
  }
}

async function handleImage(msg: Api.Message, args: string[]): Promise<void> {
  const replyMsg = await msg.getReplyMessage();
  const { userQuestion, displayQuestion, apiQuestion } = extractQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    await msg.edit({ text: "❌ 请提供图片生成提示或回复一条有文字内容的消息" });
    return;
  }

  // 获取所有可用的图片生成服务商
  const availableProviders = getAvailableProvidersForFeature('image');
  if (availableProviders.length === 0) {
    await msg.edit({ text: "❌没有可用的服务商支持图片生成功能，请检查API密钥配置" });
    return;
  }

  await msg.edit({ text: "🎨 生成图片中..." });
  
  // 智能故障转移：尝试所有可用的服务商
  let lastError: any;
  let response: any;
  
  for (let i = 0; i < availableProviders.length; i++) {
    const provider = availableProviders[i];
    try {
      const adapter = getAdapter(provider);
      response = await adapter.image({
        model: getActiveModelFor('image'),
        contents: [{ parts: [{ text: apiQuestion }] }]
      });
      
      console.log(`[AI] 图片生成成功使用服务商: ${provider}`);
      break; // 成功则跳出循环
    } catch (error: any) {
      lastError = error;
      console.warn(`[AI] 图片生成服务商 ${provider} 失败: ${error.message}`);
      
      // 如果不是最后一个服务商，继续尝试下一个
      if (i < availableProviders.length - 1) {
        console.log(`[AI] 故障转移到下一个图片生成服务商...`);
        continue;
      }
    }
  }
  
  // 如果所有服务商都失败了
  if (!response) {
    await msg.edit({ text: `❌所有图片生成服务商都不可用。错误: ${lastError?.message || '未知错误'}` });
    return;
  }
  
  try {

    // 检查是否有图片数据或URL
    if (!response.imageData && !response.text) {
      await msg.edit({ text: "❌ 图片生成失败" });
      return;
    }

    const replyMsg = await msg.getReplyMessage();
    
    // 处理图片数据
    try {
      let imageFile: Buffer & { name: string };
      
      if (response.imageData) {
        // 直接使用返回的图片数据（Gemini原生API）
        imageFile = Object.assign(response.imageData, {
          name: 'ai.png'
        });
      } else if (response.text) {
        // 尝试作为URL下载（第三方API）
        const imageResponse = await fetch(response.text);
        if (!imageResponse.ok) {
          throw new Error(`下载图片失败: ${imageResponse.status}`);
        }
        const imageBuffer = await imageResponse.arrayBuffer();
        imageFile = Object.assign(Buffer.from(imageBuffer), {
          name: 'ai.png'
        });
      } else {
        throw new Error('未找到有效的图片数据');
      }
     
       if (replyMsg) {
          await msg.client?.sendFile(msg.peerId, {
            file: imageFile,
            caption: `<b>提示:</b> ${Utils.escapeHtml(displayQuestion || apiQuestion)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('image'), kind: 'image' })}`,
            parseMode: "html",
            replyTo: replyMsg.id
          });
      
          try {
            await msg.delete();
          } catch {}
        } else {
          await msg.edit({
            file: imageFile,
            text: `<b>提示:</b> ${Utils.escapeHtml(displayQuestion || apiQuestion)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('image'), kind: 'image' })}`,
            parseMode: "html"
          });
        }
      } catch (error: any) {
        await msg.edit({ text: `❌ 图片处理失败: ${error.message}` });
      }
    } catch (error: any) {
      await msg.edit({ text: Utils.handleError(error, '图片生成', {
        logLevel: 'error',
        showTechnicalDetails: false
      }) });
    }
}

// 带故障转移的音频生成函数
async function processAudioGenerationWithFailover(
  msg: Api.Message, 
  text: string, 
  p0: string,
  replyMsg: Api.Message | null | undefined,
  availableProviders: ('gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty')[]
): Promise<void> {
  let lastError: any;
  
  for (let i = 0; i < availableProviders.length; i++) {
    const provider = availableProviders[i];
    try {
      await processAudioGenerationForProvider(msg, text, p0, replyMsg, provider);
      console.log(`[AI] 语音合成成功使用服务商: ${provider}`);
      return; // 成功则返回
    } catch (error: any) {
      lastError = error;
      console.warn(`[AI] 语音合成服务商 ${provider} 失败: ${error.message}`);
      
      // 如果不是最后一个服务商，继续尝试下一个
      if (i < availableProviders.length - 1) {
        console.log(`[AI] 故障转移到下一个语音合成服务商...`);
        continue;
      }
    }
  }
  
  // 所有服务商都失败了
  throw new Error(`所有语音合成服务商都不可用。最后错误: ${lastError?.message || '未知错误'}`);
}

// 为特定服务商生成音频
async function processAudioGenerationForProvider(
  msg: Api.Message, 
  text: string, 
  p0: string,
  replyMsg: Api.Message | null | undefined,
  provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty'
): Promise<void> {
  const client = await getAiClient();
  const modelName = getActiveModelFor('tts');
  
  // 获取配置的语音，如果没有配置或语音不兼容当前provider则使用默认语音
  let voiceName = ConfigManager.get(CONFIG_KEYS.AI_TTS_VOICE, DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]);
  
  // 检查当前语音是否兼容当前provider
  const isVoiceCompatible = (voice: string, currentProvider: string): boolean => {
    if (currentProvider === 'gemini') {
      // Gemini支持的语音列表
      const geminiVoices = ['achernar', 'achird', 'algenib', 'algieba', 'alnilam', 'aoede', 'autonoe', 'callirrhoe', 'charon', 'despina', 'enceladus', 'erinome', 'fenrir', 'gacrux', 'iapetus', 'kore', 'laomedeia', 'leda', 'orus', 'puck', 'pulcherrima', 'rasalgethi', 'sadachbia', 'sadaltager', 'schedar', 'sulafat', 'umbriel', 'vindemiatrix', 'zephyr', 'zubenelgenubi'];
      return geminiVoices.includes(voice.toLowerCase());
    } else {
      // 其他provider支持OpenAI格式的语音
      const openaiVoices = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];
      return openaiVoices.includes(voice.toLowerCase());
    }
  };
  
  if (!voiceName || voiceName === DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE] || !isVoiceCompatible(voiceName, provider)) {
    voiceName = getDefaultVoiceForProvider(provider);
  }

  const adapter = getAdapter(provider);
  const response = await adapter.tts({
    model: modelName,
    contents: [{ parts: [{ text }] }],
    voiceName
  });

  if (!response.audioData?.length) {
    throw new Error('没有收到音频数据');
  }

  const combinedAudio = Buffer.concat(response.audioData);
  if (combinedAudio.length === 0) {
    throw new Error('合并后的音频数据为空');
  }

  if (replyMsg) {
    let processedAudio: any = combinedAudio;
    
    if (response.audioMimeType && response.audioMimeType.includes('L16') && response.audioMimeType.includes('pcm')) {
      processedAudio = Utils.convertToWav(combinedAudio, response.audioMimeType) as any;
    }

    const audioFile = Object.assign(processedAudio as any, {
      name: 'ai.ogg'
    });

    await msg.client?.sendFile(msg.peerId, {
      file: audioFile,
      caption: `<b>文本:</b> ${Utils.escapeHtml(text)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), kind: 'tts', voiceName })}`,
      parseMode: "html",
      replyTo: replyMsg.id,
      attributes: [new Api.DocumentAttributeAudio({
        duration: 0,
        voice: true
      })]
    });

    try {
      await msg.delete();
    } catch {}
  } else {
    let processedAudio: any = combinedAudio;
    
    if (response.audioMimeType && response.audioMimeType.includes('L16') && response.audioMimeType.includes('pcm')) {
      processedAudio = Utils.convertToWav(combinedAudio, response.audioMimeType) as any;
    }

    const audioFile = Object.assign(processedAudio as any, {
      name: 'ai.ogg'
    });

    await msg.client?.sendFile(msg.peerId, {
      file: audioFile,
      caption: `<b>文本:</b> ${Utils.escapeHtml(text)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), kind: 'tts', voiceName })}`,
      parseMode: "html",
      attributes: [new Api.DocumentAttributeAudio({
        duration: 0,
        voice: true
      })]
    });

    try {
      await msg.delete();
    } catch {}
  }
}

async function processAudioGeneration(
msg: Api.Message, text: string, p0: string,
replyMsg?: Api.Message | null): Promise<void> {
  const client = await getAiClient();
  const modelName = getActiveModelFor('tts');
  // 获取配置的语音，如果没有配置或语音不兼容当前provider则使用默认语音
  let voiceName = ConfigManager.get(CONFIG_KEYS.AI_TTS_VOICE, DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]);
  const currentProvider = getActiveProviderFor('tts');
  
  // 检查当前语音是否兼容当前provider
  const isVoiceCompatible = (voice: string, provider: string): boolean => {
    if (provider === 'gemini') {
      // Gemini支持的语音列表
      const geminiVoices = ['achernar', 'achird', 'algenib', 'algieba', 'alnilam', 'aoede', 'autonoe', 'callirrhoe', 'charon', 'despina', 'enceladus', 'erinome', 'fenrir', 'gacrux', 'iapetus', 'kore', 'laomedeia', 'leda', 'orus', 'puck', 'pulcherrima', 'rasalgethi', 'sadachbia', 'sadaltager', 'schedar', 'sulafat', 'umbriel', 'vindemiatrix', 'zephyr', 'zubenelgenubi'];
      return geminiVoices.includes(voice.toLowerCase());
    } else {
      // 其他provider支持OpenAI格式的语音
      const openaiVoices = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'];
      return openaiVoices.includes(voice.toLowerCase());
    }
  };
  
  if (!voiceName || voiceName === DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE] || !isVoiceCompatible(voiceName, currentProvider)) {
    voiceName = getDefaultVoiceForCurrentTTS();
    // 自动更新配置以避免下次再次检查
    ConfigManager.set(CONFIG_KEYS.AI_TTS_VOICE, voiceName);
  }

  const adapter = getAdapter(getActiveProviderFor('tts'));
  const response = await adapter.tts({
    model: modelName,
    contents: [{ parts: [{ text }] }],
    voiceName
  });

  if (!response.audioData?.length) {
    throw new Error('没有收到音频数据');
  }

  const combinedAudio = Buffer.concat(response.audioData);
  if (combinedAudio.length === 0) {
    throw new Error('合并后的音频数据为空');
  }

  if (replyMsg) {
    let processedAudio: any = combinedAudio;
    
    if (response.audioMimeType && response.audioMimeType.includes('L16') && response.audioMimeType.includes('pcm')) {
      processedAudio = Utils.convertToWav(combinedAudio, response.audioMimeType) as any;
    }

    const audioFile = Object.assign(processedAudio as any, {
      name: 'ai.ogg'
    });

    await msg.client?.sendFile(msg.peerId, {
      file: audioFile,
      caption: `<b>文本:</b> ${Utils.escapeHtml(text)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), kind: 'tts', voiceName })}`,
      parseMode: "html",
      replyTo: replyMsg.id,
      attributes: [new Api.DocumentAttributeAudio({
        duration: 0,
        voice: true
      })]
    });

    try {
      await msg.delete();
    } catch {}
  } else {
    let processedAudio: any = combinedAudio;
    
    if (response.audioMimeType && response.audioMimeType.includes('L16') && response.audioMimeType.includes('pcm')) {
      processedAudio = Utils.convertToWav(combinedAudio, response.audioMimeType) as any;
    }

    const audioFile = Object.assign(processedAudio as any, {
      name: 'ai.ogg'
    });

    await msg.client?.sendFile(msg.peerId, {
      file: audioFile,
      caption: `<b>文本:</b> ${Utils.escapeHtml(text)}${Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), kind: 'tts', voiceName })}`,
      parseMode: "html",
      attributes: [new Api.DocumentAttributeAudio({
        duration: 0,
        voice: true
      })]
    });

    try {
      await msg.delete();
    } catch {}
  }
}

async function handleTTS(msg: Api.Message, args: string[]): Promise<void> {
  const replyMsg = await msg.getReplyMessage();
  const { userQuestion, displayQuestion, apiQuestion } = extractQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    await msg.edit({ text: "❌ 请提供要转换为语音的文本或回复一条有文字内容的消息" });
    return;
  }

  // 获取所有可用的语音合成服务商
  const availableProviders = getAvailableProvidersForFeature('tts');
  if (availableProviders.length === 0) {
    await msg.edit({ text: "❌没有可用的服务商支持语音合成功能，请检查API密钥配置" });
    return;
  }

  await msg.edit({ text: "🗣️ 生成语音中..." });
  
  try {
    await processAudioGenerationWithFailover(msg, apiQuestion, 'TTS Handler', replyMsg, availableProviders);
  } catch (error: any) {
    await msg.edit({ text: `❌ 所有语音合成服务商都不可用: ${error.message || '未知错误'}` });
  }
}

async function handleQuestionWithAudio(
  msg: Api.Message, 
  question: string, 
  displayQuestion: string,
  useSearch: boolean, 
  context: string,
  replyMsg?: Api.Message | null
): Promise<void> {
  const ttsProvider = getActiveProviderFor('tts');
  if (!isFeatureSupported(ttsProvider, 'tts')) {
    await msg.edit({ text: '❌当前自定义的服务暂时不支持此功能' });
    return;
  }
  try {
    const answer = await callAiChat(question, useSearch);
    
    await msg.edit({ text: "🗣️ 转换为语音中..." });
    
    const formattedText = await formatResponse(displayQuestion, answer);
    // 获取配置的语音，如果没有配置则使用当前provider的默认语音
    let voiceName = ConfigManager.get(CONFIG_KEYS.AI_TTS_VOICE, DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]);
    if (!voiceName || voiceName === DEFAULT_CONFIG[CONFIG_KEYS.AI_TTS_VOICE]) {
      voiceName = getDefaultVoiceForCurrentTTS();
    }
    const searchText = useSearch ? ' with Google Search' : '';
    
    try {
      const adapter = getAdapter(ttsProvider);
      const audioResponse = await adapter.tts({
        model: getActiveModelFor('tts'),
        contents: [{ parts: [{ text: answer }] }],
        voiceName
      });
      
      if (audioResponse.audioData?.length) {
        const combinedAudio = Buffer.concat(audioResponse.audioData);
        
        if (combinedAudio.length > 0) {
  
          if (replyMsg) {
            let processedAudio: any = combinedAudio;

            if (audioResponse.audioMimeType && audioResponse.audioMimeType.includes('L16') && audioResponse.audioMimeType.includes('pcm')) {
              processedAudio = Utils.convertToWav(combinedAudio, audioResponse.audioMimeType) as any;
            }

            const audioFile = Object.assign(processedAudio as any, {
              name: 'ai.ogg'
            });

            await msg.client?.sendFile(msg.peerId, {
              file: audioFile,
              caption: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), withSearch: useSearch, kind: 'audio', voiceName }),
              parseMode: "html",
              replyTo: replyMsg.id,
              attributes: [new Api.DocumentAttributeAudio({
                duration: 0,
                voice: true
              })]
            });

            try {
              await msg.delete();
            } catch {}
          } else {
            await Utils.sendAudioBuffer(
              msg,
              combinedAudio,
              formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('tts'), withSearch: useSearch, kind: 'audio', voiceName }),
              audioResponse.audioMimeType
            );
          }
        } else {
          throw new Error('音频数据为空');
        }
      } else {
        throw new Error('未收到音频数据');
      }
    } catch (audioError: any) {

      const errorMessage = audioError.message || '未知错误';
      if (replyMsg) {
        await msg.client?.sendMessage(msg.peerId, {
          message: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor(useSearch ? 'search' : 'chat'), withSearch: useSearch, kind: 'chat', errorText: errorMessage }),
          linkPreview: false,
          parseMode: "html",
          replyTo: replyMsg.id
        });

        try {
          await msg.delete();
        } catch {}
      } else {
        await msg.edit({ 
          text: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor(useSearch ? 'search' : 'chat'), withSearch: useSearch, kind: 'chat', errorText: errorMessage }),
          linkPreview: false,
          parseMode: "html"
        });
      }
    }
  } catch (error: any) {
    await msg.edit({ text: Utils.handleError(error, `${useSearch ? '搜索' : ''}音频回答生成`, {
      logLevel: 'error',
      showTechnicalDetails: false
    }) });
  }
}

async function handleAudio(msg: Api.Message, args: string[]): Promise<void> {
  const replyMsg = await msg.getReplyMessage();
  const { userQuestion, displayQuestion, apiQuestion } = extractQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    await msg.edit({ text: "❌ 请提供问题或回复一条有文字内容的消息" });
    return;
  }

  await handleQuestionWithAudio(msg, apiQuestion, displayQuestion, false, 'Audio', replyMsg);
}

async function handleSearchAudio(msg: Api.Message, args: string[]): Promise<void> {
  const replyMsg = await msg.getReplyMessage();
  const { userQuestion, displayQuestion, apiQuestion } = extractQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    await msg.edit({ text: "❌ 请提供搜索查询或回复一条有文字内容的消息" });
    return;
  }

  await msg.edit({ text: "🔍 搜索中..." });
  await handleQuestionWithAudio(msg, apiQuestion, displayQuestion, true, 'Search Audio', replyMsg);
}

async function handleSettings(msg: Api.Message): Promise<void> {
  const switchToText = (value: string): string => value === "on" ? "开启" : "关闭";
  const tokensToText = (value: string): string => value === "0" ? "无限制" : value;
  
  const activeProvider = getConfig(CONFIG_KEYS.AI_ACTIVE_PROVIDER, "");
  
  const settings = {
    "活跃服务商": activeProvider ? activeProvider.toUpperCase() : "自动选择",
    "基础 URL": Utils.censorUrl(getConfig(CONFIG_KEYS.AI_BASE_URL)),
    "聊天模型": getActiveModelFor('chat'),
    "搜索模型": getActiveModelFor('search'),
    "图片模型": getActiveModelFor('image'),
    "TTS模型": getActiveModelFor('tts'),
    "TTS语音": getConfig(CONFIG_KEYS.AI_TTS_VOICE),
    "最大Token数": tokensToText(getConfig(CONFIG_KEYS.AI_MAX_TOKENS)),
    "上下文启用": switchToText(getConfig(CONFIG_KEYS.AI_CONTEXT_ENABLED)),
    "Telegraph启用": switchToText(getConfig(CONFIG_KEYS.AI_TELEGRAPH_ENABLED)),
    "折叠引用": switchToText(getConfig(CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED))
  };

  const settingsText = "<b>AI 设置:</b>\n\n" + Object.entries(settings)
    .map(([key, value]) => `<b>• ${key}:</b> <code>${value}</code>`)
    .join("\n");

  await msg.edit({ text: settingsText, parseMode: "html" });
}

async function handleModelList(msg: Api.Message): Promise<void> {
  await msg.edit({ text: "🔍 获取可用模型..." });
  
  try {
    const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, "{}");
    const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, "{}");
    let modelText = "<b>📋 可用模型列表:</b>\n\n";
    
    // 官方服务商模型
    const officialProviders = [
      { key: 'gemini', name: 'Google Gemini', models: ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-1.0-pro'] },
      { key: 'openai', name: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo', 'dall-e-3', 'tts-1'] },
      { key: 'claude', name: 'Anthropic Claude', models: ['claude-3-5-sonnet-20241022', 'claude-3-haiku-20240307', 'claude-3-opus-20240229'] },
      { key: 'deepseek', name: 'DeepSeek', models: ['deepseek-chat', 'deepseek-coder'] },
      { key: 'grok', name: 'xAI Grok', models: ['grok-beta'] }
    ];
    
    let hasAnyProvider = false;
    
    for (const provider of officialProviders) {
      if (keys[provider.key]) {
        hasAnyProvider = true;
        const caps = getProviderCaps()[provider.key as keyof ReturnType<typeof getProviderCaps>];
        const features = [];
        if (caps?.chat) features.push('💬聊天');
        if (caps?.search) features.push('🔍搜索');
        if (caps?.image) features.push('🖼️图片');
        if (caps?.tts) features.push('🔊语音');
        
        modelText += `<b>🔹 ${provider.name}</b> (${features.join(' ')})\n`;
        modelText += provider.models.map(model => `  • <code>${model}</code>`).join('\n') + '\n\n';
      }
    }
    
    // 第三方API模型
    const compat = getThirdPartyCompat();
    // 如果没有设置兼容模式，默认使用 openai 兼容
    const effectiveCompat = compat || 'openai';
    if (baseUrls?.thirdparty && (keys?.thirdparty || getConfig(CONFIG_KEYS.AI_API_KEY))) {
      const supportedCompats = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
      if (supportedCompats.includes(effectiveCompat)) {
        hasAnyProvider = true;
        try {
          const allThirdPartyModels = await listModelsThirdPartyOpenAI();
          
          // 按服务商分类模型
          const categorizedModels = {
            gemini: allThirdPartyModels.filter(m => m.toLowerCase().includes('gemini')),
            openai: allThirdPartyModels.filter(m => m.toLowerCase().includes('gpt') || m.toLowerCase().includes('davinci') || m.toLowerCase().includes('turbo')),
            claude: allThirdPartyModels.filter(m => m.toLowerCase().includes('claude')),
            deepseek: allThirdPartyModels.filter(m => m.toLowerCase().includes('deepseek')),
            grok: allThirdPartyModels.filter(m => m.toLowerCase().includes('grok')),
            other: allThirdPartyModels.filter(m => 
              !m.toLowerCase().includes('gemini') && 
              !m.toLowerCase().includes('gpt') && 
              !m.toLowerCase().includes('davinci') && 
              !m.toLowerCase().includes('turbo') && 
              !m.toLowerCase().includes('claude') && 
              !m.toLowerCase().includes('deepseek') && 
              !m.toLowerCase().includes('grok')
            )
          };
          
          // 根据兼容模式显示功能标识
          const caps = getProviderCaps().thirdparty;
          const features = [];
          if (caps?.chat) features.push('💬聊天');
          if (caps?.search) features.push('🔍搜索');
          if (caps?.image) features.push('🖼️图片');
          if (caps?.tts) features.push('🔊语音');
          
          const compatName = {
            gemini: 'Gemini',
            openai: 'OpenAI',
            claude: 'Claude',
            deepseek: 'DeepSeek',
            grok: 'Grok'
          }[effectiveCompat] || effectiveCompat;
          
          modelText += `<b>🔹 第三方API</b> (兼容 ${compatName}) (${features.join(' ')})\n`;
          
          // 显示分类后的模型，限制每类最多显示5个
          let totalShown = 0;
          const maxPerCategory = 5;
          const maxTotal = 20;
          
          for (const [category, models] of Object.entries(categorizedModels)) {
            if (models.length > 0 && totalShown < maxTotal) {
              const categoryName = {
                gemini: 'Gemini系列',
                openai: 'OpenAI系列', 
                claude: 'Claude系列',
                deepseek: 'DeepSeek系列',
                grok: 'Grok系列',
                other: '其他模型'
              }[category] || category;
              
              const modelsToShow = models.slice(0, Math.min(maxPerCategory, maxTotal - totalShown));
              modelText += `  <b>${categoryName}</b> (${models.length}个):\n`;
              modelText += modelsToShow.map(model => `    • <code>${model}</code>`).join('\n') + '\n';
              
              if (models.length > modelsToShow.length) {
                modelText += `    ... 还有${models.length - modelsToShow.length}个模型\n`;
              }
              modelText += '\n';
              totalShown += modelsToShow.length;
            }
          }
          
          if (allThirdPartyModels.length > totalShown) {
            modelText += `  💡 共${allThirdPartyModels.length}个模型，仅显示前${totalShown}个\n\n`;
          }
          
        } catch (error) {
          modelText += `<b>🔹 第三方API</b> (兼容 OpenAI) (💬聊天)\n`;
          modelText += `  ❌ 获取模型失败: ${error}\n\n`;
        }
      }
    }
    
    if (!hasAnyProvider) {
      modelText += "❌ 未配置任何服务商API密钥\n\n";
      modelText += "💡 使用 <code>ai apikey &lt;provider&gt; &lt;key&gt;</code> 设置密钥";
    } else {
      modelText += "💡 使用 <code>ai model set &lt;type&gt; &lt;model&gt;</code> 设置模型";
    }
    
    await msg.edit({ text: modelText, parseMode: "html" });
  } catch (error: any) {
    await msg.edit({ text: Utils.handleError(error, '获取模型', {
      logLevel: 'error',
      showTechnicalDetails: false
    }) });
  }
}

/**
 * 清除AI聊天的对话历史记录
 * 
 * 该函数会清空存储在配置中的所有聊天历史，
 * 下次对话将从全新的上下文开始。
 * 
 * @param msg - Telegram消息对象，用于编辑回复
 */
async function handleContextClear(msg: Api.Message): Promise<void> {
  ConfigManager.set(CONFIG_KEYS.AI_CHAT_HISTORY, "[]");
  await msg.edit({ text: "✅ 对话历史已清除" });
}

/**
 * 显示当前的对话上下文状态和历史记录
 * 
 * 该函数会展示：
 * - 上下文功能的启用/禁用状态
 * - 最近的对话历史（最多显示5轮对话）
 * - 对话内容会被截断以适应显示
 * 
 * @param msg - Telegram消息对象，用于编辑回复
 */
async function handleContextShow(msg: Api.Message): Promise<void> {
  const history = JSON.parse(ConfigManager.get(CONFIG_KEYS.AI_CHAT_HISTORY, "[]"));
  const isEnabled = ConfigManager.get(CONFIG_KEYS.AI_CONTEXT_ENABLED) === "on";
  
  if (history.length === 0) {
    await msg.edit({ 
      text: `<b>对话上下文状态:</b> ${isEnabled ? "已启用" : "已禁用"}\n\n<b>对话历史:</b> 空`, 
      parseMode: "html" 
    });
    return;
  }
  
  let displayText = `<b>对话上下文状态:</b> ${isEnabled ? "已启用" : "已禁用"}\n\n<b>对话历史</b> (${history.length / 2} 轮对话):\n\n`;

  const maxRounds = 5;
  const startIndex = Math.max(0, history.length - maxRounds * 2);
  
  for (let i = startIndex; i < history.length; i += 2) {
    const userMsg = history[i]?.parts?.[0]?.text || "";
    const assistantMsg = history[i + 1]?.parts?.[0]?.text || "";
    
    const roundNum = Math.floor(i / 2) + 1;
    const truncatedUserMsg = userMsg.length > 100 ? userMsg.substring(0, 100) + "..." : userMsg;
    const truncatedAssistantMsg = assistantMsg.length > 200 ? assistantMsg.substring(0, 200) + "..." : assistantMsg;
    
    displayText += `<b>第${roundNum}轮:</b>\n`;
    displayText += `<b>Q:</b> ${Utils.escapeHtml(truncatedUserMsg)}\n`;
    displayText += `<b>A:</b> ${Utils.escapeHtml(truncatedAssistantMsg)}\n\n`;
  }
  
  if (history.length > maxRounds * 2) {
    displayText += `<i>... 还有 ${Math.floor((history.length - maxRounds * 2) / 2)} 轮更早的对话</i>`;
  }
  
  await msg.edit({ text: displayText, parseMode: "html" });
}

async function handleTelegraph(msg: Api.Message, args: string[]): Promise<void> {
  const subCommand = args[0];
  
  switch (subCommand) {
    case "on":
      ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_ENABLED, "on");
      await msg.edit({ text: "✅ Telegraph集成已启用", parseMode: "html" });
      break;
    case "off":
      ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_ENABLED, "off");
      await msg.edit({ text: "✅ Telegraph集成已禁用", parseMode: "html" });
      break;
    case "limit":
      if (args[1]) {
        const validation = Utils.validateConfig(CONFIG_KEYS.AI_TELEGRAPH_LIMIT, args[1]);
        if (!validation.isValid) {
          await msg.edit({ text: `❌ ${validation.error}` });
          return;
        }
        ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_LIMIT, args[1]);
        await msg.edit({ text: `✅ Telegraph字符限制已设置为 ${args[1]}`, parseMode: "html" });
      } else {
        await msg.edit({ text: "❌ 用法: ai telegraph limit <数字>" });
      }
      break;
    case "list":
      const posts = JSON.parse(ConfigManager.get(CONFIG_KEYS.AI_TELEGRAPH_POSTS, "{}"));
      if (Object.keys(posts).length === 0) {
        await msg.edit({ text: "<b>尚未创建Telegraph文章。</b>", parseMode: "html" });
        return;
      }
      
      const postsList = Object.entries(posts)
        .map(([id, data]: [string, any]) => `• <code>${id}</code>: <a href="https://telegra.ph/${data.path}">${Utils.escapeHtml(data.title)}</a>`)
        .join("\n");
      
      await msg.edit({ 
        text: `<b>已创建的Telegraph文章:</b>\n\n${postsList}`, 
        parseMode: "html",
        linkPreview: false
      });
      break;
    case "del":
      const delTarget = args[1];
      if (!delTarget) {
        await msg.edit({ text: "❌ 用法: ai telegraph del [id|all]" });
        return;
      }
      
      const currentPosts = JSON.parse(ConfigManager.get(CONFIG_KEYS.AI_TELEGRAPH_POSTS, "{}"));
      
      if (delTarget === "all") {
        ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_POSTS, "{}");
        await msg.edit({ text: "✅ 已删除所有Telegraph文章", parseMode: "html" });
      } else {
        if (currentPosts[delTarget]) {
          delete currentPosts[delTarget];
          ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_POSTS, JSON.stringify(currentPosts));
          await msg.edit({ text: `✅ 已删除Telegraph文章 <code>${delTarget}</code>`, parseMode: "html" });
        } else {
          await msg.edit({ text: `❌ 未找到ID为 <code>${delTarget}</code> 的Telegraph文章`, parseMode: "html" });
        }
      }
      break;
    default:
      await msg.edit({ text: "❌ 用法: ai telegraph [on|off|limit|list|del]" });
  }
}

async function handleCollapse(msg: Api.Message, args: string[]): Promise<void> {
  const setting = args[0];
  
  if (setting === "on") {
    ConfigManager.set(CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED, "on");
    await msg.edit({ text: "✅ 折叠引用已启用", parseMode: "html" });
  } else if (setting === "off") {
    ConfigManager.set(CONFIG_KEYS.AI_COLLAPSIBLE_QUOTE_ENABLED, "off");
    await msg.edit({ text: "✅ 折叠引用已禁用", parseMode: "html" });
  } else {
    await msg.edit({ text: "❌ 用法: ai collapse [on|off]" });
  }
}

/**
 * 处理AI提示词管理命令
 * 
 * 支持的子命令：
 * - add <名称> <内容>: 添加新的系统提示词
 * - del <名称>: 删除指定的系统提示词
 * - list: 列出所有已保存的系统提示词
 * - set <类型> <名称>: 为指定功能设置活跃的系统提示词
 * 
 * @param msg - Telegram消息对象，用于编辑回复
 * @param args - 命令参数数组
 */
async function handlePrompt(msg: Api.Message, args: string[]): Promise<void> {
  const [subCommand, ...subArgs] = args;
  const prompts = JSON.parse(ConfigManager.get(CONFIG_KEYS.AI_PROMPTS, "{}"));
  
  switch (subCommand) {
    case "add":
      if (subArgs.length < 2) {
        await msg.edit({ text: "❌ 用法: ai prompt add <名称> <提示内容>" });
        return;
      }
      const [name, ...promptParts] = subArgs;
      prompts[name] = promptParts.join(" ");
      ConfigManager.set(CONFIG_KEYS.AI_PROMPTS, JSON.stringify(prompts));
      await msg.edit({ text: `✅ 系统提示 '${name}' 已添加`, parseMode: "html" });
      break;
      
    case "del":
      const delName = subArgs[0];
      if (!delName) {
        await msg.edit({ text: "❌ 用法: ai prompt del <名称>" });
        return;
      }
      if (delName in prompts) {
        delete prompts[delName];
        ConfigManager.set(CONFIG_KEYS.AI_PROMPTS, JSON.stringify(prompts));
        await msg.edit({ text: `✅ 系统提示 '${delName}' 已删除`, parseMode: "html" });
      } else {
        await msg.edit({ text: `❌ 未找到系统提示 '${delName}'` });
      }
      break;
      
    case "list":
      if (Object.keys(prompts).length === 0) {
        await msg.edit({ text: "<b>未保存任何系统提示。</b>", parseMode: "html" });
        return;
      }
      const promptsList = Object.entries(prompts)
        .map(([name, content]) => `• <code>${name}</code>:\n<pre><code>${Utils.escapeHtml(content as string)}</code></pre>`)
        .join("\n\n");
      await msg.edit({ text: `<b>可用的系统提示:</b>\n\n${promptsList}`, parseMode: "html" });
      break;
      
    case "set":
      const [promptType, setName] = subArgs;
      if (!promptType || !setName) {
        await msg.edit({ text: "❌ 用法: ai prompt set [chat|search|tts] <名称>" });
        return;
      }
      
      if (!(setName in prompts)) {
        await msg.edit({ text: `❌ 未找到系统提示 '${setName}'` });
        return;
      }
      
      const promptConfig = PROMPT_TYPE_MAP[promptType as keyof typeof PROMPT_TYPE_MAP];
      if (promptConfig) {
        ConfigManager.set(promptConfig.key, setName);
        await msg.edit({ text: `✅ 当前${promptConfig.name}系统提示已设置为: <code>${setName}</code>`, parseMode: "html" });
      } else {
        await msg.edit({ text: "❌ 用法: ai prompt set [chat|search|tts] <名称>" });
      }
      break;
      
    case "show":
      const showName = subArgs[0];
      if (!showName) {
        await msg.edit({ text: "❌ 用法: ai prompt show <名称>" });
        return;
      }
      
      if (!(showName in prompts)) {
        await msg.edit({ text: `❌ 未找到系统提示 '${showName}'` });
        return;
      }
      
      const promptContent = prompts[showName] as string;
      await msg.edit({ 
        text: `<b>系统提示 '${showName}':</b>\n\n<pre><code>${Utils.escapeHtml(promptContent)}</code></pre>`, 
        parseMode: "html" 
      });
      break;
      
    default:
      await msg.edit({ text: "❌ 用法: ai prompt [add|del|list|set|show]" });
  }
}

/**
 * 处理AI模型管理命令
 * 
 * 支持的子命令：
 * - list: 显示所有可用的AI模型和服务商状态
 * - auto/automatch: 手动触发自动模型匹配和分配
 * - set <类型> <模型名>: 为指定功能设置活跃模型
 * 
 * 该函数会根据配置的API密钥和baseurl自动检测可用的服务商，
 * 并提供模型选择和自动匹配功能。
 * 
 * @param msg - Telegram消息对象，用于编辑回复
 * @param args - 命令参数数组
 */
async function handleModel(msg: Api.Message, args: string[]): Promise<void> {
  const subCommand = args[0];
  
  if (subCommand === "list") {
    await handleModelList(msg);
    return;
  }
  
  if (subCommand === "auto" || subCommand === "automatch") {
    // 手动触发自动模型匹配
    const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, '{}');
    const thirdPartyUrl = baseUrls?.thirdparty || getConfig(CONFIG_KEYS.AI_BASE_URL);
    
    if (!thirdPartyUrl) {
      await msg.edit({ text: "❌ 请先设置第三方API的baseurl" });
      return;
    }
    
    // 手动触发时使用强制更新模式
    const autoAssignResult = await performAutoModelAssignment(thirdPartyUrl, true);
    await msg.edit({ text: autoAssignResult });
    return;
  }
  

  if (subCommand === "set" && args.length >= 3) {
    const modelType = args[1];
    const modelName = args[2];
    const modelConfig = MODEL_TYPE_MAP[modelType as keyof typeof MODEL_TYPE_MAP];
    
    if (modelConfig) {
      // 写入新结构 JSON（优先级更高）
      const models = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, '{}');
      models[modelType as 'chat' | 'search' | 'image' | 'tts'] = modelName;
      ConfigManager.set(CONFIG_KEYS.AI_MODELS, JSON.stringify(models));
      // 同步旧键以保持向后兼容
      ConfigManager.set(modelConfig.key, modelName);
      await msg.edit({ 
        text: `✅ ${modelConfig.name}模型已设置为: <code>${modelName}</code>`, 
        parseMode: "html" 
      });
    } else {
      await msg.edit({ text: "❌ 用法: ai model set [chat|search|image|tts] <模型名称>" });
    }
  } else {
    await msg.edit({ text: "❌ 用法: ai model [list|set|auto]\n\n• list - 显示当前模型配置\n• set [chat|search|image|tts] <模型名称> - 手动设置模型\n• auto - 自动匹配第三方API可用模型" });
  }
}

async function handleTTSVoice(msg: Api.Message, args: string[]): Promise<void> {
  if (args.length === 0) {
    await msg.edit({ text: "❌ 用法: ai ttsvoice <语音名称> 或 ai ttsvoice list" });
    return;
  }
  
  if (args[0].toLowerCase() === 'list') {
    const availableVoices = [
      "Achernar", "Achird", "Algenib", "Algieba", "Alnilam", "Aoede", "Autonoe", "Callirrhoe",
      "Charon", "Despina", "Enceladus", "Erinome", "Fenrir", "Gacrux", "Iapetus", "Kore",
      "Laomedeia", "Leda", "Orus", "Puck", "Pulcherrima", "Rasalgethi", "Sadachbia",
      "Sadaltager", "Schedar", "Sulafat", "Umbriel", "Vindemiatrix", "Zephyr", "Zubenelgenubi"
    ];
    
    const currentVoice = getConfig(CONFIG_KEYS.AI_TTS_VOICE);
    let voiceList = "🎵 <b>可用的 TTS 音色列表:</b>\n\n";
    
    availableVoices.forEach(voice => {
      if (voice === currentVoice) {
        voiceList += `• <b>${voice}</b> ✅ (当前使用)\n`;
      } else {
        voiceList += `• ${voice}\n`;
      }
    });
    
    voiceList += "\n💡 使用 <code>ai ttsvoice &lt;音色名称&gt;</code> 来设置音色";
    
    await msg.edit({ text: voiceList, parseMode: "html" });
    return;
  }
  
  const voiceName = args.join(" ");
  
  const availableVoices = [
    "Achernar", "Achird", "Algenib", "Algieba", "Alnilam", "Aoede", "Autonoe", "Callirrhoe",
    "Charon", "Despina", "Enceladus", "Erinome", "Fenrir", "Gacrux", "Iapetus", "Kore",
    "Laomedeia", "Leda", "Orus", "Puck", "Pulcherrima", "Rasalgethi", "Sadachbia",
    "Sadaltager", "Schedar", "Sulafat", "Umbriel", "Vindemiatrix", "Zephyr", "Zubenelgenubi"
  ];
  
  if (!availableVoices.includes(voiceName)) {
    await msg.edit({ 
      text: `❌ 无效的音色名称: <code>${voiceName}</code>\n\n💡 使用 <code>ai ttsvoice list</code> 查看所有可用音色`, 
      parseMode: "html" 
    });
    return;
  }
  
  ConfigManager.set(CONFIG_KEYS.AI_TTS_VOICE, voiceName);
  await msg.edit({ text: `✅ TTS 语音已设置为: <code>${voiceName}</code>`, parseMode: "html" });
}

async function handleConfigDefault(msg: Api.Message): Promise<void> {
  try {
    // 清除所有AI相关配置，恢复到默认状态
    const configKeys = Object.values(CONFIG_KEYS);
    
    await msg.edit({ text: "🔄 正在重置配置到默认状态..." });
    
    // 删除所有配置项
    for (const key of configKeys) {
      ConfigManager.delete(key);
    }
    
    // 清除聊天历史
    ConfigManager.set(CONFIG_KEYS.AI_CHAT_HISTORY, "[]");
    
    // 清除Telegraph文章
    ConfigManager.set(CONFIG_KEYS.AI_TELEGRAPH_POSTS, "{}");
    
    // 清除提示词
    ConfigManager.set(CONFIG_KEYS.AI_PROMPTS, "{}");
    
    await msg.edit({ 
      text: "✅ 配置已重置到默认状态\n\n" +
            "📋 已清除的内容:\n" +
            "• 所有API密钥和基础URL\n" +
            "• 自定义模型设置\n" +
            "• 聊天历史记录\n" +
            "• Telegraph文章\n" +
            "• 自定义提示词\n" +
            "• 其他所有自定义配置\n\n" +
            "💡 现在可以重新配置您的AI设置"
    });
  } catch (error) {
    console.error("重置配置失败:", error);
    await msg.edit({ text: "❌ 重置配置时发生错误，请稍后重试" });
  }
}

// 处理状态检测命令
async function handleStatus(msg: Api.Message): Promise<void> {
  try {
    await msg.edit({ text: "🔍 正在检测服务商状态..." });
    
    const statusReport = getProvidersStatusReport();
    
    // 添加当前活跃服务商信息
    const activeProviders = {
      chat: getActiveProviderFor('chat'),
      search: getActiveProviderFor('search'),
      image: getActiveProviderFor('image'),
      tts: getActiveProviderFor('tts')
    };
    
    let activeInfo = '\n\n<b>🎯 当前活跃服务商</b>\n';
    activeInfo += `💬 聊天: <code>${activeProviders.chat.toUpperCase()}</code>\n`;
    activeInfo += `🔍 搜索: <code>${activeProviders.search.toUpperCase()}</code>\n`;
    activeInfo += `🖼️ 图片: <code>${activeProviders.image.toUpperCase()}</code>\n`;
    activeInfo += `🔊 语音: <code>${activeProviders.tts.toUpperCase()}</code>`;
    
    const fullReport = statusReport + activeInfo;
    
    await msg.edit({ 
      text: fullReport,
      parseMode: 'html'
    });
  } catch (error: any) {
    console.error('[AI] 状态检测失败:', error);
    await msg.edit({ text: `❌ 状态检测失败: ${error.message}` });
  }
}

// 处理上下文相关命令
async function handleContextCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  if (subArgs[0] === "clear") {
    await handleContextClear(msg);
  } else if (subArgs[0] === "on") {
    ConfigManager.set(CONFIG_KEYS.AI_CONTEXT_ENABLED, "on");
    await msg.edit({ text: "✅ 对话上下文已启用" });
  } else if (subArgs[0] === "off") {
    ConfigManager.set(CONFIG_KEYS.AI_CONTEXT_ENABLED, "off");
    await msg.edit({ text: "✅ 对话上下文已禁用" });
  } else if (subArgs[0] === "show") {
    await handleContextShow(msg);
  } else {
    await msg.edit({ text: "❌ 用法: ai context [on|off|clear|show]" });
  }
}

// 处理服务商选择命令
async function handleSelectCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  const supportedProviders = ["gemini", "openai", "claude", "deepseek", "grok", "thirdparty"];
  
  if (subArgs.length === 0) {
    await msg.edit({ text: "❌ 用法: ai select <gemini|openai|claude|deepseek|grok|thirdparty>" });
    return;
  }
  
  let provider = subArgs[0].toLowerCase();
  
  if (!supportedProviders.includes(provider)) {
    await msg.edit({ text: "❌ 用法: ai select <gemini|openai|claude|deepseek|grok|thirdparty>" });
    return;
  }
  
  // 检查服务商是否有API密钥
  if (!checkProviderApiKey(provider as any)) {
    await msg.edit({ text: `❌ ${provider.toUpperCase()} 服务商未配置API密钥，请先使用 ai apikey ${provider} <密钥> 进行配置` });
    return;
  }
  
  // 设置活跃服务商
  ConfigManager.set(CONFIG_KEYS.AI_ACTIVE_PROVIDER, provider);
  
  // 设置所有功能都使用选定的服务商
  const models = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_MODELS, '{}');
  const features = ['chat', 'search', 'image', 'tts'] as const;
  const updatedFeatures: string[] = [];
  
  for (const feature of features) {
    if (isFeatureSupported(provider as any, feature)) {
      // 获取该服务商支持的默认模型
      const defaultModel = getDefaultModelForProvider(provider as any, feature);
      if (defaultModel) {
        models[feature] = defaultModel;
        updatedFeatures.push(feature);
      }
    }
  }
  
  if (updatedFeatures.length === 0) {
    await msg.edit({ text: `❌ ${provider.toUpperCase()} 服务商不支持任何功能` });
    return;
  }
  
  ConfigManager.set(CONFIG_KEYS.AI_MODELS, JSON.stringify(models));
  
  const featureNames = { chat: '💬聊天', search: '🔍搜索', image: '🖼️图片', tts: '🔊语音' };
  const supportedFeaturesList = updatedFeatures.map(f => featureNames[f as keyof typeof featureNames]).join(' ');
  
  await msg.edit({ 
    text: `✅ 已选择 ${provider.toUpperCase()} 作为AI服务商\n\n支持功能: ${supportedFeaturesList}`,
    parseMode: 'markdown'
  });
}

// 获取服务商的默认模型
function getDefaultModelForProvider(provider: 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok' | 'thirdparty', feature: 'chat' | 'search' | 'image' | 'tts'): string | null {
  const providerDefaults = {
    gemini: {
      chat: 'gemini-1.5-flash',
      search: 'gemini-1.5-flash',
      image: 'gemini-1.5-flash',
      tts: 'tts-1'
    },
    openai: {
      chat: 'gpt-4o-mini',
      search: 'gpt-4o-mini',
      image: 'dall-e-3',
      tts: 'tts-1'
    },
    claude: {
      chat: 'claude-3-5-haiku-20241022',
      search: 'claude-3-5-haiku-20241022',
      image: null,
      tts: null
    },
    deepseek: {
      chat: 'deepseek-chat',
      search: 'deepseek-chat',
      image: null,
      tts: null
    },
    grok: {
      chat: 'grok-beta',
      search: 'grok-beta',
      image: null,
      tts: null
    },
    thirdparty: {
      chat: 'gpt-4o-mini',
      search: 'gpt-4o-mini',
      image: 'dall-e-3',
      tts: 'tts-1'
    }
  };
  
  return providerDefaults[provider]?.[feature] || null;
}

// 处理API密钥设置命令
async function handleApiKeyCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  const supported = ["gemini", "thirdparty", "openai", "claude", "deepseek", "grok"];
  if (subArgs.length >= 2) {
    const provider = subArgs[0].toLowerCase();
    const keyVal = subArgs[1].trim();
    if (!supported.includes(provider)) {
      await msg.edit({ text: "❌ 用法: ai apikey <gemini|thirdparty|openai|claude|deepseek|grok> <密钥>" });
      return;
    }
    const keys = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_KEYS, '{}');
    keys[provider] = keyVal;
    ConfigManager.set(CONFIG_KEYS.AI_KEYS, JSON.stringify(keys));
    if (provider === 'gemini') ConfigManager.set(CONFIG_KEYS.AI_API_KEY, keyVal);
    // 自动更新TTS语音以匹配新的provider
    autoUpdateTTSVoice();
    const displayValue = keyVal.substring(0, 8) + '...';
    
    let responseText = `✅ 已设置 ${provider} API Key: \`${displayValue}\``;
    
    // 如果是第三方API密钥，添加baseurl设置提示
    if (provider === 'thirdparty') {
      responseText += '\n\n💡 请继续设置第三方的baseurl：\n`ai baseurl thirdparty <地址>`';
    } else {
      // 官方API自动配置模型
      const autoConfigResult = await performOfficialAutoModelAssignment(provider as 'gemini' | 'openai' | 'claude' | 'deepseek' | 'grok');
      responseText += `\n\n${autoConfigResult}`;
    }
    
    await msg.edit({ text: responseText, parseMode: 'markdown' });
    await sleep(5000);
    try { await msg.delete(); } catch {}
  } else {
    await msg.edit({ text: "❌ 用法: ai apikey <gemini|thirdparty|openai|claude|deepseek|grok> <密钥>" });
  }
}

// 处理基础URL设置命令
async function handleBaseUrlCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  if (subArgs.length >= 2 && subArgs[0].toLowerCase() === 'thirdparty') {
    const url = subArgs[1].trim();
    const baseUrls = getJsonConfig<Record<string, string>>(CONFIG_KEYS.AI_BASE_URLS, '{}');
    baseUrls.thirdparty = url;
    ConfigManager.set(CONFIG_KEYS.AI_BASE_URLS, JSON.stringify(baseUrls));
    // 自动更新TTS语音以匹配新的provider
    autoUpdateTTSVoice();
    
    // 执行自动模型匹配
    const autoAssignResult = await performAutoModelAssignment(url);
    await msg.edit({ 
      text: `✅ 已设置第三方基础 URL: \`${Utils.censorUrl(url)}\`\n\n${autoAssignResult}`, 
      parseMode: 'markdown' 
    });
  } else {
    await msg.edit({ text: "❌ 用法: ai baseurl thirdparty <url>" });
  }
}

// 处理第三方兼容模式命令
async function handleThirdPartyCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  if (subArgs[0] === 'compat' && subArgs[1]) {
    const type = subArgs[1].toLowerCase();
    const allowed = ['gemini', 'openai', 'claude', 'deepseek', 'grok'];
    if (!allowed.includes(type)) {
      await msg.edit({ text: "❌ 用法: ai thirdparty compat <gemini|openai|claude|deepseek|grok>" });
      return;
    }
    ConfigManager.set(CONFIG_KEYS.AI_THIRD_PARTY_COMPAT, type);
    await msg.edit({ text: `✅ 第三方兼容模式已设置为: <code>${type}</code>`, parseMode: 'html' });
  } else {
    await msg.edit({ text: "❌ 用法: ai thirdparty compat <gemini|openai|claude|deepseek|grok>" });
  }
}

// 处理配置命令
async function handleConfigCommand(msg: Api.Message, subArgs: string[]): Promise<void> {
  if (subArgs[0] === 'default') {
    await handleConfigDefault(msg);
  } else {
    await msg.edit({ text: "❌ 用法: ai config default" });
  }
}

// 处理通用配置设置
async function handleGenericConfigSetting(msg: Api.Message, args: string[]): Promise<boolean> {
  if (args.length === 2 && ['apikey', 'baseurl', 'maxtokens', 'chatmodel', 'searchmodel', 'imagemodel', 'ttsmodel', 'context', 'telegraph', 'collapse'].includes(args[0])) {
    const configKey = args[0];
    const configValue = args[1].trim();
    const configInfo = CONFIG_MAP[configKey as keyof typeof CONFIG_MAP];
    
    if (!configInfo) {
      await msg.edit({ text: "❌ 未知的配置项" });
      return true;
    }
    
    if (configInfo.key !== CONFIG_KEYS.AI_API_KEY) {
      const validation = Utils.validateConfig(configInfo.key, configValue);
      if (!validation.isValid) {
        await msg.edit({ text: `❌ ${validation.error}` });
        return true;
      }
    }
    
    ConfigManager.set(configInfo.key, configValue);
    const displayValue = configInfo.key === CONFIG_KEYS.AI_API_KEY 
      ? configValue.substring(0, 8) + "..."
      : configValue;
    
    await msg.edit({ 
      text: `✅ 已设置 ${configInfo.name}: \`${displayValue}\``,
      parseMode: "markdown"
    });
    
    await sleep(5000);
    try {
      await msg.delete();
    } catch (deleteError) {
      // 忽略删除错误
    }
    return true;
  }
  return false;
}

// 处理TTS语音设置
async function handleTTSVoiceSetting(msg: Api.Message, args: string[]): Promise<boolean> {
  if (args.length === 2 && args[0] === 'ttsvoice' && args[1].toLowerCase() !== 'list') {
    const configValue = args[1].trim();
    const configInfo = CONFIG_MAP['ttsvoice'];
    
    const validation = Utils.validateConfig(configInfo.key, configValue);
    if (!validation.isValid) {
      await msg.edit({ text: `❌ ${validation.error}` });
      return true;
    }
    
    ConfigManager.set(configInfo.key, configValue);
    
    await msg.edit({ 
      text: `✅ 已设置 ${configInfo.name}: \`${configValue}\``,
      parseMode: "markdown"
    });
    
    await sleep(5000);
    try {
      await msg.delete();
    } catch (deleteError) {
      // 忽略删除错误
    }
    return true;
  }
  return false;
}

/**
 * 解析聊天请求中的问题内容
 * 
 * 该函数会根据用户输入的参数和回复的消息内容，
 * 智能组合生成用于显示和API调用的问题文本。
 * 
 * 处理逻辑：
 * - 仅有回复消息：使用回复内容作为问题
 * - 有参数和回复：参数作为问题，回复作为上下文
 * - 仅有参数：直接使用参数作为问题
 * 
 * @param args - 用户输入的命令参数
 * @param replyMsg - 回复的消息对象（可选）
 * @returns 包含显示问题和API问题的对象
 */
function parseQuestionFromArgs(args: string[], replyMsg: Api.Message | null): { displayQuestion: string; apiQuestion: string } {
  const userQuestion = args.join(" ");
  
  if (!userQuestion && replyMsg?.text) {
    const replyText = replyMsg.text.trim();
    return { displayQuestion: replyText, apiQuestion: replyText };
  } else if (userQuestion && replyMsg?.text) {
    const replyText = replyMsg.text.trim();
    return { 
      displayQuestion: userQuestion, 
      apiQuestion: `原消息内容: ${replyText}\n\n问题: ${userQuestion}` 
    };
  } else if (userQuestion) {
    return { displayQuestion: userQuestion, apiQuestion: userQuestion };
  }
  
  return { displayQuestion: "", apiQuestion: "" };
}

/**
 * 处理视觉聊天请求（图片+文本的多模态对话）
 * 
 * 该函数会：
 * 1. 下载并处理图片数据
 * 2. 解析用户问题和上下文
 * 3. 调用AI进行图片分析
 * 4. 格式化并发送响应
 * 
 * 支持的场景：
 * - 纯图片分析（无文字问题）
 * - 图片+问题分析
 * - 回复图片消息并提问
 * 
 * @param msg - 当前消息对象
 * @param args - 用户输入的命令参数
 * @param replyMsg - 回复的消息对象（可选）
 */
async function handleVisionChat(msg: Api.Message, args: string[], replyMsg: Api.Message | null): Promise<void> {
  await msg.edit({ text: "🤔 下载图片中..." });
  const imageBase64 = await downloadAndProcessImage(msg.client, msg, msg);
  
  let displayQuestion = "";
  let apiQuestion = "";
  const userQuestion = args.join(" ");
  
  if (!userQuestion && replyMsg?.text) {
    const replyText = Utils.removeEmoji(replyMsg.text.trim());
    displayQuestion = replyText;
    apiQuestion = replyText;
  } else if (userQuestion && replyMsg?.text) {
    const cleanUserQuestion = Utils.removeEmoji(userQuestion);
    const replyText = Utils.removeEmoji(replyMsg.text.trim());
    displayQuestion = cleanUserQuestion;
    apiQuestion = `关于这张图片，原消息内容: ${replyText}\n\n问题: ${cleanUserQuestion}`;
  } else if (userQuestion) {
    const cleanUserQuestion = Utils.removeEmoji(userQuestion);
    displayQuestion = cleanUserQuestion;
    apiQuestion = cleanUserQuestion;
  } else {
    displayQuestion = "";
    apiQuestion = "用中文描述此图片";
  }
  
  await msg.edit({ text: "🤔 思考中..." });
  const answer = await callAiChat(apiQuestion, false, imageBase64);
  const formattedText = await formatResponse(displayQuestion, answer);
  
  if (replyMsg) {
    await msg.client?.sendMessage(msg.peerId, {
      message: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('chat'), kind: 'chat' }),
      linkPreview: false,
      parseMode: "html",
      replyTo: replyMsg.id
    });
    try {
      await msg.delete();
    } catch {}
  } else {
    await msg.edit({ 
      text: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('chat'), kind: 'chat' }),
      linkPreview: false,
      parseMode: "html"
    });
  }
}

// 处理普通文本聊天请求
async function handleTextChat(msg: Api.Message, args: string[], replyMsg: Api.Message | null): Promise<void> {
  const { displayQuestion, apiQuestion } = parseQuestionFromArgs(args, replyMsg);
  
  if (!apiQuestion) {
    if (!replyMsg?.text?.trim()) {
      await msg.edit({ text: "❌ 请直接提问或回复一条有文字内容的消息" });
      return;
    }
  }
  
  await msg.edit({ text: "🤔 思考中..." });
  const answer = await callAiChat(apiQuestion, false);
  const formattedText = await formatResponse(displayQuestion, answer);
  
  if (replyMsg) {
    await msg.client?.sendMessage(msg.peerId, {
      message: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('chat'), kind: 'chat' }),
      linkPreview: false,
      parseMode: "html",
      replyTo: replyMsg.id
    });
    try {
      await msg.delete();
    } catch {}
  } else {
    await msg.edit({ 
      text: formattedText + Utils.renderPoweredByFooter({ model: getActiveModelFor('chat'), kind: 'chat' }),
      linkPreview: false,
      parseMode: "html"
    });
  }
}

async function handleAIRequest(msg: Api.Message): Promise<void> {
  const [, ...args] = msg.message.slice(1).split(" ");
  const subCommand = args[0];
  const subArgs = args.slice(1);

  try {
    // 处理子命令
    switch (subCommand) {
      case "search":
        await handleSearch(msg, subArgs);
        return;
      case "image":
        await handleImage(msg, subArgs);
        return;
      case "tts":
        await handleTTS(msg, subArgs);
        return;
      case "audio":
        await handleAudio(msg, subArgs);
        return;
      case "searchaudio":
        await handleSearchAudio(msg, subArgs);
        return;
      case "settings":
        await handleSettings(msg);
        return;
      case "model":
        await handleModel(msg, subArgs);
        return;
      case "ttsvoice":
        await handleTTSVoice(msg, subArgs);
        return;
      case "context":
        await handleContextCommand(msg, subArgs);
        return;
      case "status":
        await handleStatus(msg);
        return;
      case "telegraph":
        await handleTelegraph(msg, subArgs);
        return;
      case "collapse":
        await handleCollapse(msg, subArgs);
        return;
      case "prompt":
        await handlePrompt(msg, subArgs);
        return;
      case "apikey":
        await handleApiKeyCommand(msg, subArgs);
        return;
      case "baseurl":
        await handleBaseUrlCommand(msg, subArgs);
        return;
      case "thirdparty":
        await handleThirdPartyCommand(msg, subArgs);
        return;
      case "config":
        await handleConfigCommand(msg, subArgs);
        return;
      case "select":
        await handleSelectCommand(msg, subArgs);
        return;
    }

    // 处理通用配置设置
    if (await handleGenericConfigSetting(msg, args)) {
      return;
    }
    
    // 处理TTS语音设置
    if (await handleTTSVoiceSetting(msg, args)) {
      return;
    }

    // 处理聊天请求
    const replyMsg = await msg.getReplyMessage();
    const hasMedia = msg.media || (replyMsg?.media);
    const useVision = hasMedia;

    if (useVision) {
      await handleVisionChat(msg, args, replyMsg || null);
    } else {
      await handleTextChat(msg, args, replyMsg || null);
    }

  } catch (error: any) {
    const errorMsg = Utils.handleError(error, 'AI处理', {
      logLevel: 'error',
      showTechnicalDetails: false
    });
    await msg.edit({ text: errorMsg });
    await sleep(10000);
    try {
      await msg.delete();
    } catch (deleteError: any) {
      console.warn('[AI] 删除错误消息失败:', deleteError?.message);
    }
  }
}

/**
 * AI多服务商通用插件类
 */
class AiPlugin extends Plugin {
  description: string = `🤖 AI 多服务商通用插件
支持 Google Gemini、OpenAI、Anthropic Claude、DeepSeek、xAI Grok 等多个AI服务商，提供统一的AI服务接口和灵活的服务商选择功能。

━━━ 核心功能 ━━━
• <code>ai [query]</code> - 与AI模型聊天对话（默认功能，支持图片识别）
• <code>ai search [query]</code> - 使用AI增强的Google搜索
• <code>ai image [prompt]</code> - 生成AI图片
• <code>ai tts [text]</code> - 文本转语音
• <code>ai audio [query]</code> - 聊天对话并转换为语音回答
• <code>ai searchaudio [query]</code> - 搜索并转换为语音回答

━━━ 服务商管理 ━━━
• <code>ai apikey &lt;provider&gt; &lt;密钥&gt;</code> - 设置服务商API密钥
  支持的服务商: gemini, openai, claude, deepseek, grok, thirdparty
• <code>ai select &lt;provider&gt;</code> - 选择使用的AI服务商
  支持: gemini, openai, claude, deepseek, grok, thirdparty
• <code>ai baseurl thirdparty &lt;地址&gt;</code> - 设置第三方API基础URL
• <code>ai thirdparty compat &lt;type&gt;</code> - 设置第三方API兼容模式
  支持: openai, gemini, claude, deepseek, grok
• <code>ai status</code> - 检测所有服务商状态和当前活跃配置
• <code>ai settings</code> - 显示完整配置信息

━━━ 模型管理 ━━━
• <code>ai model list</code> - 显示当前模型配置和可用模型
• <code>ai model set [chat|search|image|tts] &lt;名称&gt;</code> - 手动设置各类型模型
• <code>ai model auto</code> - 自动匹配第三方API可用模型
• <code>ai chatmodel &lt;模型名&gt;</code> - 设置聊天模型（快捷方式）
• <code>ai searchmodel &lt;模型名&gt;</code> - 设置搜索模型（快捷方式）
• <code>ai imagemodel &lt;模型名&gt;</code> - 设置图片生成模型（快捷方式）
• <code>ai ttsmodel &lt;模型名&gt;</code> - 设置TTS模型（快捷方式）

━━━ 语音配置 ━━━
• <code>ai ttsvoice &lt;语音名&gt;</code> - 设置TTS语音
• <code>ai ttsvoice list</code> - 列出所有可用的TTS音色（30种音色）
• 支持自动语音匹配，根据TTS模型自动选择最佳音色

━━━ 提示词管理 ━━━
• <code>ai prompt list</code> - 列出所有已保存的系统提示词
• <code>ai prompt add &lt;名称&gt; &lt;内容&gt;</code> - 添加新的系统提示词
• <code>ai prompt del &lt;名称&gt;</code> - 删除系统提示词
• <code>ai prompt set [chat|search|tts] &lt;名称&gt;</code> - 为不同功能设置激活的系统提示词
• <code>ai prompt show &lt;名称&gt;</code> - 显示指定提示词内容

━━━ 对话上下文 ━━━
• <code>ai context on</code> - 启用对话上下文记忆
• <code>ai context off</code> - 禁用对话上下文记忆（默认）
• <code>ai context clear</code> - 清除对话历史记录
• <code>ai context show</code> - 显示当前对话历史
• 支持跨会话上下文保持，重启后自动恢复

━━━ Telegraph集成 ━━━
• <code>ai telegraph on</code> - 启用Telegraph长文章发布
• <code>ai telegraph off</code> - 禁用Telegraph集成（默认）
• <code>ai telegraph limit &lt;数量&gt;</code> - 设置Telegraph文章字符限制（0表示无限制）
• <code>ai telegraph list</code> - 列出已创建的Telegraph文章
• <code>ai telegraph del [id|all]</code> - 删除指定或全部Telegraph文章
• 当AI回答超过设定长度时自动创建Telegraph文章

━━━ 其他设置 ━━━
• <code>ai maxtokens &lt;数量&gt;</code> - 设置最大输出token数（0表示无限制）
• <code>ai collapse on|off</code> - 开启或关闭折叠引用显示
• <code>ai config default</code> - 重置所有配置到默认状态

━━━ 高级功能 ━━━
• 多服务商支持：灵活切换不同AI服务商，满足不同需求
• 自动模型分配：根据API响应自动匹配最佳模型配置
• 多格式支持：支持文本、图片、音频等多种输入输出格式
• 安全防护：自动过滤敏感信息，保护API密钥安全
• 配置持久化：所有设置自动保存，重启后完整恢复

━━━ 使用说明 ━━━
1. 首次使用需设置至少一个服务商的API密钥
2. 使用 ai select 命令选择要使用的服务商
3. 支持回复消息进行对话，自动识别图片内容
4. 支持自动模型匹配，简化第三方API配置
5. 所有配置持久化保存，重启后自动恢复
6. 支持多种兼容模式，轻松接入各类第三方API服务`;

  cmdHandlers: Record<string, (msg: Api.Message) => Promise<void>> = {
    ai: handleAIRequest,
  };
}

export default new AiPlugin();
