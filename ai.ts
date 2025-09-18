import { Plugin } from "@utils/pluginBase";
import { Api } from "telegram";
import axios from "axios";
import { JSONFilePreset } from "lowdb/node";
import * as path from "path";
import * as fs from "fs";
import { createDirectoryInAssets } from "@utils/pathHelpers";

// ---- storage ----
type Provider = { apiKey: string; baseUrl: string };
type Compat = "openai" | "gemini" | "claude";
type Models = { chat: string; search: string; image: string; tts: string; voice: string };
type Telegraph = { enabled: boolean; limit: number; token: string; posts: { title: string; url: string; createdAt: string }[] };
type DB = { providers: Record<string, Provider>; compat: Record<string, Compat>; models: Models; contextEnabled: boolean; collapse: boolean; telegraph: Telegraph; histories: Record<string, { role: string; content: string }[]> };

const MAX_MSG = 4096;
const trimBase = (u: string) => u.replace(/\/$/, "");
const html = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const nowISO = () => new Date().toISOString();

class Store {
  static db: any = null;
  static data: DB = {
    providers: {},
    compat: {},
    models: { chat: "", search: "", image: "", tts: "", voice: "" },
    contextEnabled: false,
    collapse: false,
    telegraph: { enabled: false, limit: 0, token: "", posts: [] },
    histories: {}
  };
  static baseDir: string = "";
  static file: string = "";
  static async init() {
    if (this.db) return;
    this.baseDir = createDirectoryInAssets("ai");
    this.file = path.join(this.baseDir, "config.json");
    this.db = await JSONFilePreset<DB>(this.file, {
      providers: {}, compat: {},
      models: { chat: "", search: "", image: "", tts: "", voice: "" },
      contextEnabled: false, collapse: false,
      telegraph: { enabled: false, limit: 0, token: "", posts: [] },
      histories: {}
    });
    this.data = this.db.data;
  }
  static async write() { await this.db.write(); }
}

// ---- helpers ----
function applyWrap(s: string, collapse?: boolean) { 
  if (!collapse) return s; 
  // If content already uses blockquote-based collapsible style, avoid double-wrapping with spoiler
  if (s.includes("<blockquote")) return s; 
  return `<span class="tg-spoiler">${s}</span>`; 
}
// Ensure footer is not collapsed: append outside spoiler via sendLong helpers
async function sendLong(msg: Api.Message, text: string, opts?: { collapse?: boolean }, postfix?: string) {
  const PAGE_EXTRA = 32; const WRAP_EXTRA = opts?.collapse ? 64 : 0;
  const parts = splitMessage(text, PAGE_EXTRA + WRAP_EXTRA);
  if (parts.length === 1) { await msg.edit({ text: applyWrap(parts[0], opts?.collapse) + (postfix || ""), parseMode: "html" }); return; }
  await msg.edit({ text: applyWrap(parts[0] + `\n\n📄 (1/${parts.length})`, opts?.collapse), parseMode: "html" });
  for (let i = 1; i < parts.length; i++) {
    const isLast = i === parts.length - 1;
    const chunkText = applyWrap(parts[i] + `\n\n📄 (${i + 1}/${parts.length})`, opts?.collapse) + (isLast ? (postfix || "") : "");
    await msg.reply({ message: chunkText, parseMode: "html" });
  }
}
async function sendLongReply(msg: Api.Message, replyToId: number, text: string, opts?: { collapse?: boolean }, postfix?: string) {
  const PAGE_EXTRA = 32; const WRAP_EXTRA = opts?.collapse ? 64 : 0;
  const parts = splitMessage(text, PAGE_EXTRA + WRAP_EXTRA);
  if (!msg.client) return;
  const peer = msg.peerId;
  if (parts.length === 1) { await msg.client.sendMessage(peer, { message: applyWrap(parts[0], opts?.collapse) + (postfix || ""), parseMode: "html", replyTo: replyToId }); return; }
  await msg.client.sendMessage(peer, { message: applyWrap(parts[0] + `\n\n📄 (1/${parts.length})`, opts?.collapse), parseMode: "html", replyTo: replyToId });
  for (let i = 1; i < parts.length; i++) {
    const isLast = i === parts.length - 1;
    const chunkText = applyWrap(parts[i] + `\n\n📄 (${i + 1}/${parts.length})`, opts?.collapse) + (isLast ? (postfix || "") : "");
    await msg.client.sendMessage(peer, { message: chunkText, parseMode: "html", replyTo: replyToId });
  }
}
function extractText(m: Api.Message | null | undefined): string {
  if (!m) return "";
  const anyM: any = m as any;
  return (anyM.message || anyM.text || anyM.caption || "");
}
function splitMessage(text: string, reserve = 0): string[] {
  const limit = Math.max(1, MAX_MSG - Math.max(0, reserve));
  if (text.length <= limit) return [text];
  const parts: string[] = [];
  let cur = "";
  for (const line of text.split("\n")) {
    if (line.length > limit) {
      if (cur) { parts.push(cur); cur = ""; }
      for (let i = 0; i < line.length; i += limit) parts.push(line.slice(i, i + limit));
      continue;
    }
    const next = cur ? cur + "\n" + line : line;
    if (next.length > limit) { parts.push(cur); cur = line; } else { cur = next; }
  }
  if (cur) parts.push(cur);
  return parts;
}
function detectCompat(name: string, model: string, baseUrl: string): Compat {
  const m = (model || "").toLowerCase(); const host = (baseUrl || "").toLowerCase();
  if (/claude/.test(m) || /anthropic/.test(host)) return "claude";
  if (/gemini|google/.test(m) || /generativelanguage/.test(host)) return "gemini";
  return "openai";
}
function pick(kind: keyof Models): { provider: string; model: string } | null {
  const s = Store.data.models[kind]; if (!s) return null; const i = s.indexOf(" "); if (i <= 0) return null;
  const provider = s.slice(0, i); const model = s.slice(i + 1);
  return { provider, model };
}
function providerOf(name: string): Provider | null { return Store.data.providers[name] || null; }
function footer(model: string, extra?: string) { const src = model.toLowerCase().includes("claude") ? "Anthropic Claude" : model.toLowerCase().includes("gemini") ? "Google Gemini" : "OpenAI"; return `\n\n<i>Powered by ${src}${extra ? " " + extra : ""}</i>`; }
function ensureDir() { if (!fs.existsSync(Store.baseDir)) fs.mkdirSync(Store.baseDir, { recursive: true }); }
function chatIdStr(msg: Api.Message) { return String((msg.peerId as any)?.channelId || (msg.peerId as any)?.userId || (msg.peerId as any)?.chatId || "global"); }
function histFor(id: string) { return Store.data.histories[id] || []; }
function pushHist(id: string, role: string, content: string) {
  if (!Store.data.histories[id]) Store.data.histories[id] = [];
  Store.data.histories[id].push({ role, content });
  const h = Store.data.histories[id];
  while (h.length > 20) h.shift();
}
// 添加更精细的文本清洗与HTML安全化，并将以 "> " 开头的行转换为 blockquote
function cleanTextBasic(t: string): string {
  if (!t) return "";
  return t
    .replace(/\uFEFF/g, "")
    .replace(/[\uFFFC\uFFFF\uFFFE]/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\u200B|\u200C|\u200D|\u2060/g, "")
    .normalize('NFKC');
}
function escapeAndFormatForTelegram(raw: string): string {
  const cleaned = cleanTextBasic(raw || "");
  // 先进行HTML转义，保证安全
  let escaped = html(cleaned);
  // 将以 "> " 开头的行（已转义为 &gt; ）替换为 blockquote
  escaped = escaped.replace(/^&gt;\s?(.+)$/gm, '<blockquote>$1</blockquote>');
  return escaped;
}
// Helper to decide if an error indicates missing route; used for /v1beta -> /v1 fallback
function isRouteError(err: any): boolean {
  const s = err?.response?.status;
  const txt = String(err?.response?.data || err?.message || "").toLowerCase();
  return s === 404 || s === 405 || (s === 400 && /(unknown|not found|invalid path|no route)/.test(txt));
}
// 通用：Gemini /v1beta → /v1 回退请求助手
async function geminiRequestWithFallback(p: Provider, path: string, axiosConfig: any): Promise<any> {
  const base = trimBase(p.baseUrl);
  try {
    const r = await axios({ url: base + `/v1beta${path}`, ...axiosConfig });
    return r.data;
  } catch (err) {
    if (!isRouteError(err)) throw err;
    const r2 = await axios({ url: base + `/v1${path}`, ...axiosConfig });
    return r2.data;
  }
}
function formatQA(qRaw: string, aRaw: string, footerHtml?: string): string {
  const expandAttr = Store.data.collapse ? " expandable" : "";
  const qEsc = escapeAndFormatForTelegram(qRaw);
  const aEsc = escapeAndFormatForTelegram(aRaw);
  const Q = `<b>Q:</b>\n<blockquote${expandAttr}>${qEsc}</blockquote>`;
  const A = `<b>A:</b>\n<blockquote${expandAttr}>${aEsc}</blockquote>`;
  // Do not append footer here; it will be added outside spoiler by sendLong helpers
  return `${Q}\n\n${A}`;
}

// ---- telegraph (minimal) ----
function toNodes(text: string) { return JSON.stringify(text.split("\n\n").map(p => ({ tag: "p", children: [p] }))); }
async function ensureTGToken(): Promise<string> {
  if (Store.data.telegraph.token) return Store.data.telegraph.token;
  const resp = await axios.post("https://api.telegra.ph/createAccount", null, { params: { short_name: "TeleBoxAI", author_name: "TeleBox" } });
  const t = resp.data?.result?.access_token || ""; Store.data.telegraph.token = t; await Store.write(); return t;
}
async function createTGPage(title: string, text: string): Promise<string | null> {
  try {
    const token = await ensureTGToken(); if (!token) return null;
    const resp = await axios.post("https://api.telegra.ph/createPage", null, {
      params: { access_token: token, title, content: toNodes(text), return_content: false }
    });
    return resp.data?.result?.url || null;
  } catch { return null; }
}

// ---- provider adapters ----
async function chatOpenAI(p: Provider, model: string, msgs: { role: string; content: string }[], maxTokens?: number) {
  const url = trimBase(p.baseUrl) + "/v1/chat/completions";
  const r = await axios.post(url, { model, messages: msgs, max_tokens: maxTokens || 1024 }, { headers: { Authorization: `Bearer ${p.apiKey}` } });
  return r.data?.choices?.[0]?.message?.content || "";
}
async function chatClaude(p: Provider, model: string, msgs: { role: string; content: string }[], maxTokens?: number) {
  const url = trimBase(p.baseUrl) + "/v1/messages";
  const r = await axios.post(url, { model, max_tokens: maxTokens || 1024, messages: msgs.map(m => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.content })) }, { headers: { "x-api-key": p.apiKey, "anthropic-version": "2023-06-01" } });
  return r.data?.content?.[0]?.text || r.data?.message?.content?.[0]?.text || "";
}
async function chatGemini(p: Provider, model: string, msgs: { role: string; content: string }[]) {
  const path = `/models/${encodeURIComponent(model)}:generateContent`;
  const data = await geminiRequestWithFallback(p, path, {
    method: "POST",
    data: { contents: [{ parts: msgs.map(m => ({ text: (m.role === "user" ? "" : "") + m.content })) }] },
    params: { key: p.apiKey }
  });
  const parts = data?.candidates?.[0]?.content?.parts || [];
  return parts.map((x: any) => x.text || "").join("");
}

// 新增：带图片的聊天（OpenAI）
async function chatVisionOpenAI(p: Provider, model: string, imageB64: string, prompt?: string) {
  const url = trimBase(p.baseUrl) + "/v1/chat/completions";
  const content = [
    { type: "text", text: prompt || "用中文描述此图片" },
    { type: "image_url", image_url: { url: `data:image/png;base64,${imageB64}` } }
  ];
  const r = await axios.post(
    url,
    { model, messages: [{ role: "user", content }] },
    { headers: { Authorization: `Bearer ${p.apiKey}` } }
  );
  return r.data?.choices?.[0]?.message?.content || "";
}

// 新增：带图片的聊天（Gemini）
async function chatVisionGemini(p: Provider, model: string, imageB64: string, prompt?: string) {
  const path = `/models/${encodeURIComponent(model)}:generateContent`;
  const data = await geminiRequestWithFallback(p, path, {
    method: "POST",
    data: {
      contents: [
        {
          role: "user",
          parts: [
            { inlineData: { mimeType: "image/png", data: imageB64 } },
            { text: prompt || "用中文描述此图片" }
          ]
        }
      ]
    },
    params: { key: p.apiKey }
  });
  const parts = data?.candidates?.[0]?.content?.parts || [];
  return parts.map((x: any) => x.text || "").join("");
}
// 统一的视觉聊天入口：根据 compat 路由到具体实现
async function chatVision(p: Provider, compat: string, model: string, imageB64: string, prompt?: string): Promise<string> {
  if (compat === "openai") return chatVisionOpenAI(p, model, imageB64, prompt);
  if (compat === "gemini") return chatVisionGemini(p, model, imageB64, prompt);
  // 其他不支持视觉的服务商：退化为纯文本描述
  return chatOpenAI(p, model, [{ role: "user", content: prompt || "描述这张图片" } as any] as any);
}

// 新增：带图片的聊天（Gemini）
async function imageOpenAI(p: Provider, model: string, prompt: string): Promise<string> {
  const url = trimBase(p.baseUrl) + "/v1/images/generations";
  try {
    const r = await axios.post(
      url,
      { model, prompt, response_format: "b64_json", size: "1024x1024", n: 1 },
      { headers: { Authorization: `Bearer ${p.apiKey}` }, timeout: 60000 }
    );
    const b64 = r.data?.data?.[0]?.b64_json || "";
    if (!b64) throw new Error("服务无有效输出");
    return b64;
  } catch (err: any) {
    const status = err?.response?.status;
    const body = err?.response?.data;
    const msg = body?.error?.message || body?.message || err?.message || String(err);
    throw new Error(`图片生成失败(${status || "网络错误"}): ${msg}`);
  }
}
async function ttsOpenAI(p: Provider, model: string, input: string, voice: string): Promise<Buffer> {
  const url = trimBase(p.baseUrl) + "/v1/audio/speech";
  const r = await axios.post(url, { model, input, voice, format: "ogg" }, { headers: { Authorization: `Bearer ${p.apiKey}` }, responseType: "arraybuffer" });
  return Buffer.from(r.data);
}
// Gemini image
async function imageGemini(p: Provider, model: string, prompt: string): Promise<{ image?: Buffer; text?: string; mime?: string }> {
  const path = `/models/${encodeURIComponent(model)}:generateContent`;
  try {
    const data = await geminiRequestWithFallback(p, path, {
      method: "POST",
      data: {
        contents: [ { role: "user", parts: [{ text: prompt }] } ],
        generationConfig: { responseModalities: ["TEXT", "IMAGE"] }
      },
      params: { key: p.apiKey }
    });
    const parts = data?.candidates?.[0]?.content?.parts || [];
    let text: string | undefined; let image: Buffer | undefined; let mime: string | undefined;
    for (const part of parts) {
      if ((part as any)?.text) text = String((part as any).text);
      if ((part as any)?.inlineData?.data) { image = Buffer.from((part as any).inlineData.data, "base64"); mime = (part as any).inlineData.mimeType || "image/png"; }
    }
    return { image, text, mime };
  } catch {
    return {};
  }
}
// Gemini TTS
async function ttsGemini(p: Provider, model: string, input: string, voiceName?: string): Promise<{ audio?: Buffer; mime?: string }> {
  const path = `/models/${encodeURIComponent(model)}:generateContent`;
  const voice = voiceName || "Kore";
  try {
    const data = await geminiRequestWithFallback(p, path, {
      method: "POST",
      data: {
        contents: [ { role: "user", parts: [{ text: input }] } ],
        generationConfig: {
          responseModalities: ["AUDIO"],
          speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: voice } } }
        }
      },
      params: { key: p.apiKey },
      timeout: 60000
    });
    const candidate = data?.candidates?.[0];
    const part = candidate?.content?.parts?.[0];
    if (part?.inlineData?.data) {
      const audio = Buffer.from(part.inlineData.data, "base64");
      const mime = part.inlineData.mimeType || "audio/wav";
      return { audio, mime };
    }
    return {};
  } catch {
    return {};
  }
}
// Helper: list Gemini models with /v1beta -> /v1 fallback
async function listGeminiModels(p: Provider): Promise<string[]> {
  const base = trimBase(p.baseUrl);
  try {
    const r = await axios.get(base + "/v1beta/models", { params: { key: p.apiKey } });
    return (r.data?.models || []).map((x: any) => String(x.name || '').replace(/^models\//, ''));
  } catch (err: any) {
    if (!isRouteError(err)) throw err;
    const r2 = await axios.get(base + "/v1/models", { params: { key: p.apiKey } });
    return (r2.data?.models || []).map((x: any) => String(x.name || '').replace(/^models\//, ''));
  }
}
async function callChat(kind: "chat" | "search", text: string, msg: Api.Message): Promise<{ content: string; model: string }> {
  const m = pick(kind); if (!m) throw new Error(`未设置${kind}模型，请先配置`);
  const p = providerOf(m.provider); if (!p) throw new Error(`服务商 ${m.provider} 未配置`);
  const compat = Store.data.compat[m.provider] || detectCompat(m.provider, m.model, p.baseUrl);
  const id = chatIdStr(msg); const msgs: { role: string; content: string }[] = [];
  if (Store.data.contextEnabled) msgs.push(...histFor(id));
  msgs.push({ role: "user", content: text });
  let out = "";
  if (compat === "openai") out = await chatOpenAI(p, m.model, msgs);
  else if (compat === "claude") out = await chatClaude(p, m.model, msgs);
  else out = await chatGemini(p, m.model, msgs);
  if (Store.data.contextEnabled) { pushHist(id, "user", text); pushHist(id, "assistant", out); await Store.write(); }
  return { content: out, model: m.model };
}

// ---- plugin ----
const help = `🔧 <b>🤖 多服务商智能AI助手</b>
📝 <b>特性</b>
兼容 Google Gemini、OpenAI、Anthropic Claude 标准接口，统一指令，一处配置，多处可用。
✨ <b>亮点</b>
• 🎯 统一写法：<b>服务商 模型</b>（示例：<code>openai gpt-4o</code>、<code>claude claude-3-sonnet</code>、<code>gemini gemini-pro</code>）
• 🔀 模型混用：对话 / 搜索 / 图片 / 语音 可分别指定不同服务商的最佳模型
• 🧠 可选上下文记忆、📰 长文自动发布 Telegraph、🧾 消息折叠显示

💬 <b>对话</b>
<code>ai chat [问题]</code>
• 示例：<code>ai chat 你好，帮我简单介绍一下你</code>
• 示例：<code>ai chat 写一个 Python 斐波那契函数</code>
• 支持多轮对话（可执行 <code>ai context on</code> 开启记忆）
• 支持回复已有消息继续对话
• 超长回答可自动转 Telegraph

🔍 <b>搜索</b>
<code>ai search [查询]</code>
• 示例：<code>ai search 2024 年 AI 技术进展</code>

🖼️ <b>图片</b>
<code>ai image [描述]</code>
• 示例：<code>ai image 未来城市的科幻夜景</code>

🎵 <b>文本转语音</b>
<code>ai tts [文本]</code>
• 示例：<code>ai tts 你好，这是一次语音合成测试</code>

🎤 <b>语音回答</b>
<code>ai audio [问题]</code>
• 示例：<code>ai audio 用 30 秒介绍人工智能的发展</code>

🔍🎤 <b>搜索并语音回答</b>
<code>ai searchaudio [查询]</code>
• 示例：<code>ai searchaudio 2024 年最新科技趋势</code>

💭 <b>对话上下文</b>
<code>ai context on|off|show|del</code>

📋 <b>消息折叠</b>
<code>ai collapse on|off</code>

📰 <b>Telegraph 长文</b>
<code>ai telegraph on|off|limit &lt;数量&gt;|list|del &lt;n|all&gt;</code>
• limit &lt;数量&gt;：设置字数阈值（0 表示不限制）
• 自动创建 / 管理 / 删除 Telegraph 文章

⚙️ <b>模型管理</b>
<code>ai model list</code> - 查看当前模型配置
<code>ai model chat|search|image|tts [服务商] [模型]</code> - 设置各功能模型
<code>ai model voice [音色名]</code> - 设置 TTS 音色（直接填音色名）
<code>ai model default</code> - 清空所有功能模型
<code>ai model auto</code> - 智能分配 chat/search/image/tts 与音色

🔧 <b>配置管理</b>
<code>ai config add [服务商] [API密钥] [BaseURL]</code>
<code>ai config list</code>
<code>ai config model [服务商]</code> - 查看该服务商可用模型
<code>ai config update [服务商] [apikey|baseurl] [值]</code>
<code>ai config remove [服务商|all]</code>

📝 <b>配置示例</b>
• OpenAI：<code>ai config add openai sk-proj-xxx https://api.openai.com</code>
• DeepSeek：<code>ai config add deepseek sk-xxx https://api.deepseek.com</code>
• Grok：<code>ai config add grok xai-xxx https://api.x.ai</code>
• Claude：<code>ai config add claude sk-ant-xxx https://api.anthropic.com</code>
• Gemini：<code>ai config add gemini AIzaSy-xxx https://generativelanguage.googleapis.com</code>

📖 使用 <code>ai help short</code> 查看简化指令`;

const helpShort = `🔧 <b>AI智能助手简令说明</b>
常用指令（简）
- 对话：<code>ai [问题]</code>
- 搜索：<code>ai s [查询]</code>
- 图片：<code>ai img [描述]</code>
- 语音：<code>ai v [文本]</code>
- 回答为语音：<code>ai a [问题]</code> / 搜索并语音：<code>ai sa [查询]</code>
- 上下文：<code>ai ctx on|off</code>
- 模型：<code>ai m chat|search|image|tts [服务商] [模型]</code>
- 配置：<code>ai c add [服务商] [API密钥] [BaseURL]</code>

别名：s=search, img/i=image, v/voice=tts, a=audio, sa=searchaudio, ctx=context, fold=collapse, cfg/c=config, m=model, h=help`;

class AiPlugin extends Plugin {
  description: string = `多服务商 AI 插件\n\n${help}`;
  cmdHandlers = {
    ai: async (msg: Api.Message) => {
      await Store.init(); ensureDir();
      const text = (msg as any).text || (msg as any).message || ""; const lines = text.trim().split(/\r?\n/g); const parts = (lines[0] || "").split(/\s+/);
      const [, sub, ...args] = parts; const subl = (sub || "").toLowerCase();
      // aliases: s,img,i,voice,v,a,sa,ctx,fold,cfg,c,m,h
      const aliasMap: Record<string, string> = {
      s: "search",
      img: "image",
      i: "image",
      voice: "tts",
      v: "tts",
      a: "audio",
      sa: "searchaudio",
      ctx: "context",
      fold: "collapse",
      cfg: "config",
      c: "config",
      m: "model",
      h: "help",
      };
      const subn = aliasMap[subl] || subl;
      try {
        if (!subn || subn === "help") {
          const a0 = (args[0] || "").toLowerCase();
          const showShort = subl === "h" || a0 === "short" || a0 === "-s";
          await sendLong(msg, showShort ? helpShort : help);
          return;
        }
        // config
        if (subn === "config") {
          const a0 = (args[0] || "").toLowerCase();
          if (a0 === "add") {
            const [name, key, baseUrl] = [args[1], args[2], args[3]];
            if (!name || !key || !baseUrl) { await msg.edit({ text: "❌ 参数不足", parseMode: "html" }); return; }
            Store.data.providers[name] = { apiKey: key, baseUrl }; Store.data.compat[name] = detectCompat(name, "", baseUrl); await Store.write();
            await msg.edit({ text: `✅ 已添加 <b>${html(name)}</b>`, parseMode: "html" }); return;
          }
          if (a0 === "list") {
            const list = Object.entries(Store.data.providers).map(([n, v]) => `• <b>${html(n)}</b> - key:${v.apiKey ? "✅" : "❌"} base:${html(v.baseUrl)}`).join("\n") || "(空)";
            await sendLong(msg, `📦 <b>已配置服务商</b>\n\n${list}`); return;
          }
          if (a0 === "model") {
            const name = args[1]; const p = name && providerOf(name);
            if (!p) { await msg.edit({ text: "❌ 未找到服务商", parseMode: "html" }); return; }
            const compat = Store.data.compat[name] || detectCompat(name, "", p.baseUrl);
            let models: string[] = [];
            try {
              if (compat === "openai") { const r = await axios.get(trimBase(p.baseUrl) + "/v1/models", { headers: { Authorization: `Bearer ${p.apiKey}` } }); models = (r.data?.data || []).map((x: any) => x.id); }
              else if (compat === "claude") { const r = await axios.get(trimBase(p.baseUrl) + "/v1/models", { headers: { "x-api-key": p.apiKey, "anthropic-version": "2023-06-01" } }); models = (r.data?.data || r.data?.models || []).map((x: any) => x.id || x.slug || x.name); }
              else { models = await listGeminiModels(p); }
            } catch (e: any) { await msg.edit({ text: `❌ 获取模型失败: ${html(e.message || "")}`, parseMode: "html" }); return; }
            const buckets = { chat: [] as string[], search: [] as string[], image: [] as string[], tts: [] as string[] };
            for (const m of models) {
              const ml = String(m).toLowerCase();
              if (/image|dall|sd|gpt-image/.test(ml)) buckets.image.push(m);
              else if (/tts|voice|audio\.speech/.test(ml)) buckets.tts.push(m);
              else { buckets.chat.push(m); buckets.search.push(m); }
            }
            const voiceList = compat === "gemini" ? ["Kore"] : compat === "openai" ? ["alloy","verse","aria","nova"] : [];
            const txt = `🧰 <b>${html(name)}</b> 模型\n\n<b>chat:</b>\n${buckets.chat.join("\n") || "(无)"}\n\n<b>search:</b>\n${buckets.search.join("\n") || "(无)"}\n\n<b>image:</b>\n${buckets.image.join("\n") || "(无)"}\n\n<b>tts:</b>\n${buckets.tts.join("\n") || "(无)"}\n\n<b>voices:</b>\n${voiceList.join(", ") || "(无)"}`;
            await sendLong(msg, txt); return;
          }
          if (a0 === "update") {
            const name = args[1]; const p = name && providerOf(name);
            if (!p) { await msg.edit({ text: "❌ 未找到服务商", parseMode: "html" }); return; }
            const replyVal = extractText(await msg.getReplyMessage()).trim();
            const fieldOrVal = args[2] || "";
            const lower = fieldOrVal.toLowerCase();
            if (lower === "apikey" || lower === "baseurl") {
              const val = (args.slice(3).join(" ") || replyVal).trim();
              if (!val) { await msg.edit({ text: "❌ 参数不足", parseMode: "html" }); return; }
              if (lower === "apikey") p.apiKey = val; else { p.baseUrl = val; Store.data.compat[name] = detectCompat(name, "", val); }
            } else {
              const valGuess = ([fieldOrVal, ...args.slice(3)]).join(" ").trim() || replyVal;
              if (!valGuess) { await msg.edit({ text: "❌ 参数不足", parseMode: "html" }); return; }
              if (/^https?:\/\//i.test(valGuess)) { p.baseUrl = valGuess; Store.data.compat[name] = detectCompat(name, "", valGuess); }
              else { p.apiKey = valGuess; }
            }
            Store.data.providers[name] = p; await Store.write(); await msg.edit({ text: `✅ 已更新 <b>${html(name)}</b>`, parseMode: "html" }); return;
          }
          if (a0 === "remove") {
            const target = args[1];
            if (!target) { await msg.edit({ text: "❌ 参数不足", parseMode: "html" }); return; }
            if (target.toLowerCase() === "all") {
              Store.data.providers = {}; Store.data.compat = {}; Store.data.models = { chat: "", search: "", image: "", tts: "", voice: "" }; await Store.write();
              await msg.edit({ text: "✅ 已清空所有服务商与模型设置", parseMode: "html" }); return;
            } else {
              delete Store.data.providers[target]; delete Store.data.compat[target];
              for (const k of ["chat","search","image","tts"] as (keyof Models)[]) {
                if ((Store.data.models[k] || "").startsWith(target + " ")) Store.data.models[k] = "";
              }
              await Store.write(); await msg.edit({ text: `✅ 已移除 <b>${html(target)}</b>`, parseMode: "html" }); return;
            }
          }
          await msg.edit({ text: "❌ 未知 config 子命令", parseMode: "html" }); return;
        }
        // model
        if (subn === "model") {
          const a0 = (args[0] || "").toLowerCase();
          if (a0 === "list") {
            const m = Store.data.models; const txt = `⚙️ <b>当前模型</b>\n\nchat: <code>${html(m.chat || "")}</code>\nsearch: <code>${html(m.search || "")}</code>\nimage: <code>${html(m.image || "")}</code>\ntts: <code>${html(m.tts || "")}</code>\nvoice: <code>${html(m.voice || "")}</code>`; await msg.edit({ text: txt, parseMode: "html" }); return;
          }
          if (a0 === "voice") { Store.data.models.voice = args[1] || ""; await Store.write(); await msg.edit({ text: `✅ 语音音色: <b>${html(Store.data.models.voice || "默认")}</b>`, parseMode: "html" }); return; }
          if (a0 === "default") { Store.data.models = { chat: "", search: "", image: "", tts: "", voice: "" }; await Store.write(); await msg.edit({ text: "✅ 已清空所有功能模型设置", parseMode: "html" }); return; }
          if (a0 === "auto") {
            const entries = Object.entries(Store.data.providers);
            if (!entries.length) { await msg.edit({ text: "❌ 请先使用 ai config add 添加服务商", parseMode: "html" }); return; }
            const compatOf = (n: string): Compat => (Store.data.compat[n] || detectCompat(n, "", Store.data.providers[n].baseUrl));
            const modelsBy: Record<string, string[]> = {};
            for (const [n, p] of entries) {
              const c = compatOf(n);
              try {
                if (c === "openai") { const r = await axios.get(trimBase(p.baseUrl) + "/v1/models", { headers: { Authorization: `Bearer ${p.apiKey}` } }); modelsBy[n] = (r.data?.data || []).map((x: any) => x.id); }
                else if (c === "claude") { const r = await axios.get(trimBase(p.baseUrl) + "/v1/models", { headers: { "x-api-key": p.apiKey, "anthropic-version": "2023-06-01" } }); modelsBy[n] = (r.data?.data || r.data?.models || []).map((x: any) => x.id || x.slug || x.name); }
                else { modelsBy[n] = await listGeminiModels(p); }
              } catch { modelsBy[n] = []; }
            }
            const chooseChat = (c: Compat, list: string[]) => c === "openai" ? (list.find(m => /gpt-4o-mini|gpt-4o/i.test(m)) || list[0])
              : c === "claude" ? (list.find(m => /claude-3\.5-sonnet|claude-3-opus|claude-3/i.test(m)) || list[0])
              : (list.find(m => /gemini-2\.0-flash|gemini-1\.5-flash/i.test(m)) || list[0]);
            const chooseImage = (c: Compat, list: string[]) => c === "openai" ? (list.find(m => /gpt-image-1/i.test(m)) || "")
              : c === "gemini" ? (list.find(m => /image-generation/i.test(m)) || "") : "";
            const chooseTTS = (c: Compat, list: string[]) => c === "openai" ? (list.find(m => /^tts-1/i.test(m)) || "")
              : c === "gemini" ? (list.find(m => /-tts/i.test(m)) || "") : "";
            const pickAcross = (order: Compat[], chooser: (c: Compat, list: string[]) => string) => {
              for (const t of order) {
                for (const [n] of entries) {
                  const c = compatOf(n); if (c !== t) continue; const m = chooser(c, modelsBy[n] || []); if (m) return { n, m, c } as { n: string; m: string; c: Compat };
                }
              }
              return null as any;
            };
            const chatSel = pickAcross(["openai","gemini","claude"], chooseChat);
            const searchSel = pickAcross(["openai","gemini","claude"], chooseChat);
            const imageSel = pickAcross(["openai","gemini"], chooseImage);
            const ttsSel = pickAcross(["openai","gemini"], chooseTTS);
            if (!chatSel) { await msg.edit({ text: "❌ 未找到可用 chat/search 模型", parseMode: "html" }); return; }
            Store.data.models.chat = `${chatSel.n} ${chatSel.m}`;
            Store.data.models.search = `${(searchSel || chatSel).n} ${(searchSel || chatSel).m}`;
            Store.data.models.image = imageSel ? `${imageSel.n} ${imageSel.m}` : "";
            Store.data.models.tts = ttsSel ? `${ttsSel.n} ${ttsSel.m}` : "";
            if (!Store.data.models.voice) { Store.data.models.voice = (ttsSel?.c === "gemini") ? "Kore" : (ttsSel?.c === "openai") ? "alloy" : ""; }
            await Store.write(); await msg.edit({ text: "✅ 已智能分配 chat/search/image/tts 与音色", parseMode: "html" }); return;
          }
          const kind = a0 as keyof Models; if (["chat","search","image","tts"].includes(kind)) {
            const [provider, ...mm] = args.slice(1); const model = (mm.join(" ") || "").trim();
            if (!provider || !model) { await msg.edit({ text: "❌ 参数不足", parseMode: "html" }); return; }
            if (!Store.data.providers[provider]) { await msg.edit({ text: "❌ 未知服务商", parseMode: "html" }); return; }
            (Store.data.models as any)[kind] = `${provider} ${model}`; await Store.write(); await msg.edit({ text: `✅ 已设置 ${kind}: <code>${html((Store.data.models as any)[kind])}</code>`, parseMode: "html" }); return;
          }
          await msg.edit({ text: "❌ 未知 model 子命令", parseMode: "html" }); return;
        }
        // context
        if (subn === "context") {
          const a0 = (args[0] || "").toLowerCase(); const id = chatIdStr(msg);
          if (a0 === "on") { Store.data.contextEnabled = true; await Store.write(); await msg.edit({ text: "✅ 已开启上下文", parseMode: "html" }); return; }
          if (a0 === "off") { Store.data.contextEnabled = false; await Store.write(); await msg.edit({ text: "✅ 已关闭上下文", parseMode: "html" }); return; }
          if (a0 === "show") { const items = histFor(id); const t = items.map(x => `${x.role}: ${html(x.content)}`).join("\n"); await sendLong(msg, t || "(空)"); return; }
          if (a0 === "del") { delete Store.data.histories[id]; await Store.write(); await msg.edit({ text: "✅ 已清空本会话上下文", parseMode: "html" }); return; }
          await msg.edit({ text: "❌ 未知 context 子命令", parseMode: "html" }); return;
        }
        // collapse
        if (subn === "collapse") { const a0 = (args[0] || "").toLowerCase(); Store.data.collapse = a0 === "on"; await Store.write(); await msg.edit({ text: `✅ 消息折叠: ${Store.data.collapse ? "开启" : "关闭"}`, parseMode: "html" }); return; }
        // telegraph
        if (subn === "telegraph") {
          const a0 = (args[0] || "").toLowerCase();
          if (a0 === "on") { Store.data.telegraph.enabled = true; await Store.write(); await msg.edit({ text: "✅ 已开启 telegraph", parseMode: "html" }); return; }
          if (a0 === "off") { Store.data.telegraph.enabled = false; await Store.write(); await msg.edit({ text: "✅ 已关闭 telegraph", parseMode: "html" }); return; }
          if (a0 === "limit") { const n = parseInt(args[1] || "0"); Store.data.telegraph.limit = isFinite(n) ? n : 0; await Store.write(); await msg.edit({ text: `✅ 阈值: ${Store.data.telegraph.limit}`, parseMode: "html" }); return; }
          if (a0 === "list") { const list = Store.data.telegraph.posts.map((p, i) => `${i + 1}. <a href="${p.url}">${html(p.title)}</a> ${p.createdAt}`).join("\n") || "(空)"; await sendLong(msg, `🧾 <b>Telegraph 列表</b>\n\n${list}`); return; }
          if (a0 === "del") { const t = (args[1] || "").toLowerCase(); if (t === "all") Store.data.telegraph.posts = []; else { const i = parseInt(args[1] || "0") - 1; if (i >= 0) Store.data.telegraph.posts.splice(i, 1); } await Store.write(); await msg.edit({ text: "✅ 操作完成", parseMode: "html" }); return; }
          await msg.edit({ text: "❌ 未知 telegraph 子命令", parseMode: "html" }); return;
        }
        // chat/search
        if (subn === "chat" || subn === "search") {
          const replyMsg = await msg.getReplyMessage();
          const isSearch = subn === "search";
          const plain = (args.join(" ") || "").trim();
          const repliedText = extractText(replyMsg).trim();
          const q = (plain || repliedText).trim();
          // 支持对图片消息回复进行视觉问答
          const hasImage = !!(replyMsg && (replyMsg as any).media);
          if (!q && !hasImage) { await msg.edit({ text: "❌ 请输入内容或回复一条消息", parseMode: "html" }); return; }
          await msg.edit({ text: "🔄 处理中...", parseMode: "html" });
          const m = pick(isSearch ? "search" : "chat"); if (!m) { await msg.edit({ text: `❌ 未设置 ${isSearch ? 'search' : 'chat'} 模型`, parseMode: "html" }); return; }
          const p = providerOf(m.provider); if (!p) { await msg.edit({ text: "❌ 服务商未配置", parseMode: "html" }); return; }
          const compat = Store.data.compat[m.provider] || detectCompat(m.provider, m.model, p.baseUrl);

          let content = ""; let usedModel = m.model;
          if (hasImage) {
            try {

              const raw = await msg.client?.downloadMedia(replyMsg as any);
              const buf: Buffer | undefined = typeof raw === 'string' ? Buffer.from(raw) : raw;
              if (!buf || !buf.length) { await msg.edit({ text: "❌ 无法下载被回复的媒体", parseMode: "html" }); return; }
              const b64 = buf.toString('base64');
              content = await chatVision(p, compat, m.model, b64, q);
            } catch (e: any) {
              await msg.edit({ text: `❌ 处理图片失败：${html(e?.message || String(e))}`, parseMode: "html" }); return;
            }
          } else {
            const res = await callChat(isSearch ? "search" : "chat", q, msg);
            content = res.content; usedModel = res.model;
          }

          const footTxt = footer(usedModel, isSearch ? "with Search" : "");
          const full = formatQA(q || "(图片)", content);
          const replyToId = replyMsg?.id || 0; // 不回复状态消息
          if (Store.data.telegraph.enabled && Store.data.telegraph.limit > 0 && full.length > Store.data.telegraph.limit) {
            const url = await createTGPage("TeleBox AI", content);
            if (url) {
              Store.data.telegraph.posts.unshift({ title: (q || "图片").slice(0, 30) || "AI", url, createdAt: nowISO() });
              Store.data.telegraph.posts = Store.data.telegraph.posts.slice(0, 10);
              await Store.write();
              if (replyToId) { await sendLongReply(msg, replyToId, `📰 <a href="${url}">内容较长，已创建 Telegraph</a>`, { collapse: Store.data.collapse }, footTxt); }
              else { await sendLong(msg, `📰 <a href="${url}">内容较长，已创建 Telegraph</a>`, { collapse: Store.data.collapse }, footTxt); }
              if (replyToId) { try { await msg.delete(); } catch {} }
               return;
            }
          }
          if (replyToId) { await sendLongReply(msg, replyToId, full, { collapse: Store.data.collapse }, footTxt); }
          else { await sendLong(msg, full, { collapse: Store.data.collapse }, footTxt); }
          if (replyToId) { try { await msg.delete(); } catch {} }
           return;
        }
        // image
        if (subn === "image") {
          const replyMsg = await msg.getReplyMessage();
          const prm = (args.join(" ") || "").trim() || extractText(replyMsg).trim();
          if (!prm) { await msg.edit({ text: "❌ 请输入提示词", parseMode: "html" }); return; }
          const m = pick("image"); if (!m) { await msg.edit({ text: "❌ 未设置 image 模型", parseMode: "html" }); return; }
          const p = providerOf(m.provider); if (!p) { await msg.edit({ text: "❌ 服务商未配置", parseMode: "html" }); return; }
          const compat = Store.data.compat[m.provider] || detectCompat(m.provider, m.model, p.baseUrl);
          await msg.edit({ text: "🎨 生成中...", parseMode: "html" });
          const replyToId = replyMsg?.id || 0;
          if (compat === "openai") {
            const b64 = await imageOpenAI(p, m.model, prm);
            if (!b64) { await msg.edit({ text: "❌ 图片生成失败：服务无有效输出", parseMode: "html" }); return; }
            const buf = Buffer.from(b64, "base64"); const file: any = Object.assign(buf, { name: "ai.png" });

            await msg.client?.sendFile(msg.peerId, { file, caption: `🖼️ ${html(prm)}` + footer(m.model), parseMode: "html", replyTo: replyToId || undefined });
            await msg.delete(); return;
          } else if (compat === "gemini") {
            const { image, text, mime } = await imageGemini(p, m.model, prm);
            if (image) {
              const ext = (mime || "image/png").includes("png") ? "png" : (mime || "").includes("jpeg") ? "jpg" : "png";
              const file: any = Object.assign(image, { name: `ai.${ext}` });

              await msg.client?.sendFile(msg.peerId, { file, caption: `🖼️ ${html(prm)}` + footer(m.model), parseMode: "html", replyTo: replyToId || undefined });
              await msg.delete(); return;
            }

            if (text) {
              const textOut = formatQA(prm, text);
              if (replyToId) { await sendLongReply(msg, replyToId, textOut, { collapse: Store.data.collapse }, footer(m.model)); }
              else { await sendLong(msg, textOut, { collapse: Store.data.collapse }, footer(m.model)); }
              await msg.delete(); return;
            }
            await msg.edit({ text: "❌ 图片生成失败：服务无有效输出", parseMode: "html" }); return;
          } else {
            await msg.edit({ text: "❌ 当前服务商不支持图片生成功能", parseMode: "html" }); return;
          }
        }
        // audio | searchaudio（先回答，再语音合成）
        if (subn === "audio" || subn === "searchaudio") {
          const replyMsg = await msg.getReplyMessage();
          const plain = (args.join(" ") || "").trim();
          const repliedText = extractText(replyMsg).trim();
          const q = (plain || repliedText).trim();
          if (!q) { await msg.edit({ text: "❌ 请输入内容或回复一条消息", parseMode: "html" }); return; }

          await msg.edit({ text: "🔄 处理中...", parseMode: "html" });
          const isSearch = subn === "searchaudio";
          const res = await callChat(isSearch ? "search" : "chat", q, msg);
          const content = res.content;

          const mtts = pick("tts"); if (!mtts) { await msg.edit({ text: "❌ 未设置 tts 模型", parseMode: "html" }); return; }
          const ptts = providerOf(mtts.provider); if (!ptts) { await msg.edit({ text: "❌ 服务商未配置", parseMode: "html" }); return; }
          const compat = Store.data.compat[mtts.provider] || detectCompat(mtts.provider, mtts.model, ptts.baseUrl);
          const defaultVoice = compat === "gemini" ? "Kore" : "alloy"; const voice = Store.data.models.voice || defaultVoice;

          await msg.edit({ text: "🔊 合成中...", parseMode: "html" });
          const replyToId = replyMsg?.id || 0;

          if (compat === "openai") {
            const audio = await ttsOpenAI(ptts, mtts.model, content, voice);
            const file: any = Object.assign(audio, { name: "ai.ogg" });
            await msg.client?.sendFile(msg.peerId, {
              file,
              caption: formatQA(q, content) + footer(mtts.model, isSearch ? ("Audio with Search (" + html(voice) + ")") : ("Audio (" + html(voice) + ")")),
              parseMode: "html",
              replyTo: replyToId || undefined,
              attributes: [new Api.DocumentAttributeAudio({ duration: 0, voice: true })],
            });
            await msg.delete();
            return;
          } else if (compat === "gemini") {
            const { audio, mime } = await ttsGemini(ptts, mtts.model, content, voice);
            if (audio) {
              const ext = (mime || "audio/ogg").includes("wav")
                ? "wav"
                : (mime || "").includes("mpeg") || (mime || "").includes("mp3")
                ? "mp3"
                : "ogg";
              const file: any = Object.assign(audio, { name: `ai.${ext}` });
              await msg.client?.sendFile(msg.peerId, {
                file,
                caption: formatQA(q, content) + footer(mtts.model, isSearch ? ("Audio with Search (" + html(voice) + ")") : ("Audio (" + html(voice) + ")")),
                parseMode: "html",
                replyTo: replyToId || undefined,
                attributes: [new Api.DocumentAttributeAudio({ duration: 0, voice: true })],
              });
              await msg.delete();
              return;
            } else {
              await msg.edit({ text: "❌ 语音合成失败：服务无有效输出", parseMode: "html" });
              return;
            }
          } else {
            await msg.edit({ text: "❌ 当前服务商不支持语音合成功能", parseMode: "html" });
            return;
          }
        }

        // tts
        if (subn === "tts") {
          const replyMsg = await msg.getReplyMessage();
          const t = (args.join(" ") || "").trim() || extractText(replyMsg).trim();
          if (!t) { await msg.edit({ text: "❌ 请输入文本", parseMode: "html" }); return; }
          const m = pick("tts"); if (!m) { await msg.edit({ text: "❌ 未设置 tts 模型", parseMode: "html" }); return; }
          const p = providerOf(m.provider)!; const compat = Store.data.compat[m.provider] || detectCompat(m.provider, m.model, p.baseUrl);
          const defaultVoice = compat === "gemini" ? "Kore" : "alloy"; const voice = Store.data.models.voice || defaultVoice;
          await msg.edit({ text: "🔊 合成中...", parseMode: "html" });
          const replyToId = replyMsg?.id || 0;
          if (compat === "openai") {
            const audio = await ttsOpenAI(p, m.model, t, voice);
            const file: any = Object.assign(audio, { name: "ai.ogg" });
            const sent: any = await msg.client?.sendFile(msg.peerId, { file, caption: `<b>文本:</b> ${html(t)}` + footer(m.model, `TTS (${html(voice)})`), parseMode: "html", replyTo: replyToId || undefined, attributes: [new Api.DocumentAttributeAudio({ duration: 0, voice: true })] });
            await msg.delete(); return;
          } else if (compat === "gemini") {
            const { audio, mime } = await ttsGemini(p, m.model, t, voice);
            if (audio) {
              const ext = (mime || "audio/ogg").includes("wav")
                ? "wav"
                : (mime || "").includes("mpeg") || (mime || "").includes("mp3")
                ? "mp3"
                : "ogg";
              const file: any = Object.assign(audio, { name: `ai.${ext}` });
              await msg.client?.sendFile(msg.peerId, {
                file,
                caption: `<b>文本:</b> ${html(t)}` + footer(m.model, `TTS (${html(voice)})`),
                parseMode: "html",
                replyTo: replyToId || undefined,
                attributes: [new Api.DocumentAttributeAudio({ duration: 0, voice: true })],
              });
              await msg.delete();
              return;
            } else {
              await msg.edit({ text: "❌ 语音合成失败：服务无有效输出", parseMode: "html" });
              return;
            }
          } else {
            await msg.edit({ text: "❌ 当前服务商不支持语音合成功能", parseMode: "html" });
            return;
          }
        }
        await msg.edit({ text: "❌ 未知子命令", parseMode: "html" });
        return;
      } catch (e: any) {
        await msg.edit({ text: `❌ 执行失败：${html(e?.message || String(e))}` , parseMode: "html" });
      }
    }
  };
}

export default new AiPlugin();
