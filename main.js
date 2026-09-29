'use strict';
/*
 * WebDAV nas —— 轻量 WebDAV 同步插件
 * 作者：Hadesr
 * 桌面 + 移动端通用；基于 Obsidian 官方 requestUrl（绕 CORS）
 *
 * v2.2.0 行为约定：
 *   · 同步【方向】：只下载（云端→本地）/ 只上传（本地→云端）/ 双向
 *   · 同步【传送方式】：只传变动（更新，增量）/ 全部对齐（全量，以方向权威侧为准）
 *       只下载 + 全量 = 云端全部覆盖本地（本地乱改一键还原）
 *       只上传 + 全量 = 本地全部刷新到云端
 *       双向   + 全量 = 每个文件取较新
 *   · 删除行为【跟随方向】，没有单独的删除开关：
 *       只下载 → 云端为准：云端删了→删本地；本地缺了→补回
 *       只上传 → 本地为准：本地删了→删云端；云端缺了→补传
 *       双向   → 两侧删除互相传播
 *   · 自动同步（两条独立机制）：
 *       ① 本地文件改动后 ~10 秒自动跑（只下载方向不触发）
 *       ② 可选「定时轮询」每 N 分钟跑一次（默认 0 = 关）
 *   · 【没有变化时完全静默】——不会无端弹"同步中"
 *   · 所有同步进度只走【右上角通知】，绝不弹框打断写作
 *   · 密码以密文（RC4+Base64）存在 data.json 里，可随配置一起同步
 *   · 同步基线单独存 .sync-state.json（不参与同步，各设备独立）
 */

const { Plugin, PluginSettingTab, Setting, Notice, requestUrl, Modal } = require('obsidian');

const PREFIX = '[WebDAV nas]';
const PLUGIN_ID = 'webdav-nas';
const VERSION = '2.6.4';

/* ---------------------------------------------------------------- 工具 */
function b64(buf) {
  let s = '';
  const arr = new Uint8Array(buf);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function rc4(keyBytes, data) {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + keyBytes[i % keyBytes.length]) & 255;
    const t = S[i]; S[i] = S[j]; S[j] = t;
  }
  const out = new Uint8Array(data.length);
  let i = 0; j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    const t = S[i]; S[i] = S[j]; S[j] = t;
    out[k] = data[k] ^ S[(S[i] + S[j]) & 255];
  }
  return out;
}
// 密码混淆密钥。⚠️ 修改此值会使已保存的密码失效（需重新输入一次）。
const OBF_KEY = new TextEncoder().encode('Hadesrkd83Jf7Qz2Mx9Vp4Rt6Yn1Uc0Bo5HjSw');
const OBF_TAG = 'enc3:';                 // 密文格式标识；更早的格式一律视为失效
const OBF_MARK = 'HADESR-v3|';           // 内部标记
function encStr(s) {
  if (s == null) return '';
  try {
    return OBF_TAG + b64(rc4(OBF_KEY, new TextEncoder().encode(OBF_MARK + String(s))));
  } catch (e) { return String(s); }
}
function decStr(t) {
  if (t == null) return '';
  const s = String(t);
  if (!s.startsWith('enc')) return s;      // 明文（兼容）
  if (!s.startsWith(OBF_TAG)) return '';   // 旧格式 → 解不开，需重新输入
  try {
    const out = new TextDecoder().decode(rc4(OBF_KEY, unb64(s.slice(OBF_TAG.length))));
    if (!out.startsWith(OBF_MARK)) return '';   // 校验不通过：密钥/密文不匹配
    return out.slice(OBF_MARK.length);
  } catch (e) { return ''; }
}

function encPath(rel) {
  return String(rel).split('/').filter(Boolean).map(encodeURIComponent).join('/');
}
function human(n) {
  if (n == null) return '?';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + u[i];
}
function hrefToRel(href, basePath) {
  let p = String(href);
  const m = p.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+(\/.*)?$/);
  if (m) p = m[1] || '/';
  p = p.split('?')[0].split('#')[0];
  const bp = basePath.replace(/\/+$/, '');
  if (bp && (p === bp || p === bp + '/')) return '';
  if (bp && p.startsWith(bp + '/')) p = p.slice(bp.length + 1);
  else p = p.replace(/^\/+/, '');
  try { p = decodeURIComponent(p); } catch (e) { /* 保底 */ }
  return p.replace(/\/+$/, '');
}
function firstTag(block, tag) {
  const re = new RegExp('<(?:[A-Za-z0-9_.-]+:)?' + tag + '[^>]*>([^<]*)<', 'i');
  const m = block.match(re);
  return m ? m[1] : null;
}
function parsePropfindRaw(xml) {
  const out = [];
  const blocks = String(xml).split(/<(?:\w+:)?response[\s>]/i).slice(1);
  for (const b of blocks) {
    const href = firstTag(b, 'href');
    if (!href) continue;
    const isDir = /<(?:[A-Za-z0-9_.-]+:)?collection/i.test(b);
    const size = firstTag(b, 'getcontentlength');
    const etag = firstTag(b, 'getetag');
    const mtime = firstTag(b, 'getlastmodified');
    const name = firstTag(b, 'displayname');
    out.push({
      href, name, isDir,
      size: size ? parseInt(size, 10) : 0,
      etag: etag || null,
      mtime: mtime ? (Date.parse(mtime) || 0) : 0,
    });
  }
  return out;
}
function splitPatterns(str) {
  return String(str || '').split(/[,，\n]/).map((s) => s.trim().replace(/^\/+|\/+$/g, '')).filter(Boolean);
}
function isExcludedBy(rel, patterns) {
  if (!patterns || !patterns.length) return false;
  const parts = String(rel).split('/');
  for (const p of patterns) {
    if (!p) continue;
    if (rel === p || rel.startsWith(p + '/')) return true;
    if (parts.includes(p)) return true;
  }
  return false;
}

/* ---------------------------------------------------------------- WebDAV 客户端 */
class DavClient {
  constructor(settings) {
    this.base = String(settings.address || '').replace(/\/+$/, '');
    let rd = String(settings.remoteDir || '').replace(/^\/+|\/+$/g, '');
    this.autoDeduped = false;
    if (rd) {
      // 地址里已经含有这个目录名时，不再重复拼接。
      // 群晖很常见：地址本身就是 https://nas:5006/共享文件夹名
      let dec = this.base;
      try { dec = decodeURIComponent(this.base); } catch (e) { /* 保留原样 */ }
      const noScheme = dec.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+/, '');
      if (noScheme === '/' + rd || noScheme.endsWith('/' + rd)) {
        rd = '';
        this.autoDeduped = true;
      }
    }
    this.remoteDir = rd;
    if (rd) this.base += '/' + encPath(rd);
    const m = this.base.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+(\/.*)?$/);
    this.basePath = m && m[1] ? m[1].replace(/\/+$/, '') : '';
    this.auth = 'Basic ' + b64(new TextEncoder().encode(`${settings.username}:${decStr(settings.password)}`));
  }
  urlFor(rel) { return rel ? this.base + '/' + encPath(rel) : this.base + '/'; }
  async req(method, rel, opt = {}) {
    const headers = Object.assign({ Authorization: this.auth }, opt.headers || {});
    let res;
    try {
      res = await requestUrl({ url: this.urlFor(rel), method, headers, body: opt.body, throw: false });
    } catch (e) {
      throw new Error(`网络错误（${method} ${this.urlFor(rel)}）：${e && e.message ? e.message : e}`);
    }
    return res;
  }
  async testConn() { return (await this.req('PROPFIND', '', { headers: { Depth: '0' } })).status; }
  hrefPath(href) {
    let p = String(href);
    const m = p.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+(\/.*)?$/);
    if (m) p = m[1] || '/';
    return p.split('?')[0].split('#')[0];
  }
  /* href → 相对 base 的路径。若按 base 剥不出来（群晖等格式不同），用最后一段兜底 */
  relOf(href, curRel) {
    const hp = this.hrefPath(href);
    const bp = this.basePath.replace(/\/+$/, '');
    let p = hp;
    if (bp && (p === bp || p === bp + '/')) return '';
    if (bp && p.startsWith(bp + '/')) p = p.slice(bp.length + 1);
    else p = p.replace(/^\/+/, '');
    try { p = decodeURIComponent(p); } catch (e) { /* 保底 */ }
    p = p.replace(/\/+$/, '');
    const prefixOk = curRel
      ? (p === curRel || p.startsWith(curRel + '/'))
      : (p.indexOf('/') === -1);
    if (!p || !prefixOk) {
      const segs = hp.split('/').filter(Boolean);
      let seg = segs.length ? segs[segs.length - 1] : '';
      try { seg = decodeURIComponent(seg); } catch (e) { /* 保底 */ }
      if (!seg) return '';
      p = curRel ? curRel + '/' + seg : seg;
    }
    return p;
  }
  async listDir(rel) {
    const res = await this.req('PROPFIND', rel, { headers: { Depth: '1' } });
    if (res.status !== 207) {
      let extra = '';
      if (res.status === 404) {
        const rd = this.remoteDir || '';
        if (/[^\x00-\x7F]/.test(rd)) {
          extra = ` → 「远端目录」含非 ASCII 字符（${rd}）。` +
            `部分服务器/反代不会解码 %XX 中文路径，导致 404。` +
            `建议：在服务器上改用英文文件夹名（如 obsidian），或把「远端目录」留空`;
        } else {
          extra = ` → 路径不存在。检查「远端目录」拼得对不对，或该文件夹是否已在服务器上创建`;
        }
      } else if (res.status === 401 || res.status === 403) {
        extra = ' → 认证或权限不足（检查账号/密码、以及该文件夹的访问权限）';
      }
      throw new Error(`列目录失败 HTTP ${res.status}${extra}`);
    }
    const reqPath = this.hrefPath(this.urlFor(rel)).replace(/\/+$/, '');
    const out = [];
    for (const e of parsePropfindRaw(res.text || '')) {
      const hp = this.hrefPath(e.href).replace(/\/+$/, '');
      if (hp === reqPath) continue;                       // 目录自身，跳过
      const p = this.relOf(e.href, rel);
      if (!p) continue;
      out.push({ path: p, isDir: e.isDir, size: e.size, etag: e.etag, mtime: e.mtime });
    }
    return out;
  }
  async walk() {
    const files = {}, stack = [''], seen = new Set();
    while (stack.length) {
      const d = stack.shift();
      if (seen.has(d)) continue;
      seen.add(d);
      for (const e of await this.listDir(d)) {
        if (e.isDir) { if (!seen.has(e.path)) stack.push(e.path); }
        else files[e.path] = e;
      }
    }
    return files;
  }
  async mkdirs(dir) {
    const parts = String(dir).split('/').filter(Boolean);
    let cur = '';
    for (const p of parts) {
      cur = cur ? cur + '/' + p : p;
      await this.req('MKCOL', cur);
    }
  }
  async put(rel, ab) {
    const res = await this.req('PUT', rel, {
      headers: { 'Content-Type': 'application/octet-stream' }, body: ab,
    });
    if (![200, 201, 204].includes(res.status)) {
      const extra = (res.status === 409)
        ? ' → 目标目录不存在（409 Conflict）。检查「远端目录」是否正确、有没有拼重'
        : (res.status === 404 ? ' → 路径不存在' : '');
      throw new Error(`上传失败 HTTP ${res.status}${extra}`);
    }
  }
  async get(rel) {
    const res = await this.req('GET', rel);
    if (res.status !== 200) throw new Error(`下载失败 HTTP ${res.status}`);
    return res.arrayBuffer;
  }
  async del(rel) {
    const res = await this.req('DELETE', rel);
    if (![200, 202, 204, 404].includes(res.status)) throw new Error(`删除失败 HTTP ${res.status}`);
  }
}

/* ---------------------------------------------------------------- 同步计划
 * 删除行为完全跟随 mode（不再有单独的删除开关）
 */
function buildPlan(local, remote, state, mode, granularity) {
  const acts = [];
  const st = state.files || {};
  const all = new Set([...Object.keys(local), ...Object.keys(remote), ...Object.keys(st)]);
  const canPush = (mode !== 'pull');
  const canPull = (mode !== 'push');
  const full = (granularity === 'full');
  const pickNewer = (L, R) => (L.mtime > R.mtime ? 'push' : 'pull');
  for (const rel of [...all].sort()) {
    const L = local[rel], R = remote[rel], S = st[rel];
    if (L && R) {
      let lCh = false, rCh = false;
      if (S) {
        lCh = L.size !== S.size || Math.abs(L.mtime - (S.mtime || 0)) > 1;
        rCh = R.etag !== S.etag;
      }
      // 「全量对齐」不依赖基线：直接比较两边实际内容（size）。
      // 这样即使基线脏了 / 丢了，强制对齐依然 100% 生效。
      const differs = full
        ? (L.size !== R.size)
        : (S ? (lCh || rCh) : (L.size !== R.size));
      if (!differs) {
        acts.push(['skip', rel, '']);
      } else if (full) {
        if (mode === 'push') acts.push(['push', rel, '全量→本地覆盖云端']);
        else if (mode === 'pull') acts.push(['pull', rel, '全量→云端覆盖本地']);
        else acts.push([pickNewer(L, R), rel, '全量(双向)→取较新']);
      } else if (!S) {
        acts.push([pickNewer(L, R), rel, '首次同步→取较新']);
      } else if (lCh && !rCh) {
        acts.push(canPush ? ['push', rel, '本地已改'] : ['skip', rel, '本地已改(只下载不动)']);
      } else if (rCh && !lCh) {
        acts.push(canPull ? ['pull', rel, '云端已改'] : ['skip', rel, '云端已改(只上传不动)']);
      } else {
        acts.push([pickNewer(L, R), rel, '两边都改→取较新']);
      }
    } else if (L && !R) {
      // 仅本地有
      if (!S) {
        acts.push(canPush ? ['push', rel, '新文件(仅本地)'] : ['skip', rel, '仅在本地(只下载模式不动)']);
      } else {
        // 基线里存在 → 云端这个文件被删了
        if (mode === 'push') acts.push(['push', rel, '云端缺失→补传']);
        else acts.push(['del_local', rel, '云端已删→删本地']);       // pull / sync
      }
    } else if (R && !L) {
      // 仅远端有
      if (!S) {
        acts.push(canPull ? ['pull', rel, '新文件(仅远端)'] : ['skip', rel, '仅在远端(只上传模式不动)']);
      } else {
        // 基线里存在 → 本地这个文件被删了
        if (mode === 'pull') acts.push(['pull', rel, '本地缺失→补回']);
        else acts.push(['del_remote', rel, '本地已删→删云端']);      // push / sync
      }
    } else {
      acts.push(['forget', rel, '两边都没了']);
    }
  }
  return acts;
}

/* ---------------------------------------------------------------- 预览弹窗（仅手动触发） */
class PlanModal extends Modal {
  constructor(app, lines, summary) { super(app); this.lines = lines; this.summary = summary; }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: '同步预览（未改动任何文件）' });
    contentEl.createEl('p', { text: this.summary, cls: 'mod-muted' });
    contentEl.createEl('pre', { cls: 'wdnas-plan', text: this.lines.join('\n') });
    new Setting(contentEl).addButton((b) => b.setButtonText('关闭').onClick(() => this.close()));
  }
  onClose() { this.contentEl.empty(); }
}

/* ---------------------------------------------------------------- 诊断弹窗 */
class DiagModal extends Modal {
  constructor(app, text) { super(app); this.text = text; }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: 'WebDAV 诊断报告' });
    contentEl.createEl('p', { cls: 'mod-muted', text: '把下面的内容复制给开发者即可定位问题。' });
    contentEl.createEl('pre', { cls: 'wdnas-plan', text: this.text });
    new Setting(contentEl)
      .addButton((b) => b.setButtonText('复制').onClick(async () => {
        try { await navigator.clipboard.writeText(this.text); new Notice('已复制'); }
        catch (e) { new Notice('复制失败，请手动选中'); }
      }))
      .addButton((b) => b.setButtonText('关闭').onClick(() => this.close()));
  }
  onClose() { this.contentEl.empty(); }
}

/* ---------------------------------------------------------------- 插件 */
class WebdavFnos extends Plugin {
  async onload() {
    const data = (await this.loadData()) || {};
    const s = data.settings || {};
    this.settings = Object.assign({
      address: '', username: '', password: '',
      remoteDir: '', mode: 'push', granularity: 'full',
      protectRatio: 30, syncConfigDir: false, exclude: '',
      autoSyncMinutes: 0, autoOnChange: true,
    }, s);
    // 兼容旧字段
    delete this.settings.propagateDelete;
    if (this.settings.conflict) {   // 旧版「冲突策略」→ 新版「传送方式」
      if (!s.granularity) {
        this.settings.granularity = (this.settings.conflict === 'keep_newer') ? 'incremental' : 'full';
      }
      delete this.settings.conflict;
    }

    this.statePath = `.obsidian/plugins/${PLUGIN_ID}/.sync-state.json`;
    this.state = await this.loadState();

    // 密码处理
    const pw = String(this.settings.password || '');
    if (pw.startsWith(OBF_TAG)) {
      // 当前格式，正常
    } else if (pw.startsWith('enc')) {
      // 旧格式密文（enc1:/enc2: 等）→ 解不开，清掉并提示重新输入
      this.settings.password = '';
      await this.saveAll();
      new Notice(`${PREFIX} 密码加密方式已更新，请到「设置 → WebDAV nas」重新输入一次密码`, 12000);
      console.log(PREFIX, '检测到旧格式密文，已清空，等待重新输入');
    } else if (pw) {
      // 明文 → 立刻加密落盘
      this.settings.password = encStr(pw);
      await this.saveAll();
      console.log(PREFIX, '明文密码已加密存储');
    }

    this.syncing = false;
    this.autoTimer = null;
    this.autoDebounce = null;

    this.addRibbonIcon('refresh-cw', 'WebDAV 同步', () => this.runSync({ dryOnly: false }));
    this.addCommand({ id: 'sync-now', name: '立即同步', callback: () => this.runSync({ dryOnly: false }) });
    this.addCommand({ id: 'preview', name: '预览（不修改文件）', callback: () => this.runSync({ dryOnly: true }) });
    this.addCommand({
      id: 'force-align',
      name: '强制全部对齐一次（救援：用权威侧覆盖）',
      callback: () => this.runSync({ dryOnly: false, forceFull: true }),
    });
    this.addCommand({
      id: 'reset-baseline',
      name: '重置同步基线（修好"判定一致其实是错的"这类问题）',
      callback: async () => {
        this.state = { files: {} };
        await this.saveState();
        new Notice(`${PREFIX} 基线已清空 —— 下次同步会重新全量比对（对照两边实际状态）`, 6000);
      },
    });
    this.addCommand({ id: 'test', name: '测试连接', callback: () => this.testConn() });
    this.addCommand({ id: 'diagnose', name: '诊断连接（排查用，会生成报告）', callback: () => this.diagnose() });
    this.addSettingTab(new FnosSettingTab(this.app, this));

    this.registerEvent(this.app.vault.on('modify', () => this.onFileChanged()));
    this.registerEvent(this.app.vault.on('create', () => this.onFileChanged()));
    this.registerEvent(this.app.vault.on('delete', () => this.onFileChanged()));

    this.setupAutoTimer();
  }

  onunload() {
    if (this.autoTimer) clearInterval(this.autoTimer);
    if (this.autoDebounce) clearTimeout(this.autoDebounce);
  }

  /* ---- 基线独立存储（不参与同步）---- */
  async loadState() {
    try {
      if (await this.app.vault.adapter.exists(this.statePath)) {
        return JSON.parse(await this.app.vault.adapter.read(this.statePath));
      }
    } catch (e) { /* ignore */ }
    return { files: {} };
  }
  async saveState() {
    try {
      await this.app.vault.adapter.write(this.statePath, JSON.stringify(this.state));
    } catch (e) { console.error(PREFIX, '保存基线失败', e); }
  }
  async saveAll() {
    await this.saveData({ settings: this.settings });
    await this.saveState();
  }

  client() { return new DavClient(this.settings); }
  patterns() { return splitPatterns(this.settings.exclude); }

  /* ---- 定时轮询（可选，默认关）---- */
  setupAutoTimer() {
    if (this.autoTimer) { clearInterval(this.autoTimer); this.autoTimer = null; }
    const mins = parseInt(this.settings.autoSyncMinutes, 10) || 0;
    if (mins <= 0) { console.log(PREFIX, '定时同步：关闭'); return; }
    this.autoTimer = setInterval(() => this.runSync({ dryOnly: false, reason: 'timer' }), mins * 60 * 1000);
    console.log(PREFIX, `定时同步：每 ${mins} 分钟`);
    new Notice(`${PREFIX} 定时同步已开启：每 ${mins} 分钟`, 4000);
  }

  /* ---- 本地有改动 → 10 秒后自动跑（与分钟数无关）---- */
  onFileChanged() {
    if (!this.settings.autoOnChange) return;
    const mode = this.settings.mode || 'push';
    if (mode === 'pull') return;                      // 只下载模式：本地改动不影响云端
    if (!this.settings.address || !this.settings.username) return;
    if (this.autoDebounce) clearTimeout(this.autoDebounce);
    this.autoDebounce = setTimeout(() => this.runSync({ dryOnly: false, reason: 'change' }), 10000);
  }

  async testConn() {
    try {
      const st = await this.client().testConn();
      if (st === 207 || st === 200) new Notice(`${PREFIX} 连接成功 ✅ HTTP ${st}`, 4000);
      else if (st === 401) new Notice(`${PREFIX} 401 认证失败：用户名/密码不对`, 9000);
      else new Notice(`${PREFIX} 异常 HTTP ${st}`, 9000);
      console.log(PREFIX, 'testConn ->', st);
    } catch (e) {
      new Notice(`${PREFIX} 连接失败：${e.message}`, 9000);
      console.error(PREFIX, e);
    }
  }

  /* ---- 诊断：打印实际 URL / 原始 href / 解析结果，便于排查（尤其群晖）---- */
  async diagnose() {
    const lines = [];
    const S = this.settings;
    lines.push(`插件      : WebDAV nas v${VERSION}`);
    lines.push(`地址      : ${S.address}`);
    lines.push(`远端目录  : ${S.remoteDir || '(空)'}`);
    lines.push(`方向/传送 : ${S.mode} / ${S.granularity}`);
    const dav = this.client();
    lines.push(`拼出 base : ${dav.base}`);
    lines.push(`basePath  : ${dav.basePath}`);
    const addrPath = dav.hrefPath(S.address).replace(/\/+$/, '');
    if (S.remoteDir && addrPath.endsWith('/' + encodeURIComponent(S.remoteDir))) {
      lines.push(`⚠️ 地址里似乎已经含有「${S.remoteDir}」，又填了远端目录 → 变成 ${dav.base}`);
      lines.push(`   建议：把「远端目录」留空`);
    }
    lines.push('');

    try {
      const u = dav.urlFor('');
      const r = await dav.req('PROPFIND', '', { headers: { Depth: '0' } });
      lines.push(`[1] PROPFIND ${u}  (Depth 0) → HTTP ${r.status}`);
    } catch (e) { lines.push(`[1] 出错: ${e.message}`); }

    try {
      const u = dav.urlFor('');
      const r = await dav.req('PROPFIND', '', { headers: { Depth: '1' } });
      lines.push(`[2] PROPFIND ${u}  (Depth 1) → HTTP ${r.status}`);
      const raw = parsePropfindRaw(r.text || '');
      const reqPath = dav.hrefPath(u).replace(/\/+$/, '');
      lines.push(`    返回 ${raw.length} 条，前 8 条（原始 href → 解析结果）：`);
      raw.slice(0, 8).forEach((e) => {
        const self = (dav.hrefPath(e.href).replace(/\/+$/, '') === reqPath) ? '  (目录自身)' : '';
        lines.push(`      ${e.isDir ? '[D]' : '[F]'} ${e.href}${self}`);
        lines.push(`            → ${JSON.stringify(dav.relOf(e.href, ''))}`);
      });
    } catch (e) { lines.push(`[2] 出错: ${e.message}`); }

    try {
      const testRel = '_webdav_test_' + Date.now() + '.txt';
      await dav.put(testRel, new TextEncoder().encode('hello').buffer);
      lines.push(`[3] PUT ${dav.urlFor(testRel)} → 成功 ✅`);
      await dav.del(testRel);
      lines.push(`[4] DELETE 测试文件 → 成功 ✅`);
    } catch (e) { lines.push(`[3] 上传测试失败: ${e.message}`); }

    // ⑤ 同步判定诊断（能看到每个文件的 L/R/S 三方数值，排查"判定不一致"用）
    lines.push('');
    lines.push('【同步判定诊断】');
    try {
      const local = await this.scanLocal();
      const remoteW = await dav.walk();
      const acts = buildPlan(local, remoteW, this.state, S.mode || 'push', S.granularity || 'full');
      const cnt = {};
      for (const [k] of acts) cnt[k] = (cnt[k] || 0) + 1;
      lines.push(`  方向=${S.mode}  方式=${S.granularity}  基线=${Object.keys(this.state.files || {}).length} 项`);
      lines.push(`  云端 ${Object.keys(remoteW).length} / 本地 ${Object.keys(local).length} 个文件`);
      lines.push(`  判定 → 上传${cnt.push || 0} 下载${cnt.pull || 0} ` +
        `删云端${cnt.del_remote || 0} 删本地${cnt.del_local || 0} 跳过${cnt.skip || 0}`);
      const f = (o) => o ? `{size:${o.size},mtime:${o.mtime || '-'}${o.etag ? ',etag:' + o.etag : ''}}` : '无';
      lines.push('  明细（前 12 条）：');
      for (const [k, rel, why] of acts.slice(0, 12)) {
        const L = local[rel], R = remoteW[rel], SB = (this.state.files || {})[rel];
        lines.push(`    [${k}] ${rel}  ${why || '(判定一致)'}`);
        lines.push(`        L(本地)=${f(L)}`);
        lines.push(`        R(云端)=${f(R)}`);
        lines.push(`        S(基线)=${f(SB)}`);
      }
    } catch (e) { lines.push(`  出错: ${e.message}`); }

    if (S.remoteDir) {
      lines.push('');
      lines.push('【对照】假如「远端目录」留空：');
      const dav2 = new DavClient(Object.assign({}, S, { remoteDir: '' }));
      try {
        const u2 = dav2.urlFor('');
        const r2 = await dav2.req('PROPFIND', '', { headers: { Depth: '1' } });
        lines.push(`  PROPFIND ${u2} (Depth 1) → HTTP ${r2.status}`);
        parsePropfindRaw(r2.text || '').slice(0, 4).forEach((e) => lines.push(`    ${e.href}`));
      } catch (e) { lines.push(`  出错: ${e.message}`); }
    }

    const text = lines.join('\n');
    console.log(PREFIX, '诊断报告\n' + text);
    new DiagModal(this.app, text).open();
  }

  /* ---- 本地扫描 ---- */
  async scanLocal() {
    const out = {};
    const pats = this.patterns();
    const wantCfg = !!this.settings.syncConfigDir;

    if (!wantCfg) {
      for (const f of this.app.vault.getFiles()) {
        if (isExcludedBy(f.path, pats)) continue;
        // 用真实文件系统 stat（adapter.stat），而不是 Obsidian 的缓存 stat ——
        // 否则刚写入/被外部改过的文件可能拿到过时的时间戳，导致判定错乱
        let st = null;
        try { st = await this.app.vault.adapter.stat(f.path); } catch (e) { /* 落回缓存 */ }
        if (st && st.type === 'file') {
          out[f.path] = { size: st.size, mtime: Math.floor(st.mtime / 1000) };
        } else {
          out[f.path] = { size: f.stat.size, mtime: Math.floor(f.stat.mtime / 1000) };
        }
      }
      return out;
    }
    // 勾选「同步 .obsidian」才走 adapter 递归
    const alwaysSkip = new Set([
      '.obsidian/workspace.json', '.obsidian/workspace-mobile.json',
      '.obsidian/cache', '.git', '.trash',
      `.obsidian/plugins/${PLUGIN_ID}/.sync-state.json`,      // 基线永不同步
      `.obsidian/plugins/${PLUGIN_ID}/data.json.bak`,
    ]);
    const skipSuffix = ['.bak', '.bak2', '.bak3', '.tmp'];
    const recurse = async (dir) => {
      let res;
      try { res = await this.app.vault.adapter.list(dir); } catch (e) { return; }
      for (const f of res.files) {
        if (alwaysSkip.has(f)) continue;
        if (skipSuffix.some((s) => f.endsWith(s))) continue;
        if (isExcludedBy(f, pats)) continue;
        let st = null;
        try { st = await this.app.vault.adapter.stat(f); } catch (e) { /* ignore */ }
        if (st && st.type === 'file') out[f] = { size: st.size, mtime: Math.floor(st.mtime / 1000) };
      }
      for (const d of res.folders) {
        const name = d.split('/').pop();
        if (alwaysSkip.has(d) || alwaysSkip.has(name)) continue;
        if (isExcludedBy(d, pats)) continue;
        await recurse(d);
      }
    };
    await recurse('/');
    if (Object.keys(out).length === 0) {
      for (const f of this.app.vault.getFiles()) {
        if (isExcludedBy(f.path, pats)) continue;
        out[f.path] = { size: f.stat.size, mtime: Math.floor(f.stat.mtime / 1000) };
      }
    }
    return out;
  }

  async readLocal(rel) {
    try {
      const f = this.app.vault.getAbstractFileByPath(rel);
      if (f) return await this.app.vault.readBinary(f);
    } catch (e) { /* 落到 adapter */ }
    return await this.app.vault.adapter.readBinary(rel);
  }

  async removeLocal(rel) {
    const f = this.app.vault.getAbstractFileByPath(rel);
    if (f) { await this.app.vault.delete(f); return; }
    try { await this.app.vault.adapter.remove(rel); } catch (e) { /* ignore */ }
  }

  async ensureDir(dir) {
    const parts = String(dir).split('/').filter(Boolean);
    let cur = '';
    for (const p of parts) {
      cur = cur ? cur + '/' + p : p;
      if (!(await this.app.vault.adapter.exists(cur))) {
        try { await this.app.vault.adapter.mkdir(cur); } catch (e) { /* ignore */ }
      }
    }
  }

  /* ---- 主同步流程：进度只走右上角通知 ---- */
  async runSync({ dryOnly = false, reason = 'manual', forceFull = false } = {}) {
    if (this.syncing) { if (reason === 'manual') new Notice(`${PREFIX} 正在同步中…`); return; }
    if (!this.settings.address || !this.settings.username) {
      if (reason === 'manual') new Notice(`${PREFIX} 请先在设置里填服务器地址和用户名`);
      return;
    }
    this.syncing = true;
    let notice = null;
    try {
      const dav = this.client();
      if (dav.autoDeduped && !this._dedupHinted) {
        this._dedupHinted = true;
        new Notice(`${PREFIX} 地址里已包含「${this.settings.remoteDir}」，已自动忽略「远端目录」` +
          `以免路径重复（群晖常见）`, 9000);
      }
      // 先【静默扫描】：没有任何变化就一声不吭，绝不打扰
      const remote = await dav.walk();
      const local = await this.scanLocal();
      const mode = this.settings.mode || 'push';
      // 自动同步（改动触发 / 定时）永远用「只传变动」：只增不覆盖，绝不打扰你正在写的内容
      // 手动「立即同步」用设置里的方式（默认「全部对齐」→ 改错了点一下就恢复）
      const granularity = forceFull
        ? 'full'
        : (reason === 'manual' ? (this.settings.granularity || 'full') : 'incremental');
      const acts = buildPlan(local, remote, this.state, mode, granularity);

      const cnt = {};
      for (const [k] of acts) cnt[k] = (cnt[k] || 0) + 1;
      const changes = (cnt.push || 0) + (cnt.pull || 0) + (cnt.del_local || 0) + (cnt.del_remote || 0);
      const total = Math.max(1, new Set([...Object.keys(local), ...Object.keys(remote)]).size);
      const risky = (cnt.del_local || 0) + (cnt.del_remote || 0);
      const riskyRatio = risky / total;

      const label = { push: '⬆ 上传', pull: '⬇ 下载', del_remote: '🗑 删云端', del_local: '🗑 删本地' };
      const lines = [];
      for (const k of ['push', 'pull', 'del_remote', 'del_local']) {
        for (const [kk, rel, why] of acts) if (kk === k) lines.push(`${label[k]}  ${rel}   ${why}`);
      }
      const summary = `模式=${mode}   云端 ${Object.keys(remote).length} / 本地 ${Object.keys(local).length} 个文件\n` +
        `变更 ${changes} 个  上传${cnt.push || 0} 下载${cnt.pull || 0} 删云端${cnt.del_remote || 0} 删本地${cnt.del_local || 0}`;

      if (changes === 0) {
        if (reason === 'manual') new Notice(`${PREFIX} 已是最新，无需同步 ✅`, 3000);
        for (const [k, rel] of acts) if (k === 'forget') delete this.state.files[rel];
        await this.saveState();
        return;
      }
      if (dryOnly) {
        new PlanModal(this.app, lines.slice(0, 500), summary).open();
        return;
      }
      if (risky > 0 && riskyRatio * 100 > (this.settings.protectRatio || 30)) {
        new Notice(`${PREFIX} ⛔ 删除 ${risky} 个（占 ${(riskyRatio * 100).toFixed(0)}%）超过保护阈值，已中止`, 12000);
        console.warn(PREFIX, '已中止，计划如下：\n' + lines.join('\n'));
        return;
      }

      // 真有变化，才开始显示「同步中」通知
      notice = new Notice(`${PREFIX} 同步中… 0/${changes}`, 0);

      // ---- 执行（进度只走右上角）----
      let ok = 0, fail = 0;
      const totalActs = changes;
      const handled = new Set();          // 本次确实对齐过的文件
      for (const [kind, rel] of acts) {
        if (kind === 'skip' || kind === 'forget') continue;
        let good = true;
        try {
          if (kind === 'push') {
            const ab = await this.readLocal(rel);
            const dir = rel.split('/').slice(0, -1).join('/');
            if (dir) await dav.mkdirs(dir);
            await dav.put(rel, ab);
          } else if (kind === 'pull') {
            const ab = await dav.get(rel);
            const dir = rel.split('/').slice(0, -1).join('/');
            if (dir) await this.ensureDir(dir);
            await this.app.vault.adapter.writeBinary(rel, ab);
          } else if (kind === 'del_remote') {
            await dav.del(rel);
          } else if (kind === 'del_local') {
            await this.removeLocal(rel);
          }
          ok++;
          handled.add(rel);
        } catch (e) {
          good = false; fail++;
          console.error(PREFIX, kind, rel, e);
        }
        notice.setMessage(`${PREFIX} ${ok + fail}/${totalActs}  ${label[kind] || kind} ${rel}` +
          (fail ? `  （失败 ${fail}）` : ''));
      }

      // ---- 重建基线 ----
      // 关键修复：只把「本次确实对齐过」的文件写进新基线；
      // 未处理的文件【保留旧基线】。否则会把"本地改错但没同步"的文件记成已同步，
      // 之后连「强制对齐」都会因判定"两边一致"而跳过（历史 bug）。
      notice.setMessage(`${PREFIX} 更新基线…`);
      const oldFiles = this.state.files || {};
      const remote2 = await dav.walk();
      const local2 = await this.scanLocal();
      const files = {};
      for (const rel of new Set([...Object.keys(local2), ...Object.keys(remote2)])) {
        const L = local2[rel], R = remote2[rel];
        if (!L || !R) continue;
        if (handled.has(rel)) {
          files[rel] = { size: L.size, mtime: L.mtime, etag: R.etag };
        } else if (oldFiles[rel]) {
          files[rel] = oldFiles[rel];                     // 未处理 → 保留旧基线
        } else if (L.size === R.size) {
          files[rel] = { size: L.size, mtime: L.mtime, etag: R.etag };
        }
      }
      this.state = { files, lastSync: new Date().toISOString() };
      await this.saveState();

      notice.hide();
      new Notice(`${PREFIX} 同步完成：成功 ${ok}，失败 ${fail}`, fail ? 10000 : 3000);
    } catch (e) {
      if (notice) notice.hide();
      new Notice(`${PREFIX} 同步失败：${e.message}`, 12000);
      console.error(PREFIX, e);
    } finally {
      this.syncing = false;
    }
  }
}

/* ---------------------------------------------------------------- 设置页 */
class FnosSettingTab extends PluginSettingTab {
  constructor(app, plugin) { super(app, plugin); this.plugin = plugin; }

  display() {
    const { containerEl } = this;
    const p = this.plugin;
    containerEl.empty();
    containerEl.createEl('h2', { text: 'WebDAV nas' });
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: `作者：Hadesr　·　版本 v${VERSION}　·　一个轻量的 WebDAV 同步插件（桌面 + 移动端）`,
    });

    containerEl.createEl('h3', { text: '连接' });
    new Setting(containerEl).setName('服务器地址').setDesc('例：https://hadesr.com:5006/WebDAV')
      .addText((t) => t.setValue(p.settings.address)
        .onChange(async (v) => { p.settings.address = v.trim(); await p.saveAll(); }));
    new Setting(containerEl).setName('用户名')
      .addText((t) => t.setValue(p.settings.username)
        .onChange(async (v) => { p.settings.username = v.trim(); await p.saveAll(); }));
    new Setting(containerEl).setName('密码')
      .setDesc('以密文保存（RC4+Base64）。可随配置一起同步到其他设备，免手输。')
      .addText((t) => {
        t.inputEl.type = 'password';
        t.setValue(decStr(p.settings.password))
          .onChange(async (v) => { p.settings.password = v ? encStr(v) : ''; await p.saveAll(); });
      });
    new Setting(containerEl).setName('远端目录').setDesc('留空 = 地址指向的根；填「知识库」则同步到 /WebDAV/知识库/')
      .addText((t) => t.setValue(p.settings.remoteDir)
        .onChange(async (v) => { p.settings.remoteDir = v.trim(); await p.saveAll(); }));

    containerEl.createEl('h3', { text: '同步方向 + 传送方式' });
    new Setting(containerEl).setName('同步方向')
      .setDesc('只下载 = 云端 → 本地　·　只上传 = 本地 → 云端　·　双向 = 两边互通。' +
        '删除也跟随方向：只下载时云端删了就删本地；只上传时本地删了就删云端；双向则互相传播。')
      .addDropdown((d) => d
        .addOption('pull', '只下载（云端 → 本地）')
        .addOption('push', '只上传（本地 → 云端）')
        .addOption('sync', '双向')
        .setValue(p.settings.mode).onChange(async (v) => { p.settings.mode = v; await p.saveAll(); }));
    new Setting(containerEl).setName('「立即同步」的方式')
      .setDesc('手动点「立即同步 / 侧边栏图标」时怎么传。\n' +
        '【全部对齐】= 按方向强制对齐一次：只下载 → 云端覆盖本地（**本地改错了，点一下就恢复**）；' +
        '只上传 → 本地全部刷到云端；双向 → 每个文件取较新。\n' +
        '【只传变动】= 只处理真正改过的（不会覆盖任何东西）。\n' +
        '⚠️ 注意：自动同步永远用「只传变动」，不受这里影响 —— 所以平时写作不会被打扰、也不会被覆盖。')
      .addDropdown((d) => d
        .addOption('full', '全部对齐（推荐：改错了点一下就恢复）')
        .addOption('incremental', '只传变动（最保守）')
        .setValue(p.settings.granularity).onChange(async (v) => { p.settings.granularity = v; await p.saveAll(); }));
    new Setting(containerEl).setName('删除保护阈值(%)')
      .setDesc('一次同步里「删除」占比超过它就中止（只统计删除，上传/下载不受影响）。防误删。')
      .addText((t) => t.setValue(String(p.settings.protectRatio))
        .onChange(async (v) => { p.settings.protectRatio = parseInt(v, 10) || 30; await p.saveAll(); }));

    containerEl.createEl('h3', { text: '自动同步' });
    new Setting(containerEl).setName('本地改动后自动同步')
      .setDesc('默认开。本地文件改动约 10 秒后自动跑一次。⚠️【只下载】方向下本地改动' +
        '【完全不会】触发同步（也不会传上去）——要还原被改乱的文件，请手动点「立即同步」。' +
        '与下面的"分钟数"无关。')
      .addToggle((tg) => tg.setValue(!!p.settings.autoOnChange)
        .onChange(async (v) => { p.settings.autoOnChange = v; await p.saveAll(); }));
    new Setting(containerEl).setName('定时轮询间隔（分钟）')
      .setDesc('0 = 关闭。填数字后每 N 分钟额外跑一次（用于兜底：例如云端被改动后自动拉回）。' +
        '改完立即生效。Obsidian 关闭或被系统挂起时不会跑。')
      .addText((t) => t.setValue(String(p.settings.autoSyncMinutes || 0))
        .onChange(async (v) => {
          p.settings.autoSyncMinutes = parseInt(v, 10) || 0;
          await p.saveAll();
          p.setupAutoTimer();
        }));

    containerEl.createEl('h3', { text: '同步范围' });
    new Setting(containerEl).setName('同步 .obsidian 配置目录')
      .setDesc('⚠️ 默认关。勾上会同步插件/主题/快捷键等配置（密码已加密，可随配置一起同步）。' +
        '风险：多设备配置互相覆盖。已强制排除同步基线、workspace、缓存、*.bak。')
      .addToggle((tg) => tg.setValue(!!p.settings.syncConfigDir)
        .onChange(async (v) => { p.settings.syncConfigDir = v; await p.saveAll(); }));
    new Setting(containerEl).setName('排除规则')
      .setDesc('逗号分隔。可写目录名或路径前缀，例：.trash, 私人, 附件/大文件')
      .addText((t) => t.setValue(p.settings.exclude)
        .onChange(async (v) => { p.settings.exclude = v; await p.saveAll(); }));

    containerEl.createEl('h3', { text: '操作' });
    new Setting(containerEl)
      .addButton((b) => b.setButtonText('测试连接').onClick(() => p.testConn()))
      .addButton((b) => b.setButtonText('诊断').onClick(() => p.diagnose()))
      .addButton((b) => b.setButtonText('预览').onClick(() => p.runSync({ dryOnly: true })))
      .addButton((b) => b.setButtonText('立即同步').setCta().onClick(() => p.runSync({ dryOnly: false })));
    new Setting(containerEl)
      .setName('强制全部对齐一次（救援）')
      .setDesc('不管上面怎么设置，按当前方向强制对齐一次。' +
        '「只下载」方向下 = 用云端覆盖本地（本地改错了用这个救回来）。')
      .addButton((b) => b.setButtonText('强制对齐').onClick(() => p.runSync({ dryOnly: false, forceFull: true })));
    new Setting(containerEl)
      .setName('重置同步基线')
      .setDesc('清除"上次同步到哪"的记录，下次同步会重新全量比对两边实际状态。' +
        '⚠️ 只在遇到"明明改了却判定没变"这种怪问题时用。')
      .addButton((b) => b.setButtonText('重置基线').onClick(async () => {
        p.state = { files: {} };
        await p.saveState();
        new Notice(`${PREFIX} 基线已清空 —— 下次同步会重新全量比对`, 6000);
      }));

    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: '同步进度只显示在右上角通知里，不会弹框。' +
        '显示「同步完成」时文件已全部传完；飞牛文件管理器若没马上看到，刷新一下即可（NAS 端索引延迟）。',
    });
  }
}

module.exports = WebdavFnos;
