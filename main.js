'use strict';
/* WebDAV nas —— 轻量 WebDAV 同步插件（作者 Hadesr） */

const { Plugin, PluginSettingTab, Setting, Notice, requestUrl, Modal, setIcon } = require('obsidian');

const PREFIX = '[WebDAV nas]';
const PLUGIN_ID = 'webdav-nas';
const VERSION = '2.7.1';

/* 路径归一化 + 本插件文件分类 */
function normRel(p) { return String(p || '').replace(/\\/g, '/').replace(/^\/+/, '').replace(/^\.\//, ''); }
/* 基线/备份：双向都不同步 */
function isSelfCfg(rel) {
  const r = normRel(rel);
  return r === `.obsidian/plugins/${PLUGIN_ID}/.sync-state.json` ||
    r.startsWith(`.obsidian/plugins/${PLUGIN_ID}/data.json.bak`);
}
/* 本机配置：只上传做云端备份，绝不下载（防止主机的方向覆盖客户端） */
function isSelfData(rel) {
  return normRel(rel) === `.obsidian/plugins/${PLUGIN_ID}/data.json`;
}

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
// 系统元数据垃圾（.DS_Store / Icon\r 等）：一律忽略。
const OS_JUNK = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini', '.localized', '.apdisk']);
// Mac 自定义文件夹图标文件：名为 "Icon" + 回车符(0x0D)，无点前缀、isJunk 认不出，但纯系统垃圾。
OS_JUNK.add('Icon\r');

/* ---------------------------------------------------------------- WebDAV 客户端 */
class DavClient {
  constructor(settings) {
    this.base = String(settings.address || '').replace(/\/+$/, '');
    let rd = String(settings.remoteDir || '').replace(/^\/+|\/+$/g, '');
    this.autoDeduped = false;
    if (rd) {
// 地址已含目录名时不再重复拼接（群晖常见）。
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

/* ---- 同步计划（删除行为跟随同步方向）---- */
function buildPlan(local, remote, state, mode, granularity, mirror, cfgStrict) {
  const acts = [];
  const st = state.files || {};
// 首同步：基线为空时按合并处理，不删任何一侧。
  const firstSync = Object.keys(st).length === 0 && !mirror;
  const selfDir = '.obsidian/plugins/' + PLUGIN_ID + '/';
  const all = new Set([...Object.keys(local), ...Object.keys(remote), ...Object.keys(st)]);
  const canPush = (mode !== 'pull');
  const canPull = (mode !== 'push');
  const full = (granularity === 'full');
  const pickNewer = (L, R) => (L.mtime > R.mtime ? 'push' : 'pull');
  for (const rel of [...all].sort()) {
    if (isSelfCfg(rel)) { acts.push(['skip', rel, '本插件配置→不同步']); continue; }
    const L = local[rel], R = remote[rel], S = st[rel];
    // 「完全同步 .obsidian」只对配置文件生效：跳过首次同步保护
    const protectFirst = firstSync && !(cfgStrict && mode === 'pull' && rel.startsWith('.obsidian/'));
    if (L && R) {
      let lCh = false, rCh = false;
      if (S) {
        lCh = L.size !== S.size || Math.abs(L.mtime - (S.mtime || 0)) > 1;
        rCh = R.etag !== S.etag;
      }
// 全量对齐直接比实际内容，不依赖基线。
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
        // 上传(push)=本地为准→本地独有本就该传上去；下载(pull)=本地以云端为准→本地独有=云端没有→删本地
        if (mode === 'pull') acts.push([protectFirst ? 'skip' : 'del_local', rel, protectFirst ? '首次同步→保留本地独有' : '本地独有→删本地(下载=本地以云端为准)']);
        else if (mode === 'sync') acts.push(['push', rel, '双向合并→上传本地独有']);
        else acts.push(canPush ? ['push', rel, '新文件(仅本地)→上传'] : ['skip', rel, '仅在本地(只上传模式不动)']);  // push 上传到云端
      } else {
        // 基线里存在 → 云端这个文件被删了（对方删的）→ 双向/下载 跟随删除；上传则补传
        if (mode === 'push') acts.push(['push', rel, '云端缺失→补传']);
        else acts.push(['del_local', rel, '云端已删→删本地(双向/下载跟随)']);
      }
    } else if (R && !L) {
      // 仅远端有
      if (!S) {
        // 下载(pull)=云端为准→云端独有本就该下载；上传(push)=云端以本地为准→云端独有=本地没有→删云端
        if (mode === 'sync') acts.push(['pull', rel, '双向合并→下载云端独有']);
        else if (mode === 'pull') acts.push(canPull ? ['pull', rel, '新文件(仅远端)→下载'] : ['skip', rel, '仅在远端(只下载模式不动)']);
        else if (mode === 'push') acts.push([protectFirst ? 'skip' : 'del_remote', rel, protectFirst ? '首次同步→保留云端独有' : '云端独有→删云端(上传=云端以本地为准)']);
        else acts.push(canPull ? ['pull', rel, '新文件(仅远端)'] : ['skip', rel, '仅在远端(只上传模式不动)']);
      } else {
        // 基线里存在 → 本地这个文件被删了（我删的）→ 双向/上传 跟随删除；下载则重新下载
        if (mode === 'pull') acts.push(['pull', rel, '本地缺失→补回']);
        else acts.push(['del_remote', rel, '本地已删→删云端(双向/下载跟随)']);
      }
    } else {
      acts.push(['forget', rel, '两边都没了']);
    }
  }
  // 本机配置：只上传做云端备份，绝不下载/删除
  for (const a of acts) {
    if (isSelfData(a[1]) && (a[0] === 'pull' || a[0] === 'del_local' || a[0] === 'del_remote')) {
      a[0] = 'skip'; a[2] = '本机配置→只上传不下载';
    }
  }
  // 本插件自身文件永不删除（配置已排除；主程序允许更新，但不许被删）
  for (const a of acts) {
    if ((a[0] === 'del_local' || a[0] === 'del_remote') && a[1].startsWith(selfDir)) {
      a[0] = 'skip'; a[2] = '本插件自身→不删除';
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

/* ---------------------------------------------------------------- 删除前手动确认弹窗 */
class DeleteConfirmModal extends Modal {
  // resolve(true)=确认删除；resolve(false)=取消（跳过删除）
  constructor(app, lines, summary, onConfirm) { super(app); this.lines = lines; this.summary = summary; this.onConfirm = onConfirm; }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl('h3', { text: '⚠️ 即将删除以下内容（请核对）' });
    contentEl.createEl('p', { text: this.summary, cls: 'mod-muted' });
    const pre = contentEl.createEl('pre', { cls: 'wdnas-plan', text: this.lines.join('\n') });
    pre.style.color = 'var(--text-error)';
    new Setting(contentEl)
      .addButton((b) => b.setButtonText('取消（跳过删除）').onClick(() => { this.onConfirm(false); this.close(); }))
      .addButton((b) => b.setButtonText('确认删除').setWarning().onClick(() => { this.onConfirm(true); this.close(); }));
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
    console.log(`${PREFIX} 已加载 v${VERSION}`);   // 确认磁盘代码是否真的被重新加载
    const data = (await this.loadData()) || {};
    const s = data.settings || {};
    this.settings = Object.assign({
      address: '', username: '', password: '',
      remoteDir: '', mode: 'push', granularity: 'full',
      protectRatio: 30, syncConfigDir: false, syncConfigStrict: false, mirror: false, exclude: '',
      autoSyncMinutes: 0, autoOnChange: true, hideOfficialSync: false,
      confirmDelete: true, syncEmptyDirs: false,
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

    const ribbonIcon = this.addRibbonIcon('cloud', '', () => this.runSync({ dryOnly: false }));
    ribbonIcon.addClass('wdnas-ribbon');
    ribbonIcon.setAttribute('aria-label', '立即同步');
    this.ribbonIcon = ribbonIcon;

    // 状态栏（右下角）同步按钮：纯【云朵】图标（与官方环形同步图标区分开），点击立即同步；同步中变旋转图标
    this.syncBtn = this.addStatusBarItem();
    this.syncBtn.addClass('wdnas-sync-btn');
    setIcon(this.syncBtn, 'cloud');
    this.syncBtn.setAttribute('title', '立即同步');
    this.syncBtn.addEventListener('click', () => this.runSync({ dryOnly: false }));
    // 应用「隐藏官方同步图标」开关
    this.applyOfficialHide();

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
    this.addCommand({
      id: 'empty-trash',
      name: '清空回收站(.trash)（永久删除，不可恢复）',
      callback: () => this.emptyTrash(),
    });
    this.addSettingTab(new FnosSettingTab(this.app, this));

    this.registerEvent(this.app.vault.on('modify', () => this.onFileChanged()));
    this.registerEvent(this.app.vault.on('create', () => this.onFileChanged()));
    this.registerEvent(this.app.vault.on('delete', () => this.onFileChanged()));

    this.setupAutoTimer();
  }

  onunload() {
    if (this.autoTimer) clearInterval(this.autoTimer);
    if (this.autoDebounce) clearTimeout(this.autoDebounce);
    if (this._hideObs) { try { this._hideObs.disconnect(); } catch (e) {} this._hideObs = null; }
    const el = document.getElementById('wdnas-hide-official');
    if (el) el.remove();
  }

  // 状态栏按钮：纯图标。idle = cloud（云朵，与官方环形同步图标区分）；同步中 = loader（旋转），进度放 tooltip（不显示文字）
  setSyncBtn(state) {
    if (this.ribbonIcon) this.ribbonIcon.classList.toggle('wdnas-spin', state !== 'idle');
    if (!this.syncBtn) return;
    if (state === 'idle') {
      setIcon(this.syncBtn, 'cloud');
      this.syncBtn.classList.remove('wdnas-spin');
      this.syncBtn.setAttribute('title', '立即同步');
    } else {
      setIcon(this.syncBtn, 'loader');
      this.syncBtn.classList.add('wdnas-spin');
      this.syncBtn.setAttribute('title', typeof state === 'string' ? state : 'WebDAV nas：同步中…');
    }
  }

// 隐藏官方「同步」图标：多重 CSS + MutationObserver 兜底，排除本插件按钮。
  applyOfficialHide() {
    const id = 'wdnas-hide-official';
    const existing = document.getElementById(id);
    if (this._hideObs) { try { this._hideObs.disconnect(); } catch (e) {} this._hideObs = null; }
    if (existing) existing.remove();

    if (!this.settings.hideOfficialSync) return;   // 关：仅清理即可

    const s = document.createElement('style');
    s.id = id;
    s.textContent =
      '.status-bar-item.sync-status-icon{display:none !important;}' +
      '.status-bar-item.plugin-sync{display:none !important;}' +
      '.status-bar-item.plugin-obsidian-sync{display:none !important;}' +
      '.status-bar-item[data-plugin="sync"]{display:none !important;}';
    document.head.appendChild(s);

    const isSync = (el) => {
      const t = (el.getAttribute('aria-label') || el.getAttribute('title') || el.textContent || '').toLowerCase();
      if (!t) return false;
      if (t.includes('sync')) return true;                       // 英文 "Sync" / "Obsidian Sync"
      if (t.includes('同步') && !t.includes('webdav')) return true;  // 中文「同步」，但排除本插件「WebDAV 同步」
      return false;
    };
    const reap = () => {
      // 永远保留本插件自己的图标（用专属 class 精确排除，不依赖文字匹配）
      document.querySelectorAll('.status-bar-item').forEach((el) => {
        if (el.classList.contains('wdnas-sync-btn')) return;
        if (isSync(el)) el.style.display = 'none';
      });
      document.querySelectorAll('.ribbon-item').forEach((el) => {
        if (el.classList.contains('wdnas-sync-btn')) return;
        if (isSync(el)) el.style.display = 'none';
      });
    };
    reap();
    try {
      this._hideObs = new MutationObserver(reap);
      this._hideObs.observe(document.body, { childList: true, subtree: true });
    } catch (e) { /* 不支持就只跑一次 reap */ }
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
// 写盘后回读校验 + 重试，避免 Windows 下 saveData 静默失败。
    let ok = false;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await this.saveData({ settings: this.settings });
        const check = await this.loadData();
        if (check && check.settings
            && check.settings.mode === this.settings.mode
            && !!check.settings.syncConfigDir === !!this.settings.syncConfigDir) {
          ok = true;
          break;
        }
      } catch (e) { console.error(PREFIX, 'saveAll 写盘异常', e); }
      if (attempt < 3) await new Promise((r) => setTimeout(r, 400));
    }
    if (!ok) {
      console.error(PREFIX, '⚠️ 设置保存校验未通过（可能被杀软拦截）：请检查 Windows Defender 是否拦截了 data.json 的写入');
      new Notice(`${PREFIX} 设置未能持久化保存（疑似被杀软拦截），重启可能丢失，请把库文件夹加入 Defender 排除项`, 10000);
    }
    try { await this.saveState(); } catch (e) { /* ignore */ }
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
      if (!S.syncConfigDir) {
        for (const k of Object.keys(remoteW)) {
          if (k.startsWith('.obsidian/') || k.startsWith('.git/') || k.startsWith('.trash/')) delete remoteW[k];
        }
      }
      for (const k of Object.keys(remoteW)) if (isSelfCfg(k)) delete remoteW[k];
      const cfgStrict = (S.mode === 'pull') && !!S.syncConfigDir && !!S.syncConfigStrict;
      const acts = buildPlan(local, remoteW, this.state, S.mode || 'push', S.granularity || 'full', !!S.mirror, cfgStrict);
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
// 本地扫描走 adapter.list（真实文件系统），不用 getFiles() 缓存。
    const skipDir = (d) => {
      if (!wantCfg && (d === '.obsidian' || d.startsWith('.obsidian/'))) return true;
      if (d === '.git' || d.startsWith('.git/') || d === '.trash' || d.startsWith('.trash/')) return true;
      if (isExcludedBy(d, pats)) return true;
      return false;
    };
    const alwaysSkip = new Set([
      '.obsidian/workspace.json', '.obsidian/workspace-mobile.json',
      '.obsidian/cache', '.git', '.trash',
      `.obsidian/plugins/${PLUGIN_ID}/.sync-state.json`,      // 基线永不同步
      `.obsidian/plugins/${PLUGIN_ID}/data.json.bak`,
    ]);
    const skipSuffix = ['.bak', '.bak2', '.bak3', '.tmp'];
    const addFile = (f) => {
      if (!wantCfg && f.startsWith('.obsidian/')) return;
      if (isSelfCfg(f)) return;
      if (f.startsWith('.git/') || f.startsWith('.trash/')) return;
      if (alwaysSkip.has(f) || alwaysSkip.has(f.split('/').pop())) return;
      if (skipSuffix.some((s) => f.endsWith(s))) return;
      if (OS_JUNK.has(f.split('/').pop())) return;   // 系统垃圾文件不进同步
      if (isExcludedBy(f, pats)) return;
      return this.app.vault.adapter.stat(f)
        .then((st) => { if (st && st.type === 'file') out[f] = { size: st.size, mtime: Math.floor(st.mtime / 1000) }; })
        .catch(() => {});
    };
    const recurse = async (dir) => {
      let res;
      try { res = await this.app.vault.adapter.list(dir); } catch (e) { return; }
      const proms = [];
      for (const f of res.files) proms.push(addFile(f));
      for (const d of res.folders) {
        const name = d.split('/').pop();
        if (alwaysSkip.has(d) || alwaysSkip.has(name)) continue;
        if (OS_JUNK.has(name)) continue;   // 系统垃圾目录不递归
        if (skipDir(d) || skipDir(name)) continue;
        proms.push(recurse(d));
      }
      await Promise.all(proms);
    };
    // 根目录：优先 ''，若 '' 抛错再试 '/'（兼容性）；两者都失败就如实返回空（宁可不传，也不退回缓存制造重复）
    let listed = false;
    for (const root of ['', '/']) {
      try {
        const res = await this.app.vault.adapter.list(root);
        listed = true;
        const proms = [];
        for (const f of res.files) proms.push(addFile(f));
        for (const d of res.folders) {
          const name = d.split('/').pop();
          if (alwaysSkip.has(d) || alwaysSkip.has(name)) continue;
          if (OS_JUNK.has(name)) continue;   // 系统垃圾目录不递归
          if (skipDir(d) || skipDir(name)) continue;
          proms.push(recurse(d));
        }
        await Promise.all(proms);
        break;
      } catch (e) { /* 试下一个根 */ }
    }
    if (!listed) console.warn(PREFIX, 'scanLocal: adapter.list 两个根目录都失败，本地清单为空');
    // 同步配置目录时，显式补一次 .obsidian（adapter.list 通常不返回隐藏目录）
    if (wantCfg) {
      try {
        if (await this.app.vault.adapter.exists('.obsidian')) await recurse('.obsidian');
      } catch (e) { /* ignore */ }
    }
    return out;
  }

// 镜像模式：收集远端孤儿空目录。
  async computeOrphanRemoteDirs(dav, local, remote) {
    const remoteFiles = Object.keys(remote || {});
    const localFiles = Object.keys(local || {});
    const under = (dir, rels) => rels.some((r) => r === dir || r.startsWith(dir + '/'));
    const remoteDirs = new Set();
    const stack = ['']; const seen = new Set();
    while (stack.length) {
      const d = stack.shift();
      if (seen.has(d)) continue; seen.add(d);
      let list;
      try { list = await dav.listDir(d); } catch (e) { continue; }
      for (const e of list) {
        if (e.isDir) { remoteDirs.add(e.path); if (!seen.has(e.path)) stack.push(e.path); }
      }
    }
    const orphan = [];
    for (const d of remoteDirs) {
      if (!this.settings.syncConfigDir && (d === '.obsidian' || d.startsWith('.obsidian/'))) continue;
      if (under(d, remoteFiles)) continue;   // 远端还有文件 → 非空
      if (under(d, localFiles)) continue;     // 本地有对应文件 → 需保留（马上要上传）
      orphan.push(d);
    }
    return orphan;
  }

// 下载侧：收集本地孤儿空目录。
  async computeOrphanLocalDirs(local, remote, includeCfg) {
    const localFiles = Object.keys(local || {});
    const remoteFiles = Object.keys(remote || {});
    const base = (this.app.vault.adapter.basePath || '').replace(/\/+$/, '');
    const toRel = (p) => {
      let r = p;
      if (base && r.startsWith(base)) r = r.slice(base.length);
      return r.replace(/^\/+/, '');
    };
    // 真实枚举本地所有目录（含零文件空目录）
    const localDirs = new Set();
    const stack = [''];
    const seen = new Set();
    while (stack.length) {
      const d = stack.pop();
      if (seen.has(d)) continue; seen.add(d);
      let list;
      try { list = await this.app.vault.adapter.list(d); } catch (e) { continue; }
      for (const fld of (list.folders || [])) {
        const rel = toRel(fld);
        if (!rel || rel === d) continue;
        if (rel === '.git' || rel.startsWith('.git/') || rel === '.trash' || rel.startsWith('.trash/')) continue;
        if (rel.startsWith(`.obsidian/plugins/${PLUGIN_ID}`)) continue;   // 本插件自身不删
        if (rel === '.obsidian' || rel.startsWith('.obsidian/')) {
          if (!includeCfg) continue;                                       // 默认不动 .obsidian
          const root = (rel === '.obsidian' || rel === '.obsidian/plugins' || rel === '.obsidian/themes');
          if (!root) localDirs.add(rel);                                   // 只把具体插件/主题目录当候选
          if (!seen.has(rel)) stack.push(rel);
          continue;
        }
        localDirs.add(rel);
        if (!seen.has(rel)) stack.push(rel);
      }
    }
    const remoteDirs = new Set();
    for (const rel of remoteFiles) {
      const parts = rel.split('/');
      for (let i = 1; i < parts.length; i++) remoteDirs.add(parts.slice(0, i).join('/'));
    }
    const under = (dir, rels) => rels.some((r) => r === dir || r.startsWith(dir + '/'));
    const orphan = [];
    for (const d of localDirs) {
      if (under(d, localFiles)) continue;   // 本地还有文件 → 非空，保留
      if (remoteDirs.has(d)) continue;      // 云端有对应目录 → 保留（下载不应破坏云端想要的结构）
      orphan.push(d);
    }
    return orphan;
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

// 清空库内 .trash（永久删除，先确认）。
  async emptyTrash() {
    const ad = this.app.vault.adapter;
    const files = [];
    const folders = [];
    const walk = async (d) => {
      let list;
      try { list = await ad.list(d); } catch (e) { return; }   // .trash 不存在 → 当作空
      for (const f of (list.files || [])) files.push(f);
      for (const sub of (list.folders || [])) { folders.push(sub); await walk(sub); }
    };
    await walk('.trash');
    if (!files.length && !folders.length) {
      new Notice(`${PREFIX} 回收站已是空的 ✅`, 3000);
      return;
    }
    const lines = [
      ...files.map((f) => `🗑 文件  ${f}`),
      ...folders.map((d) => `📁 文件夹  ${d}`),
    ];
    const ok = await new Promise((resolve) => {
      new DeleteConfirmModal(this.app, lines,
        `将永久删除回收站 ${files.length} 个文件 + ${folders.length} 个文件夹（不可恢复，请确认）`, resolve).open();
    });
    if (!ok) return;
    let removed = 0, failed = 0;
    for (const f of files) {
      try { await ad.remove(f); removed++; }
      catch (e) { failed++; console.warn(PREFIX, '清空回收站：删文件失败', f, (e && e.message) || e); }
    }
    folders.sort((a, b) => b.split('/').length - a.split('/').length);   // 最深优先：先删空的子目录，再删父目录
    for (const d of folders) {
      try { await ad.rmdir(d, false); removed++; }
      catch (e) { /* 可能已被父级一并带走/不存在，忽略 */ }
    }
    try { await ad.mkdir('.trash'); } catch (e) { /* 已存在 */ }          // 重建空回收站，Obsidian 需要它存在
    new Notice(`${PREFIX} 回收站已清空：删除 ${removed} 项${failed ? `，失败 ${failed}` : ''}`, 4000);
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

// 删本地后递归清理空目录壳。
  async removeEmptyLocalDirs(parents, local2, remote2, includeCfg) {
    const guard = (d) => {
      if (!d) return true;
      if (d === '' || d === '.' || d === '/') return true;
      if (d === '.obsidian' || d === '.obsidian/plugins' || d === '.obsidian/themes') return true;
      if (d.startsWith(`.obsidian/plugins/${PLUGIN_ID}`)) return true;
      if (d === '.git' || d.startsWith('.git/') || d === '.trash' || d.startsWith('.trash/')) return true;
      if (!includeCfg && (d === '.obsidian' || d.startsWith('.obsidian/'))) return true;
      return false;
    };
    const under = (dir, rels) => rels.some((r) => r === dir || r.startsWith(dir + '/'));
    const localFiles = Object.keys(local2 || {});
    const remoteFiles = Object.keys(remote2 || {});
    const pats = this.patterns ? this.patterns() : [];
    const alwaysSkip = new Set([
      '.obsidian/workspace.json', '.obsidian/workspace-mobile.json',
      '.obsidian/cache', '.git', '.trash',
      `.obsidian/plugins/${PLUGIN_ID}/.sync-state.json`,
      `.obsidian/plugins/${PLUGIN_ID}/data.json.bak`,
    ]);
    const skipSuffix = ['.bak', '.bak2', '.bak3', '.tmp'];
// 逻辑为空的目录：整目录移入回收站（系统回收站优先，退回库内 .trash）。
    const trashDir = async (d) => {
      // 1) 官方 Vault.trash：先尝试系统回收站（Mac ~/.Trash / Windows 回收站），失败自动退回库内 .trash。需抽象文件对象。
      try {
        const af = this.app.vault.getAbstractFileByPath(d);
        if (af && typeof this.app.vault.trash === 'function') { await this.app.vault.trash(af, true); return; }
      } catch (e) { /* 取不到抽象文件或失败 → 走 adapter 级 */ }
      const ad = this.app.vault.adapter;
      // 2) 系统回收站（用户要的"放回收站"即这一层）—— macOS ~/Trash、Windows 回收站、Linux 桌面垃圾桶
      if (typeof ad.trashSystem === 'function') {
        try { await ad.trashSystem(d); return; } catch (e) { /* 系统回收站被禁用 → 库内 .trash */ }
      }
      // 3) 库内 .trash（可恢复，Obsidian 默认约 30 天后清）。同名已存在则加时间戳避免覆盖。
      if (typeof ad.trashLocal === 'function') {
        try { await ad.trashLocal(d); return; }
        catch (e) {
          if (e && e.code === 'EEXIST') {
            await ad.mkdir('.trash');
            await ad.rename(d, `.trash/${d}__${Date.now()}`);
            return;
          }
          throw e;
        }
      }
      // 4) 极旧版本都没有 trash 方法 → 直接 rename 到 .trash（仍是移动、可逆，不会永久丢失）
      await ad.mkdir('.trash');
      await ad.rename(d, `.trash/${d}__${Date.now()}`);
    };
    let candidates = [...new Set(parents)].filter((d) => d && !guard(d));
    let changed = true, rounds = 0, removed = 0;
    const failed = [];                       // 本次没删掉的目录（用于 Mac 兜底提醒）
    this._failedLocalDirs = [];
    while (changed && rounds < 50) {
      changed = false; rounds++;
      candidates.sort((a, b) => b.split('/').length - a.split('/').length); // 最深优先
      const next = [];
      for (const d of candidates) {
        if (guard(d)) continue;
        if (under(d, localFiles) || under(d, remoteFiles)) { next.push(d); continue; }
// 确认无真实文件：整目录移入回收站（可恢复）。
        try {
          await trashDir(d);
          removed++;
          changed = true;
          const p = d.split('/').slice(0, -1).join('/');
          if (p && !guard(p) && !next.includes(p)) next.push(p);
        } catch (e) {
          // ENOENT = 目录已不在原位置（上轮已移入回收站 / 被更深子目录顺带移走 / 并发删除）→ 目标达成，不算失败。
          if (e && e.code === 'ENOENT') { /* 已清理，无需告警、不进 failed */ }
          else {
// 失败记日志并进 failed（触发 Mac 兜底提醒）。
            console.warn(PREFIX, '本地空目录移入回收站失败', d, '原因=', (e && e.message) || e);
            if (!failed.includes(d)) failed.push(d);
            next.push(d);
          }
        }
      }
      candidates = next;
    }
    this._failedLocalDirs = [...new Set(failed)];
    return removed;
  }

  /* ---- 主同步流程：进度只走右上角通知 ---- */
  async runSync({ dryOnly = false, reason = 'manual', forceFull = false } = {}) {
    if (this.syncing) { if (reason === 'manual') new Notice(`${PREFIX} 正在同步中…`); return; }
    if (!this.settings.address || !this.settings.username) {
      if (reason === 'manual') new Notice(`${PREFIX} 请先在设置里填服务器地址和用户名`);
      return;
    }
    this.syncing = true;
    this.setSyncBtn('⟳ 同步中…');
    let notice = null;
    try {
      const dav = this.client();
      if (dav.autoDeduped && !this._dedupHinted) {
        this._dedupHinted = true;
        new Notice(`${PREFIX} 地址里已包含「${this.settings.remoteDir}」，已自动忽略「远端目录」` +
          `以免路径重复（群晖常见）`, 9000);
      }
      // 先【静默扫描】：没有任何变化就一声不吭，绝不打扰
      const wantCfg = !!this.settings.syncConfigDir;
      const remote = await dav.walk();
      // 「关闭同步 .obsidian」时，远端清单也要排除配置/系统目录，否则下载(pull)仍会把 .obsidian 拉回来
      if (!wantCfg) {
        for (const k of Object.keys(remote)) {
          if (k.startsWith('.obsidian/') || k.startsWith('.git/') || k.startsWith('.trash/')) delete remote[k];
        }
      }
      // 本插件自身配置永不参与同步（避免主机的「同步方向」盖掉客户端）
      for (const k of Object.keys(remote)) if (isSelfCfg(k)) delete remote[k];
      const local = await this.scanLocal();
      const mode = this.settings.mode || 'push';
// 自动同步只用「只传变动」，不覆盖正在写的内容。
      const granularity = forceFull
        ? 'full'
        : (reason === 'manual' ? (this.settings.granularity || 'full') : 'incremental');
      // 「完全同步 .obsidian」只在「只下载」模式生效
      const cfgStrict = mode === 'pull' && !!this.settings.syncConfigDir && !!this.settings.syncConfigStrict;
      const acts = buildPlan(local, remote, this.state, mode, granularity, this.settings.mirror, cfgStrict);

// 镜像模式：预算孤儿空目录，受「空白文件夹处理」开关控制。
      const wantEmpty = this.settings.syncEmptyDirs === true;   // 默认关
      const orphanDirs = (wantEmpty && mode !== 'pull')
        ? await this.computeOrphanRemoteDirs(dav, local, remote)
        : [];
// 下载侧：预算本地孤儿空目录（同样受开关控制）。
      const orphanLocal = ((wantEmpty && mode !== 'push') || cfgStrict)
        ? await this.computeOrphanLocalDirs(local, remote, cfgStrict)
        : [];

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

      if (changes === 0 && orphanDirs.length === 0 && orphanLocal.length === 0) {
        if (reason === 'manual') new Notice(`${PREFIX} 已是最新，无需同步 ✅`, 3000);
        for (const [k, rel] of acts) if (k === 'forget') delete this.state.files[rel];
        await this.saveState();
        return;
      }
      if (dryOnly) {
        const preview = lines.slice();
        for (const d of orphanDirs) preview.push(`🗑 删目录  ${d}   （孤儿空目录·镜像清理）`);
        new PlanModal(this.app, preview.slice(0, 500), summary).open();
        return;
      }
// 删除前手动确认：列出所有删除项，确认后才执行。
      const delList = [];
      for (const [k, rel] of acts) {
        if (k === 'del_local') delList.push(`🗑 删本地文件  ${rel}`);
        else if (k === 'del_remote') delList.push(`🗑 删云端文件  ${rel}`);
      }
      for (const d of orphanLocal) delList.push(`🗑 清本地空目录  ${d}`);
      for (const d of orphanDirs) delList.push(`🗑 清云端空目录  ${d}`);
      let skipDelete = false;
      if (this.settings.confirmDelete && delList.length) {
        if (reason === 'manual') {
          const ok = await new Promise((resolve) => {
            new DeleteConfirmModal(this.app, delList,
              `模式=${mode}　将删除 ${delList.length} 项（上传/下载不受影响）`, resolve).open();
          });
          if (!ok) skipDelete = true;
        } else {
          // 自动同步不弹窗、也不删：等你在手动同步里验证过、并关掉「删除前手动确认」后才全自动删
          skipDelete = true;
        }
      }
      if (skipDelete) {
        for (let i = 0; i < acts.length; i++) {
          if (acts[i][0] === 'del_local' || acts[i][0] === 'del_remote') acts[i] = ['skip', acts[i][1], '用户取消删除'];
        }
      }
// 镜像模式不受 protectRatio 拦截，但任一方为空时禁止反向清空。
      const mirror = !!this.settings.mirror;
      const localEmpty = Object.keys(local).length === 0;
      const remoteEmpty = Object.keys(remote).length === 0;
      const mirrorWipe = mode !== 'sync' && (
        (mode !== 'pull' && localEmpty) ||  // 上传 + 本地空 → 会清空云端，无条件中止保护
        (mode === 'pull' && remoteEmpty)    // 下载 + 云端空 → 会清空本地，无条件中止保护
      );                                    // 双向模式不走此中止：双向就是要互相补全
      if (mirrorWipe && !skipDelete) {
        new Notice(`${PREFIX} ⛔ 镜像模式：本地 / 云端一方为空，为避免清空对方已中止（请检查同步目录是否正确）`, 12000);
        console.warn(PREFIX, '镜像模式空一方中止，计划如下：\n' + lines.join('\n'));
        return;
      }
      if (mode === 'sync' && risky > 0 && !skipDelete && riskyRatio * 100 > (this.settings.protectRatio || 30)) {
        new Notice(`${PREFIX} ⛔ 删除 ${risky} 个（占 ${(riskyRatio * 100).toFixed(0)}%）超过保护阈值，已中止`, 12000);
        console.warn(PREFIX, '已中止，计划如下：\n' + lines.join('\n'));
        return;
      }

      // 真有变化，才开始显示「同步中」通知
      notice = new Notice(`${PREFIX} 同步中… 0/${changes}`, 0);

      // ---- 执行（进度只走右上角）----
      let ok = 0, fail = 0;
      const delLocalParents = [];        // 收集被删本地文件的父目录，用于事后清理本地空目录壳
      const delRemoteParents = [];       // 收集被删云端文件的父目录，用于事后清理云端空目录壳（对称）
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
            const pdir = rel.split('/').slice(0, -1).join('/');
            if (pdir) { delLocalParents.push(pdir); delRemoteParents.push(pdir); }
            await dav.del(rel);
          } else if (kind === 'del_local') {
            const pdir = rel.split('/').slice(0, -1).join('/');
            if (pdir) delLocalParents.push(pdir);
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
        this.setSyncBtn(`⟳ ${ok + fail}/${totalActs}`);
      }

// 重建基线：只写本次确实对齐过的文件，未处理的保留旧基线。
      notice.setMessage(`${PREFIX} 更新基线…`);
      const oldFiles = this.state.files || {};
      const remote2 = await dav.walk();
      if (!wantCfg) {
        for (const k of Object.keys(remote2)) {
          if (k.startsWith('.obsidian/') || k.startsWith('.git/') || k.startsWith('.trash/')) delete remote2[k];
        }
      }
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

// 清理远端孤儿空目录：用最新远端状态再算一次，历史与新产生的都能清掉。
      let cleanedDirs = 0;
      if (orphanDirs.length && !skipDelete) {
        try {
          const orphanNow = await this.computeOrphanRemoteDirs(dav, local, remote2);
          orphanNow.sort((a, b) => b.split('/').length - a.split('/').length);  // 先删最深的
          for (const d of orphanNow) {
            try { await dav.del(d); cleanedDirs++; }
            catch (e) { console.warn(PREFIX, '清理孤儿目录失败', d, e.message); }
          }
        } catch (e) { console.warn(PREFIX, '计算孤儿目录失败', e.message); }
      }

// 清理本轮删文件后腾空的远端目录壳（不受开关影响）。
      if (delRemoteParents.length && !skipDelete) {
        const rf2 = Object.keys(remote2 || {});
        const lf2 = Object.keys(local2 || {});
        const under2 = (dir, rels) => rels.some((r) => r === dir || r.startsWith(dir + '/'));
        const uniq = [...new Set(delRemoteParents)].filter(Boolean)
          .sort((a, b) => b.split('/').length - a.split('/').length);
        for (const d of uniq) {
          if (d === '.obsidian' || d.startsWith('.obsidian/') || d === '.trash' ||
              d.startsWith('.trash/') || d === '.git' || d.startsWith('.git/')) continue;
          if (under2(d, rf2) || under2(d, lf2)) continue;   // 云端或本地还有文件 → 保留
          try { await dav.del(d); cleanedDirs++; }
          catch (e) { console.warn(PREFIX, '清理云端空目录失败', d, e.message); }
        }
      }

// 清理本地孤儿空目录（下载/删本地后残留）。
      let cleanedLocalDirs = 0;
      if (delLocalParents.length && !skipDelete) {
        try { cleanedLocalDirs += await this.removeEmptyLocalDirs(delLocalParents, local2, remote2, cfgStrict); }
        catch (e) { console.warn(PREFIX, '清理本地孤儿目录失败', e.message); }
      }
// 即使本轮没删文件，也清一遍本地残留空壳（仅下载/双向/镜像）。
      if (mode !== 'push' && orphanLocal.length && !skipDelete) {
        try {
          orphanLocal.sort((a, b) => b.split('/').length - a.split('/').length);
          cleanedLocalDirs += await this.removeEmptyLocalDirs(orphanLocal, local2, remote2, cfgStrict);
        } catch (e) { console.warn(PREFIX, '清理本地孤儿目录失败', e.message); }
      }

      notice.hide();
// 目录清理结果要可自证：清掉多少、跳过多少都报出来。
      const dirMsg = (cleanedDirs || cleanedLocalDirs)
        ? `，空目录移入回收站 云端${cleanedDirs}/本地${cleanedLocalDirs}`
        : (orphanDirs.length || orphanLocal.length)
          ? `，空目录候选 云端${orphanDirs.length}/本地${orphanLocal.length}（未处理，检查是否取消删除/被保护中止）`
          : '';
      console.log(`${PREFIX} 同步完成`, { ok, fail, mode, cleanedDirs, cleanedLocalDirs, orphanDirs: orphanDirs.length, orphanLocal: orphanLocal.length, skipDelete });
      new Notice(`${PREFIX} 同步完成：成功 ${ok}，失败 ${fail}${dirMsg}`, fail ? 10000 : 3000);
      // Mac 专属兜底提醒：自动移入回收站万一失败，明确告诉用户去 Finder 手动移到废纸篓（不受任何开关/设置控制，只要本轮确认过删除且 Mac 端有残留就弹）。
      const isMac = (typeof process !== 'undefined' && process.platform === 'darwin');
      const failDirs = this._failedLocalDirs || [];
      if (isMac && failDirs.length) {
        const list2 = failDirs.join('、');
        console.warn(PREFIX, 'Mac 本地空目录自动移入回收站失败，需用户在 Finder 手动移到废纸篓：', failDirs);
        new Notice(`${PREFIX} ⚠️ Mac：有 ${failDirs.length} 个本地空目录没能自动移入回收站，请到 Finder 手动移到废纸篓：${list2}`, 20000);
      }
    } catch (e) {
      if (notice) notice.hide();
      new Notice(`${PREFIX} 同步失败：${e.message}`, 12000);
      console.error(PREFIX, e);
    } finally {
      this.syncing = false;
      this.setSyncBtn('idle');
    }
  }
}

/* ---------------------------------------------------------------- 设置页 */
class FnosSettingTab extends PluginSettingTab {
  constructor(app, plugin) { super(app, plugin); this.plugin = plugin; this._page = ''; }

  /* 一级目录 + 二级页：只切 UI，不改设置逻辑 */
  display() {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.addClass('nas-settings');
    if (!this._page) { this._renderHome(containerEl); return; }
    this._renderBack(containerEl, this._page);
    if (this._page === 'conn') this._pageConn(containerEl);
    else if (this._page === 'sync') this._pageSync(containerEl);
    else if (this._page === 'auto') this._pageAuto(containerEl);
    else if (this._page === 'scope') this._pageScope(containerEl);
    else if (this._page === 'tools') this._pageTools(containerEl);
    else this._pageAbout(containerEl);
  }

  _go(page) { this._page = page || ''; this.display(); try { this.containerEl.scrollTop = 0; } catch (e) { /* 忽略 */ } }

  _renderHome(c) {
    const head = c.createDiv({ cls: 'nas-head' });
    const logo = head.createDiv({ cls: 'nas-logo' });
    setIcon(logo, 'cloud');
    logo.title = '点击立即同步';
    logo.setAttribute('role', 'button');
    logo.setAttribute('aria-label', '立即同步');
    logo.onclick = async () => {
      if (this.plugin.syncing) return;
      logo.classList.add('is-syncing');
      try { await this.plugin.runSync({ dryOnly: false }); }
      finally { logo.classList.remove('is-syncing'); }
    };
    if (this.plugin.syncing) logo.classList.add('is-syncing');
    const nameEl = head.createDiv({ cls: 'nas-name', text: 'WebDAV nas' });
    nameEl.title = '关于';
    nameEl.setAttribute('role', 'button');
    nameEl.setAttribute('aria-label', '关于');
    nameEl.onclick = () => this._go('about');
    head.createDiv({ cls: 'nas-meta', text: '轻量 WebDAV 同步 · v' + VERSION + ' · 作者 Hadesr' });

    const s = this.plugin.settings;
    const dir = { pull: '只下载', push: '只上传', sync: '双向' }[s.mode] || s.mode;
    const trans = s.granularity === 'full' ? '全部对齐' : '只传变动';
    const rows = [
      { id: 'conn', icon: 'plug', name: '连接与账号', desc: (s.address || '未填地址') + ' · ' + (s.username || '未填用户名') },
      { id: 'sync', icon: 'arrow-left-right', name: '同步方向与方式', desc: dir + ' · ' + trans + ' · 阈值 ' + s.protectRatio + '%' },
      { id: 'auto', icon: 'timer', name: '自动同步', desc: (s.autoOnChange ? '改动后自动' : '改动不自动') + ' · 轮询 ' + (s.autoSyncMinutes || 0) + ' 分钟' },
      { id: 'scope', icon: 'shield', name: '同步范围与安全', desc: (s.syncConfigDir ? '含 .obsidian' : '不含 .obsidian') + ' · ' + (s.confirmDelete ? '删前确认' : '自动删') },
      { id: 'tools', icon: 'wrench', name: '维护与救援', desc: '测试 / 诊断 / 强制对齐 / 重置基线 / 清空回收站' }
    ];

    const self = this;
    rows.forEach(function (r) {
      const row = c.createDiv({ cls: 'nas-nav-row' });
      const ic = row.createDiv({ cls: 'nas-nav-icon' });
      setIcon(ic, r.icon);
      const tx = row.createDiv({ cls: 'nas-nav-text' });
      tx.createEl('div', { cls: 'nas-nav-name', text: r.name });
      tx.createEl('div', { cls: 'nas-nav-desc', text: r.desc });
      const ar = row.createDiv({ cls: 'nas-nav-arrow' });
      setIcon(ar, 'chevron-right');
      row.onclick = function () { self._go(r.id); };
    });

  }

  _renderBack(c, page) {
    const title = { conn: '连接与账号', sync: '同步方向与方式', auto: '自动同步', scope: '同步范围与安全', tools: '维护与救援', about: '关于' }[page] || '设置';
    const back = c.createDiv({ cls: 'nas-back' });
    const ic = back.createSpan({ cls: 'nas-back-icon' });
    setIcon(ic, 'chevron-left');
    back.createSpan({ cls: 'nas-back-title', text: title });
    back.onclick = () => this._go('');
  }

  _pageConn(containerEl) {
    const p = this.plugin;
    new Setting(containerEl).setName('服务器地址').setDesc('例：https://nas.example.com:5006/WebDAV')
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
  }

  _pageSync(containerEl) {
    const p = this.plugin;
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
  }

  _pageAuto(containerEl) {
    const p = this.plugin;
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
  }

  _pageScope(containerEl) {
    const p = this.plugin;
    const strictOnDesc = '开启后：云端没有的 .obsidian 文件、插件、主题会从本机删除（进回收站），让本机与云端完全一致。本插件自己的 data.json 永不更新。';
    const strictOffDesc = '仅在「同步方向 = 只下载」且开启「同步 .obsidian 配置目录」时可用。';
    const canStrict = () => (p.settings.mode || 'push') === 'pull' && !!p.settings.syncConfigDir;

    let strictSetting = null;
    new Setting(containerEl).setName('同步 .obsidian 配置目录')
      .setDesc('⚠️ 默认关。勾上会同步插件/主题/快捷键等配置（密码已加密，可随配置一起同步）。' +
        '风险：多设备配置互相覆盖。已强制排除同步基线、workspace、缓存、*.bak。')
      .addToggle((tg) => tg.setValue(!!p.settings.syncConfigDir)
        .onChange(async (v) => {
          p.settings.syncConfigDir = v;
          await p.saveAll();
          if (strictSetting) {
            strictSetting.setDisabled(!canStrict());
            strictSetting.setDesc(canStrict() ? strictOnDesc : strictOffDesc);
          }
        }));
    strictSetting = new Setting(containerEl).setName('完全同步 .obsidian（删除本机多余插件 / 文件夹）')
      .setDesc(canStrict() ? strictOnDesc : strictOffDesc)
      .addToggle((tg) => tg.setValue(!!p.settings.syncConfigStrict)
        .onChange(async (v) => { p.settings.syncConfigStrict = v; await p.saveAll(); }))
      .setDisabled(!canStrict());
    new Setting(containerEl).setName('严格首同步（关闭首次同步保护）')
      .setDesc('⚠️ 上传/下载本身已是严格镜像（保证两端一毛一样：一边多余就删另一边，含空目录）。' +
        '默认关 = 「首次同步保护」开：第一次同步（基线还空）只合并、不删对端历史文件，避免误清空；建立基线后第二次起就严格相等。' +
        '开启本开关 = 连第一次同步也直接删除多余文件（真正严格，但首次就可能清掉对端没同步过的文件）。' +
        '删除保护阈值现在仅用于双向模式（防回删），上传/下载的删除由「删除前手动确认」+ 空一方中止来保护。')
      .addToggle((tg) => tg.setValue(!!p.settings.mirror)
        .onChange(async (v) => { p.settings.mirror = v; await p.saveAll(); }));
    new Setting(containerEl).setName('删除前手动确认')
      .setDesc('⚠️ 默认开。任何会「删本地文件 / 删云端文件 / 清本地或云端空目录」的操作，' +
        '都会先弹窗列出将要删除的内容，你点「确认删除」才执行；点「取消」则本次跳过所有删除（上传/下载仍照常）。' +
        '验证无误后，关掉本开关即可恢复全自动删除。')
      .addToggle((tg) => tg.setValue(!!p.settings.confirmDelete)
        .onChange(async (v) => { p.settings.confirmDelete = v; await p.saveAll(); }));
    new Setting(containerEl).setName('空白文件夹处理（有 / 无）')
      .setDesc('⚠️ 默认「无」（关）= 绝不做"主动清空目录"，不会误删你刚新建的、或别的设备新建的空白文件夹；' +
        '但「删掉文件后腾出来的空文件夹」仍会自动清理（删文件/改名的传播不受影响）。\n' +
        '「有」（开）= 按方向主动对齐空文件夹：下载听云端（本地多余空目录清掉、云端有的建到本地）、' +
        '上传听本地（本地空目录建到云端）、双向按"谁新听谁"。想彻底清理历史遗留空文件夹时再手动开。')
      .addToggle((tg) => tg.setValue(!!p.settings.syncEmptyDirs)
        .onChange(async (v) => { p.settings.syncEmptyDirs = v; await p.saveAll(); }));
    new Setting(containerEl).setName('隐藏官方同步图标')
      .setDesc('⚠️ 默认关。勾上后：右下角官方的 Obsidian 同步状态图标、以及左侧栏官方的「同步」按钮' +
        '都会被隐藏，只留本插件在右下角的「⇅ WebDAV」图标（点击即可立即同步）。' +
        '想切回官方图标，取消勾选即可。')
      .addToggle((tg) => tg.setValue(!!p.settings.hideOfficialSync)
        .onChange(async (v) => { p.settings.hideOfficialSync = v; await p.saveAll(); p.applyOfficialHide(); }));
    new Setting(containerEl).setName('排除规则')
      .setDesc('逗号分隔。可写目录名或路径前缀，例：.trash, 私人, 附件/大文件')
      .addText((t) => t.setValue(p.settings.exclude)
        .onChange(async (v) => { p.settings.exclude = v; await p.saveAll(); }));
  }

  _pageTools(containerEl) {
    const p = this.plugin;
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
    new Setting(containerEl)
      .setName('清空回收站(.trash)')
      .setDesc('把库内 .trash 里的文件/文件夹永久删除（不可恢复）。' +
        'iOS/安卓的"文件"App 看不到隐藏的 .trash，用这个按钮在 Obsidian 内清空。' +
        '点后会先弹窗列出内容、你确认才删。')
      .addButton((b) => b.setButtonText('清空回收站').setWarning().onClick(() => p.emptyTrash()));
  }

  _pageAbout(containerEl) {
    containerEl.createEl('p', { cls: 'setting-item-description', text: '轻量 WebDAV 同步插件 · 作者 Hadesr · v' + VERSION });
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: '同步进度在通知里显示，不会弹框。' +
        '显示「同步完成」时文件已全部传完；飞牛文件管理器若没马上看到，刷新一下即可（NAS 端索引延迟）。',
    });
  }
}

module.exports = WebdavFnos;
