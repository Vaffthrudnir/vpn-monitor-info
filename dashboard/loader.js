/* VPN Monitor browser loader. No external dependencies; ciphertext-only cache. */
(function (global) {
  'use strict';
  const LIMIT = Object.freeze({manifest: 64 * 1024, encrypted: 16 * 1024 * 1024,
    plaintext: 64 * 1024 * 1024, refs: 1200, points: 10000, series: 1000,
    totalFetched: 192 * 1024 * 1024, totalPlain: 256 * 1024 * 1024});
  const REF = /^objects\/[a-f0-9]{64}\.json$/;
  const SERIES_FIELDS = ['avg', 'min', 'max', 'valid_seconds', 'coverage_pct', 'source', 'peak_at'];
  const REQUIRED_FIELDS = ['avg', 'min', 'max', 'valid_seconds', 'coverage_pct'];
  const AAD = new TextEncoder().encode('vpnmon-web-v1');
  const INFLIGHT = new Set();
  const has = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const fail = message => { throw new Error(message); };

  function validateRef(ref) {
    if (typeof ref !== 'string' || !REF.test(ref)) fail('Некорректный путь фрагмента в архиве.');
    return ref;
  }
  function base64(value, maxBytes) {
    if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 + 4
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      fail('Некорректная кодировка зашифрованного объекта.');
    }
    let raw;
    try { raw = atob(value); } catch (_) { fail('Некорректная кодировка объекта.'); }
    if (raw.length > maxBytes) fail('Размер объекта превышает предел.');
    return Uint8Array.from(raw, ch => ch.charCodeAt(0));
  }
  function decodeJSON(bytes) {
    try {
      return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes), (key, value) => {
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') fail('Недопустимое поле JSON.');
        return value;
      });
    } catch (_) { fail('Не удалось прочитать JSON архива.'); }
  }
  function validateManifest(value) {
    if (!object(value) || value.schema !== 1 || typeof value.updated_at !== 'string'
        || !Number.isFinite(Date.parse(value.updated_at)) || typeof value.key_id !== 'string'
        || !/^[a-f0-9]{16,128}$/.test(value.key_id) || !object(value.kdf)) {
      fail('Версия или структура манифеста не поддерживается.');
    }
    const kdf = value.kdf;
    if (kdf.name !== 'PBKDF2' || kdf.hash !== 'SHA-256' || !Number.isInteger(kdf.iterations)
        || kdf.iterations < 310000 || kdf.iterations > 2000000) fail('Неподдерживаемые параметры шифрования.');
    const salt = base64(kdf.salt, 64);
    if (salt.length < 16 || salt.length > 64) fail('Некорректная соль шифрования.');
    validateRef(value.catalog); validateRef(value.renderer);
    return value;
  }
  function keyIdentity(manifest) {
    return [manifest.key_id, manifest.kdf.name, manifest.kdf.hash, manifest.kdf.iterations, manifest.kdf.salt].join(':');
  }
  async function deriveKey(password, manifest) {
    validateManifest(manifest);
    if (typeof password !== 'string' || !password.length || password.length > 1024) fail('Введите пароль панели.');
    const material = await global.crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return global.crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256',
      iterations: manifest.kdf.iterations, salt: base64(manifest.kdf.salt, 64)},
      material, {name: 'AES-GCM', length: 256}, false, ['decrypt']);
  }
  async function verifyHash(bytes, ref) {
    validateRef(ref);
    const digest = new Uint8Array(await global.crypto.subtle.digest('SHA-256', bytes));
    const hex = Array.from(digest, x => x.toString(16).padStart(2, '0')).join('');
    if (hex !== ref.slice(8, -5)) fail('Контрольная сумма фрагмента не совпала. Повторите обновление.');
  }
  async function collectStream(stream, limit) {
    const reader = stream.getReader();
    const parts = []; let total = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > limit) { await reader.cancel(); fail('Размер распакованных данных превышает предел.'); }
        parts.push(value);
      }
    } finally { reader.releaseLock(); }
    const result = new Uint8Array(total); let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
    return result;
  }
  async function decryptObject(bytes, key) {
    if (bytes.byteLength > LIMIT.encrypted) fail('Зашифрованный объект слишком велик.');
    const envelope = decodeJSON(bytes);
    if (!object(envelope) || envelope.v !== 1) fail('Неподдерживаемый формат объекта.');
    const nonce = base64(envelope.nonce, 12), ciphertext = base64(envelope.ciphertext, LIMIT.encrypted);
    if (nonce.length !== 12 || ciphertext.length < 16) fail('Некорректный зашифрованный объект.');
    let compressed;
    try { compressed = await global.crypto.subtle.decrypt({name: 'AES-GCM', iv: nonce, additionalData: AAD, tagLength: 128}, key, ciphertext); }
    catch (_) { fail('Не удалось расшифровать данные. Проверьте пароль панели.'); }
    if (typeof global.DecompressionStream !== 'function') fail('Браузер не поддерживает распаковку gzip. Обновите Safari, Chrome или Firefox.');
    let plain;
    try { plain = await collectStream(new Blob([compressed]).stream().pipeThrough(new global.DecompressionStream('gzip')), LIMIT.plaintext); }
    catch (error) { if (error.message?.includes('предел')) throw error; fail('Не удалось распаковать расшифрованный архив.'); }
    return {value: decodeJSON(plain), plainBytes: plain.byteLength};
  }
  function arrayColumn(value, length, label, numeric = false) {
    if (!Array.isArray(value) || value.length !== length) fail('Размер столбца не совпал: ' + label);
    if (numeric && value.some(x => x !== null && !finite(x))) fail('Некорректное число в столбце: ' + label);
  }
  function validateColumns(columns) {
    if (!object(columns) || !Array.isArray(columns.timestamps) || columns.timestamps.length > LIMIT.points
        || !object(columns.series) || Object.keys(columns.series).length > LIMIT.series) fail('Некорректная структура временного фрагмента.');
    const length = columns.timestamps.length;
    let previous = -Infinity;
    for (const stamp of columns.timestamps) {
      if (!finite(stamp) || stamp <= previous) fail('Временная шкала фрагмента должна возрастать.');
      previous = stamp;
    }
    arrayColumn(columns.bins, length, 'bins');
    arrayColumn(columns.coverage_seconds, length, 'coverage_seconds', true);
    for (const bin of columns.bins) {
      const start = Array.isArray(bin) ? bin[0] : bin?.start, end = Array.isArray(bin) ? bin[1] : bin?.end;
      if (!finite(start) || !finite(end) || end <= start) fail('Некорректные границы временного интервала.');
    }
    for (const [metric, values] of Object.entries(columns.series)) {
      if (!object(values)) fail('Некорректный ряд: ' + metric);
      for (const field of REQUIRED_FIELDS) arrayColumn(values[field], length, metric + '/' + field, true);
      for (const field of ['source', 'peak_at']) if (has(values, field)) {
        arrayColumn(values[field], length, metric + '/' + field, field === 'peak_at');
        if (field === 'source' && values[field].some(x => x !== null && typeof x !== 'string')) fail('Некорректный источник ряда.');
      }
    }
    if (columns.counter_totals !== undefined) {
      if (!object(columns.counter_totals)) fail('Некорректные счётчики.');
      for (const [counter, values] of Object.entries(columns.counter_totals)) arrayColumn(values, length, counter, true);
    }
    return columns;
  }
  function validateCatalog(catalog) {
    if (!object(catalog) || catalog.schema !== 1 || !object(catalog.payload)
        || !object(catalog.payload.periods) || !object(catalog.chunks)) fail('Неподдерживаемая структура каталога.');
    const periods = Object.keys(catalog.payload.periods);
    if (!periods.length || periods.length > 4 || periods.some(x => !['24h', '7d', '30d', 'mtd'].includes(x))) fail('Некорректный список периодов.');
    const refs = [];
    for (const period of periods) {
      const nodes = catalog.payload.periods[period];
      if (!object(nodes) || Object.keys(nodes).some(n => !['ru', 'fr'].includes(n))) fail('Некорректный список узлов.');
      for (const [node, data] of Object.entries(nodes)) {
        if (!object(data) || !object(data.report)) fail('Некорректный отчёт узла.');
        const chunks = catalog.chunks[period]?.[node] || [];
        if (!Array.isArray(chunks)) fail('Некорректный список фрагментов.');
        if (data.ts !== null && data.ts !== undefined) {
          if (!object(data.ts) || !object(data.ts.series) || !object(data.ts.period)) fail('Некорректные метаданные графиков.');
          if (has(data.ts, 'timestamps') || has(data.ts, 'bins') || has(data.ts, 'coverage_seconds')) fail('В каталоге обнаружены неразделённые временные ряды.');
        } else if (chunks.length) fail('Нет метаданных для временных фрагментов.');
        for (const ref of chunks) refs.push(validateRef(ref));
      }
    }
    if (refs.length > LIMIT.refs) fail('Слишком много фрагментов архива.');
    return [...new Set(refs)];
  }
  function assemble(catalog, chunks) {
    validateCatalog(catalog);
    const payload = JSON.parse(JSON.stringify(catalog.payload));
    for (const [period, nodes] of Object.entries(payload.periods)) {
      for (const [node, data] of Object.entries(nodes)) {
        const ts = data.ts;
        if (!ts) continue;
        const refs = catalog.chunks[period]?.[node] || [];
        ts.timestamps = []; ts.bins = []; ts.coverage_seconds = [];
        if (!object(ts.counter_totals)) ts.counter_totals = {};
        for (const key of Object.keys(ts.counter_totals)) ts.counter_totals[key] = [];
        const seenFields = new Map();
        for (const [metric, series] of Object.entries(ts.series)) {
          if (!object(series)) fail('Некорректные метаданные ряда.');
          for (const field of SERIES_FIELDS) {
            if (Array.isArray(series[field])) fail('В каталоге обнаружен неразделённый ряд.');
            series[field] = [];
          }
          seenFields.set(metric, new Set());
        }
        let last = -Infinity;
        for (const ref of refs) {
          const part = chunks.get(ref);
          if (!object(part) || part.schema !== 1 || part.kind !== 'timeseries') fail('Не найден корректный временной фрагмент.');
          const col = validateColumns(part.columns), n = col.timestamps.length;
          if (n && col.timestamps[0] <= last) fail('Временные фрагменты пересекаются или расположены не по порядку.');
          if (ts.timestamps.length + n > LIMIT.points) fail('Слишком много точек в периоде.');
          if (Object.keys(col.series).some(key => !has(ts.series, key))) fail('Состав метрик фрагмента отличается от каталога.');
          const oldLength = ts.timestamps.length;
          ts.timestamps.push(...col.timestamps); ts.bins.push(...col.bins); ts.coverage_seconds.push(...col.coverage_seconds);
          for (const metric of Object.keys(ts.series)) {
            const values = col.series[metric] || {};
            for (const field of SERIES_FIELDS) {
              const valuesArray = has(values, field) ? values[field] : new Array(n).fill(null);
              ts.series[metric][field].push(...valuesArray);
              if (has(values, field)) seenFields.get(metric).add(field);
            }
          }
          const counters = col.counter_totals || {};
          for (const counter of Object.keys(counters)) if (!has(ts.counter_totals, counter)) {
            ts.counter_totals[counter] = new Array(oldLength).fill(null);
          }
          for (const counter of Object.keys(ts.counter_totals)) ts.counter_totals[counter].push(...(counters[counter] || new Array(n).fill(null)));
          if (n) last = col.timestamps[n - 1];
        }
        for (const [metric, fields] of seenFields) {
          for (const optional of ['source', 'peak_at']) if (!fields.has(optional)) delete ts.series[metric][optional];
        }
      }
    }
    return payload;
  }
  function escapeJSON(value) {
    return JSON.stringify(value).replace(/&/g, '\\u0026').replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
      .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  }
  function renderHTML(template, payload, nonce) {
    if (typeof template !== 'string' || template.length > 2 * 1024 * 1024
        || template.split('__DATA__').length !== 2 || template.split('__SESSION_NONCE__').length !== 2) fail('Некорректный шаблон панели.');
    const csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\'; img-src data: blob:; connect-src \'none\'; form-action \'none\'; base-uri \'none\'">';
    let html = template.replace('__DATA__', () => escapeJSON(payload)).replace('__SESSION_NONCE__', () => escapeJSON(nonce));
    if (!/<head(?:\s[^>]*)?>/i.test(html)) fail('В шаблоне отсутствует head.');
    return html.replace(/<head(?:\s[^>]*)?>/i, match => match + csp);
  }

  class CipherCache {
    constructor() { this.db = null; this.memory = new Map(); this.memoryBytes = 0; this.failed = false; }
    async open() {
      if (this.db || this.failed) return;
      if (!global.indexedDB) { this.failed = true; return; }
      try {
        this.db = await new Promise((resolve, reject) => {
          const req = global.indexedDB.open('vpnmon-encrypted-cache-v1', 1);
          req.onupgradeneeded = () => req.result.createObjectStore('objects', {keyPath: 'ref'});
          req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error);
          req.onblocked = () => reject(new Error('cache blocked'));
        });
      } catch (_) { this.failed = true; }
    }
    async operation(mode, fn) {
      await this.open();
      if (!this.db) return null;
      return new Promise((resolve, reject) => {
        const tx = this.db.transaction('objects', mode); let request;
        try { request = fn(tx.objectStore('objects')); } catch (error) { reject(error); return; }
        tx.oncomplete = () => resolve(request?.result ?? null);
        tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error);
      });
    }
    async get(ref) {
      if (this.memory.has(ref)) return this.memory.get(ref);
      try {
        const row = await this.operation('readonly', store => store.get(ref));
        if (row?.bytes instanceof ArrayBuffer && row.bytes.byteLength <= LIMIT.encrypted) return new Uint8Array(row.bytes);
      } catch (_) { this.failed = true; }
      return null;
    }
    async put(ref, bytes) {
      // No plaintext, key or password enters this cache.
      if (this.memoryBytes + bytes.byteLength <= 32 * 1024 * 1024 && !this.memory.has(ref)) {
        this.memory.set(ref, bytes); this.memoryBytes += bytes.byteLength;
      }
      try { await this.operation('readwrite', store => store.put({ref, bytes: bytes.slice().buffer, savedAt: Date.now()})); }
      catch (_) { this.failed = true; }
    }
    async remove(ref) {
      const saved = this.memory.get(ref); if (saved) this.memoryBytes -= saved.byteLength;
      this.memory.delete(ref);
      try { await this.operation('readwrite', store => store.delete(ref)); } catch (_) { this.failed = true; }
    }
    async retain(refs) {
      const keep = new Set(refs);
      for (const ref of [...this.memory.keys()]) if (!keep.has(ref)) {
        this.memoryBytes -= this.memory.get(ref).byteLength; this.memory.delete(ref);
      }
      try { await this.operation('readwrite', store => {
        const req = store.openCursor();
        req.onsuccess = () => { const cursor = req.result; if (!cursor) return; if (!keep.has(cursor.key)) cursor.delete(); cursor.continue(); };
        return undefined;
      }); } catch (_) { this.failed = true; }
    }
    async clear() {
      this.memory.clear(); this.memoryBytes = 0;
      try { await this.operation('readwrite', store => store.clear()); } catch (_) { this.failed = true; }
    }
  }

  async function fetchBytes(url, limit, options = {}) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 30000);
    INFLIGHT.add(controller);
    try {
      const response = await fetch(url, {credentials: 'omit', redirect: 'error', signal: controller.signal, ...options});
      if (!response.ok) fail(response.status === 404 ? 'Архив ещё не опубликован или обновляется. Повторите позже.' : 'Сайт вернул ошибку HTTP ' + response.status + '.');
      const declared = Number(response.headers.get('content-length'));
      if (declared > limit) fail('Размер ответа превышает предел.');
      if (!response.body) fail('Браузер не предоставляет поток ответа.');
      return await collectStream(response.body, limit);
    } catch (error) {
      if (error.name === 'AbortError') fail('Сайт не ответил за 30 секунд. Сохранённая панель остаётся доступной.');
      throw error;
    } finally { clearTimeout(timeout); INFLIGHT.delete(controller); }
  }
  async function parallelMap(values, count, fn) {
    let next = 0;
    await Promise.all(Array.from({length: Math.min(count, values.length)}, async () => {
      while (next < values.length) { const index = next++; await fn(values[index], index); }
    }));
  }

  // The pure API is also exercised by Node/WebCrypto tests.
  const API = {LIMIT, validateRef, validateManifest, keyIdentity, deriveKey, verifyHash,
    decryptObject, validateColumns, validateCatalog, assemble, escapeJSON, renderHTML, CipherCache};
  global.VPNMonLoaderCore = Object.freeze(API);
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  if (!global.document) return;

  const $ = id => global.document.getElementById(id);
  const cache = new CipherCache();
  const state = {key: null, identity: null, generation: 0, busy: false, timer: null,
    catalogRef: null, rendererRef: null, renderer: null, frame: null, nonce: null,
    lastSuccess: null, updatedAt: null, measurementTimes: {ru:null,fr:null}};
  function date(value) { return new Date(value).toLocaleString('ru-RU', {timeZone: 'Europe/Moscow', day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit'}) + ' МСК'; }
  function progress(text) { $('progress').textContent = text; }
  function setError(message, login = false) {
    const element = $(login ? 'loginError' : 'updateError'); element.textContent = message || ''; element.hidden = !message;
  }
  function paintStatus(label, level = '') {
    $('connectionStatus').textContent = label; $('statusDot').className = 'state-dot ' + level;
    $('sourceTime').textContent = 'Архив: ' + (state.updatedAt ? date(state.updatedAt) : '—');
    $('successTime').textContent = 'Получено: ' + (state.lastSuccess ? date(state.lastSuccess) : '—');
    $('measurementTime').textContent = 'Измерения: ' + ['ru','fr'].map(node => {
      const stamp = state.measurementTimes[node];
      if (!finite(stamp)) return node.toUpperCase() + ' — нет данных';
      const minutes = Math.max(0, Math.floor((Date.now() - stamp * 1000) / 60000));
      const age = minutes < 1 ? 'менее минуты назад' : minutes < 60 ? minutes + ' мин назад'
        : minutes < 1440 ? Math.floor(minutes / 60) + ' ч назад' : Math.floor(minutes / 1440) + ' дн назад';
      return node.toUpperCase() + ' ' + age;
    }).join(' · ');
  }
  function staleStatus() {
    if (state.updatedAt && Date.now() - Date.parse(state.updatedAt) > 30 * 60 * 1000) return 'Архив давно не обновлялся';
    if (Object.values(state.measurementTimes).some(t => !finite(t) || Date.now() - t * 1000 > 30 * 60 * 1000)) return 'Есть устаревшие или отсутствующие измерения';
    return null;
  }
  function checkBrowser() {
    if (!global.isSecureContext || !global.crypto?.subtle) fail('Откройте панель по HTTPS в современном браузере.');
    if (typeof global.DecompressionStream !== 'function') fail('Браузер не поддерживает распаковку gzip. Обновите Safari, Chrome или Firefox.');
  }
  async function loadManifest() {
    const bytes = await fetchBytes(new URL('manifest.json', global.document.baseURI), LIMIT.manifest, {cache: 'no-cache'});
    return validateManifest(decodeJSON(bytes));
  }
  async function applyManifest(manifest, epoch) {
    if (state.identity !== keyIdentity(manifest)) fail('Ключ архива изменён. Закройте панель и откройте её с новым паролем.');
    if (state.catalogRef === manifest.catalog && state.rendererRef === manifest.renderer) {
      state.updatedAt = manifest.updated_at;
      const stale = staleStatus(); paintStatus(stale || 'Актуальная версия', stale ? 'warn' : 'ok');
      $('trafficInfo').textContent = 'Новых фрагментов нет'; return;
    }
    const decoded = new Map(); let fetched = 0, reused = 0, networkBytes = 0, plainBytes = 0;
    const sessionKey = state.key;
    async function load(ref) {
      validateRef(ref);
      if (decoded.has(ref)) return decoded.get(ref);
      let bytes = await cache.get(ref);
      if (bytes) {
        try { await verifyHash(bytes, ref); reused++; }
        catch (_) { await cache.remove(ref); bytes = null; }
      }
      if (!bytes) {
        bytes = await fetchBytes(new URL(ref, global.document.baseURI), LIMIT.encrypted, {cache: 'force-cache'});
        await verifyHash(bytes, ref); fetched++; networkBytes += bytes.byteLength;
        if (networkBytes > LIMIT.totalFetched) fail('Общий размер обновления превышает предел.');
        await cache.put(ref, bytes);
      }
      if (epoch !== state.generation || !state.key) fail('Панель закрыта.');
      const unpacked = await decryptObject(bytes, sessionKey);
      plainBytes += unpacked.plainBytes;
      if (plainBytes > LIMIT.totalPlain) fail('Общий объём распакованного архива превышает предел.');
      decoded.set(ref, unpacked.value);
      progress('Чтение фрагментов: ' + (fetched + reused) + ' · новых ' + fetched);
      return unpacked.value;
    }
    const catalog = await load(manifest.catalog), refs = validateCatalog(catalog);
    await parallelMap(refs, 4, load);
    let renderer = state.renderer;
    if (state.rendererRef !== manifest.renderer || !renderer) {
      const value = await load(manifest.renderer);
      if (!object(value) || value.kind !== 'renderer' || typeof value.html !== 'string') fail('Неподдерживаемый шаблон панели.');
      renderer = value.html;
    }
    const payload = assemble(catalog, decoded);
    if (epoch !== state.generation || !state.key) return;
    if (!state.frame || state.rendererRef !== manifest.renderer) {
      const nonce = Array.from(global.crypto.getRandomValues(new Uint8Array(24)), x => x.toString(16).padStart(2,'0')).join('');
      const html = renderHTML(renderer, payload, nonce), frame = global.document.createElement('iframe');
      frame.className = 'panel'; frame.title = 'Аналитика российского и французского серверов';
      frame.setAttribute('sandbox', 'allow-scripts allow-downloads'); frame.setAttribute('referrerpolicy', 'no-referrer');
      frame.srcdoc = html; frame.hidden = true;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { frame.remove(); reject(new Error('Панель не завершила загрузку.')); }, 20000);
        frame.addEventListener('load', () => { clearTimeout(timer); resolve(); }, {once: true});
        $('panelHost').append(frame);
      });
      if (epoch !== state.generation || !state.key) { frame.remove(); return; }
      state.frame?.remove(); state.frame = frame; state.nonce = nonce; frame.hidden = false;
    } else {
      state.frame.contentWindow.postMessage({type: 'vpnmon-data', nonce: state.nonce, data: payload}, '*');
    }
    state.catalogRef = manifest.catalog; state.rendererRef = manifest.renderer; state.renderer = renderer;
    state.lastSuccess = Date.now(); state.updatedAt = manifest.updated_at;
    state.measurementTimes = {ru:null,fr:null};
    for (const nodes of Object.values(payload.periods)) for (const node of ['ru','fr']) {
      const stamp = nodes[node]?.report?.latest_sample_ts;
      if (finite(stamp) && (state.measurementTimes[node] === null || stamp > state.measurementTimes[node])) state.measurementTimes[node] = stamp;
    }
    $('loginCard').hidden = true; $('loginFootnote').hidden = true;
    $('statusBar').hidden = false; $('lockButton').hidden = false;
    $('trafficInfo').textContent = 'Новых фрагментов: ' + fetched + ' · из кеша: ' + reused + ' · ' + (networkBytes / 1024).toLocaleString('ru-RU',{maximumFractionDigits:1}) + ' КБ';
    const stale = staleStatus(); paintStatus(stale || 'Панель обновлена', stale ? 'warn' : 'ok');
    setError(''); progress('');
    // Delete ciphertext no longer referenced by this complete snapshot, after success.
    await cache.retain([manifest.catalog, manifest.renderer, ...refs]);
  }
  async function refresh() {
    if (!state.key || state.busy) return;
    const epoch = state.generation; state.busy = true; $('refreshButton').disabled = true;
    try { paintStatus('Проверяем обновления'); await applyManifest(await loadManifest(), epoch); }
    catch (error) {
      if (epoch === state.generation && state.key) {
        paintStatus('Обновление не получено', 'warn');
        setError((error.message || 'Ошибка загрузки.') + ' Последняя успешно открытая панель сохранена.');
      }
    } finally { if (epoch === state.generation) { state.busy = false; $('refreshButton').disabled = false; } }
  }
  function lock() {
    state.generation++; state.key = null; state.identity = null; state.renderer = null;
    for (const controller of INFLIGHT) controller.abort();
    state.busy = false; $('unlockButton').disabled = false; $('refreshButton').disabled = false;
    state.catalogRef = null; state.rendererRef = null; state.nonce = null;
    state.lastSuccess = null; state.updatedAt = null; clearInterval(state.timer); state.timer = null;
    state.measurementTimes = {ru:null,fr:null};
    state.frame?.remove(); state.frame = null; $('panelHost').replaceChildren();
    $('dashboardPassword').value = ''; $('dashboardPassword').type = 'password';
    $('showPassword').textContent = 'Показать'; $('showPassword').setAttribute('aria-pressed','false');
    $('loginCard').hidden = false; $('loginFootnote').hidden = false;
    $('statusBar').hidden = true; $('lockButton').hidden = true;
    setError(''); setError('', true); progress(''); $('dashboardPassword').focus();
  }
  $('unlockForm').addEventListener('submit', async event => {
    event.preventDefault(); if (state.busy) return;
    state.busy = true; const epoch = ++state.generation; $('unlockButton').disabled = true;
    let password = $('dashboardPassword').value; $('dashboardPassword').value = '';
    setError('', true); progress('Проверка архива…');
    try {
      checkBrowser(); const manifest = await loadManifest(); progress('Расшифровка…');
      const key = await deriveKey(password, manifest); password = null;
      if (epoch !== state.generation) return;
      state.key = key; state.identity = keyIdentity(manifest);
      await applyManifest(manifest, epoch);
      if (epoch === state.generation && state.key) state.timer = setInterval(refresh, 60000);
    } catch (error) {
      if (epoch === state.generation) { state.key = null; state.identity = null; setError(error.message || 'Ошибка открытия панели.', true); progress(''); }
    } finally { password = null; if (epoch === state.generation) { state.busy = false; $('unlockButton').disabled = false; } }
  });
  $('showPassword').addEventListener('click', () => {
    const reveal = $('dashboardPassword').type === 'password'; $('dashboardPassword').type = reveal ? 'text' : 'password';
    $('showPassword').textContent = reveal ? 'Скрыть' : 'Показать'; $('showPassword').setAttribute('aria-pressed', String(reveal));
  });
  $('lockButton').addEventListener('click', lock);
  $('refreshButton').addEventListener('click', refresh);
  $('cacheButton').addEventListener('click', async () => {
    if (state.busy) return; await cache.clear(); $('trafficInfo').textContent = 'Кеш очищен; текущая панель остаётся открытой.';
  });
  global.addEventListener('pagehide', lock);
  global.addEventListener('online', refresh);
})(typeof window === 'undefined' ? globalThis : window);
