/* =========================================================
   pynnzcek-end — security.js
   Lapisan proteksi client-side anti-bot / anti-spam.
   CATATAN: Proteksi sesungguhnya tetap harus di sisi server.
   Modul ini menambah friksi & deteksi untuk bot sederhana.
   ========================================================= */
(function (global) {
  'use strict';

  var LS_KEY = 'pynnzcek_ratelimit_v1';
  var MAX_PER_MINUTE = 10;   // maksimal cek per menit
  var MAX_PER_HOUR = 60;     // maksimal cek per jam
  var MIN_PAGE_TIME_MS = 1500; // minimal waktu sejak load sebelum cek pertama

  var pageLoadTime = Date.now();
  var humanInteracted = false;
  var blocked = false;

  /* ---------- 1. Deteksi User-Agent bot ---------- */
  var BOT_PATTERNS = [
    /bot/i, /crawl/i, /spider/i, /slurp/i, /scraper/i, /curl/i, /wget/i,
    /python-requests/i, /httpclient/i, /java\//i, /okhttp/i, /axios/i,
    /phantom/i, /headless/i, /selenium/i, /puppeteer/i, /playwright/i,
    /go-http-client/i, /libwww/i, /nmap/i, /sqlmap/i, /nikto/i, /masscan/i,
    /zgrab/i, /httpx/i, /nuclei/i, /semrush/i, /ahrefs/i, /mj12/i, /dotbot/i
  ];
  function isBotUA() {
    var ua = navigator.userAgent || '';
    for (var i = 0; i < BOT_PATTERNS.length; i++) {
      if (BOT_PATTERNS[i].test(ua)) return true;
    }
    // Headless Chrome / webdriver detection
    if (navigator.webdriver === true) return true;
    if (/HeadlessChrome/i.test(ua)) return true;
    return false;
  }

  /* ---------- 2. Deteksi interaksi manusia ---------- */
  function markHuman() { humanInteracted = true; }
  ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel']
    .forEach(function (ev) {
      window.addEventListener(ev, markHuman, { passive: true, once: true });
    });

  /* ---------- 3. Rate limiting via localStorage ---------- */
  function getLog() {
    try {
      var raw = localStorage.getItem(LS_KEY);
      var arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr : [];
    } catch (e) { return []; }
  }
  function saveLog(arr) {
    try { localStorage.setItem(LS_KEY, JSON.stringify(arr)); } catch (e) {}
  }
  function checkRateLimit() {
    var now = Date.now();
    var log = getLog().filter(function (t) { return now - t < 3600 * 1000; });
    var lastMinute = log.filter(function (t) { return now - t < 60 * 1000; });
    if (lastMinute.length >= MAX_PER_MINUTE) {
      return { ok: false, reason: 'Terlalu banyak request. Tunggu sebentar (limit ' + MAX_PER_MINUTE + '/menit).' };
    }
    if (log.length >= MAX_PER_HOUR) {
      return { ok: false, reason: 'Limit harian tercapai (' + MAX_PER_HOUR + '/jam). Coba lagi nanti.' };
    }
    log.push(now);
    saveLog(log);
    return { ok: true };
  }

  /* ---------- 4. Validasi URL ketat ---------- */
  var BLOCKED_PROTO = ['javascript:', 'data:', 'file:', 'blob:', 'vbscript:', 'about:', 'chrome:', 'view-source:'];
  function validateUrl(raw) {
    if (!raw || typeof raw !== 'string') return { ok: false, reason: 'URL kosong.' };
    var s = raw.trim();
    if (s.length > 2048) return { ok: false, reason: 'URL terlalu panjang (>2048 char).' };
    // blokir karakter berbahaya
    if (/[\s<>"'`\\]/.test(s)) return { ok: false, reason: 'URL mengandung karakter terlarang.' };
    var lower = s.toLowerCase();
    for (var i = 0; i < BLOCKED_PROTO.length; i++) {
      if (lower.indexOf(BLOCKED_PROTO[i]) === 0) {
        return { ok: false, reason: 'Protokol ' + BLOCKED_PROTO[i] + ' diblokir.' };
      }
    }
    var url;
    try {
      url = new URL(s);
    } catch (e) {
      return { ok: false, reason: 'Format URL tidak valid. Gunakan https://...' };
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { ok: false, reason: 'Hanya http/https yang diizinkan.' };
    }
    // blokir IP private / loopback sederhana (opsional, bisa dimatikan)
    var host = url.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' ||
        /^192\.168\./.test(host) || /^10\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
        host.endsWith('.internal') || host.endsWith('.local')) {
      return { ok: false, reason: 'Akses ke alamat private/internal diblokir (SSRF protection).' };
    }
    return { ok: true, url: url.toString() };
  }

  /* ---------- 5. Math CAPTCHA sederhana ---------- */
  var captchaA = 0, captchaB = 0;
  function newCaptcha() {
    captchaA = Math.floor(Math.random() * 9) + 1;
    captchaB = Math.floor(Math.random() * 9) + 1;
    return { a: captchaA, b: captchaB };
  }
  function checkCaptcha(answer) {
    var n = parseInt(answer, 10);
    return !isNaN(n) && n === captchaA + captchaB;
  }

  /* ---------- 6. Gate utama: dipanggil sebelum setiap cek ---------- */
  function gate(opts) {
    // opts: { honeypotValue, captchaAnswer, url }
    if (blocked) return { ok: false, reason: 'Akses diblokir karena terdeteksi aktivitas mencurigakan.' };

    // 6a. Honeypot: kalau terisi = bot
    if (opts.honeypotValue && opts.honeypotValue.trim() !== '') {
      blocked = true;
      return { ok: false, reason: 'Terdeteksi aktivitas otomatis (honeypot).' };
    }
    // 6b. Deteksi UA bot
    if (isBotUA()) {
      blocked = true;
      return { ok: false, reason: 'User-Agent terdeteksi sebagai bot/automation.' };
    }
    // 6c. Time gate: terlalu cepat setelah load = bot
    if (Date.now() - pageLoadTime < MIN_PAGE_TIME_MS) {
      return { ok: false, reason: 'Terlalu cepat. Tunggu ' + Math.ceil((MIN_PAGE_TIME_MS - (Date.now() - pageLoadTime)) / 1000) + ' detik lagi.' };
    }
    // 6d. Interaksi manusia
    if (!humanInteracted) {
      return { ok: false, reason: 'Geser/klik/ketik dulu di halaman ini untuk membuktikan kamu manusia.' };
    }
    // 6e. Captcha
    if (!checkCaptcha(opts.captchaAnswer)) {
      return { ok: false, reason: 'Jawaban human-check salah. Coba lagi.' };
    }
    // 6f. Validasi URL
    var v = validateUrl(opts.url);
    if (!v.ok) return v;
    // 6g. Rate limit
    var r = checkRateLimit();
    if (!r.ok) return r;

    return { ok: true, url: v.url };
  }

  /* ---------- Public API ---------- */
  global.PynnzcekSecurity = {
    gate: gate,
    newCaptcha: newCaptcha,
    validateUrl: validateUrl,
    isBotUA: isBotUA,
    MIN_PAGE_TIME_MS: MIN_PAGE_TIME_MS,
    MAX_PER_MINUTE: MAX_PER_MINUTE,
    MAX_PER_HOUR: MAX_PER_HOUR
  };
})(window);
