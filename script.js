/* =========================================================
   pynnzcek-end — script.js
   create by pynnzdev
   ========================================================= */
(function () {
  'use strict';

  var TIMEOUT = 20000;
  var PREVIEW_MAX = 1500;

  var inp = document.getElementById('inp');
  var btn = document.getElementById('btn');
  var result = document.getElementById('result');
  var hp = document.getElementById('hp_field');           // honeypot
  var captchaQ = document.getElementById('captcha_q');
  var captchaInp = document.getElementById('captcha_ans');
  var captchaRefresh = document.getElementById('captcha_refresh');
  var secStatus = document.getElementById('sec_status');
  var busy = false;

  var Sec = window.PynnzcekSecurity;

  /* ---------- helpers ---------- */
  function esc(s) {
    if (s == null) s = '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function bytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(2) + ' MB';
  }
  function setSecStatus(text, cls) {
    secStatus.textContent = text;
    secStatus.className = 'sec-status ' + cls;
  }
  function refreshCaptcha() {
    var c = Sec.newCaptcha();
    captchaQ.textContent = c.a + ' + ' + c.b + ' = ?';
    captchaInp.value = '';
    setSecStatus('belum dijawab', 'pending');
  }

  /* ---------- fetch endpoint ---------- */
  async function checkEndpoint(url) {
    var start = performance.now();
    var ctl = new AbortController();
    var to = setTimeout(function () { ctl.abort(); }, TIMEOUT);
    try {
      var r = await fetch(url, {
        method: 'GET', signal: ctl.signal, redirect: 'follow', mode: 'cors',
        credentials: 'omit', referrerPolicy: 'no-referrer'
      });
      clearTimeout(to);
      var elapsed = Math.round(performance.now() - start);
      var text = await r.text();
      return {
        ok: true, status: r.status, statusText: r.statusText, ms: elapsed,
        contentType: r.headers.get('content-type') || '-',
        server: r.headers.get('server') || '-',
        size: text.length, body: text
      };
    } catch (e) {
      clearTimeout(to);
      return {
        ok: false,
        error: e.name === 'AbortError' ? 'timeout > 20s' : (e.message || 'gagal'),
        ms: Math.round(performance.now() - start)
      };
    }
  }

  /* ---------- klasifikasi hasil ---------- */
  function classify(info) {
    if (!info.ok) {
      var isTo = info.error.indexOf('timeout') !== -1;
      return {
        tag: 'FAILED', cls: 'bad',
        title: isTo ? 'Endpoint gak nyahut (timeout)' : 'Endpoint gagal diakses',
        desc: isTo
          ? 'Server gak kasih respon dalam 20 detik. Bisa jadi down, lemot banget, atau URL-nya salah.'
          : 'Browser gagal nyambung. Kemungkinan CORS blocked, koneksi internet bermasalah, atau domain gak exist.',
        badge: 'failed'
      };
    }
    if (info.status >= 200 && info.status < 300) {
      var spd = info.ms < 500 ? 'cepat' : info.ms < 1500 ? 'oke' : info.ms < 3000 ? 'lemot' : 'lemot banget';
      return {
        tag: 'ALIVE', cls: 'ok',
        title: 'Endpoint nyala - status ' + info.status,
        desc: 'Respon masuk dalam ' + info.ms + ' ms (' + spd + '). Content-type: ' + info.contentType + '. Ukuran body ' + bytes(info.size) + '.',
        badge: 'alive'
      };
    }
    if (info.status >= 300 && info.status < 400) {
      return { tag: 'REDIRECT', cls: 'warn', title: 'Endpoint redirect - status ' + info.status, desc: 'Server ngarahin ke URL lain. Cek header location buat liat tujuan.', badge: 'redirect' };
    }
    if (info.status >= 400 && info.status < 500) {
      return { tag: 'CLIENT ERR', cls: 'warn', title: 'Error dari sisi client - ' + info.status, desc: 'Request ditolak server. Kemungkinan butuh auth, param kurang, atau endpoint emang gak ada.', badge: '4xx' };
    }
    return { tag: 'SERVER ERR', cls: 'bad', title: 'Error dari sisi server - ' + info.status, desc: 'Server-nya sendiri error. Bukan salah lo, coba lagi nanti atau hubungi yang punya API.', badge: '5xx' };
  }

  /* ---------- render hasil ---------- */
  function renderResult(info) {
    var c = classify(info);
    var h = '';
    h += '<div class="step"><div class="step-hd"><span class="n">!</span>Hasil Cek<span class="badge">' + c.badge + '</span></div><div class="step-body">';
    h += '<div class="summary">';
    h += '<div class="line ' + c.cls + '"><span class="ic">' + (c.cls === 'ok' ? 'OK' : c.cls === 'bad' ? 'X' : '!') + '</span>' + esc(c.title) + '</div>';
    h += '<div class="desc">' + esc(c.desc) + '</div>';
    h += '</div>';
    if (info.ok) {
      var statusCls = (info.status >= 200 && info.status < 300) ? 'ok' : (info.status >= 300 && info.status < 400) ? 'info' : (info.status >= 400 && info.status < 500) ? 'warn' : 'bad';
      var speedCls = info.ms < 500 ? 'ok' : (info.ms < 2000 ? 'info' : 'warn');
      h += '<div class="kv">';
      h += '<div class="item ' + statusCls + '"><div class="lbl">Status</div><div class="val">' + info.status + ' ' + esc(info.statusText || '') + '</div></div>';
      h += '<div class="item ' + speedCls + '"><div class="lbl">Response Time</div><div class="val">' + info.ms + ' ms</div></div>';
      h += '<div class="item info"><div class="lbl">Size</div><div class="val">' + bytes(info.size) + '</div></div>';
      h += '<div class="item info"><div class="lbl">Content-Type</div><div class="val" style="font-size:12px">' + esc(info.contentType) + '</div></div>';
      h += '</div>';
      h += '<div class="sec-title">Body Preview (first ' + PREVIEW_MAX + ' char)</div>';
      var preview = info.body.slice(0, PREVIEW_MAX);
      h += '<div class="preview">' + esc(preview) + (info.body.length > PREVIEW_MAX ? '\n\n... (truncated ' + info.body.length + ' total char)' : '') + '</div>';
    } else {
      h += '<div class="kv">';
      h += '<div class="item bad"><div class="lbl">Status</div><div class="val">GAGAL</div></div>';
      h += '<div class="item warn"><div class="lbl">Waktu</div><div class="val">' + info.ms + ' ms</div></div>';
      h += '</div>';
      h += '<div class="sec-title">Error Message</div>';
      h += '<div class="preview bad">' + esc(info.error) + '</div>';
    }
    h += '</div></div>';
    return h;
  }

  function renderBlocked(reason) {
    return '<div class="step"><div class="step-hd"><span class="n">X</span>Dihentikan Sistem Keamanan<span class="badge">blocked</span></div><div class="step-body">' +
      '<div class="summary"><div class="line bad"><span class="ic">X</span>Request dibatalkan</div>' +
      '<div class="desc">' + esc(reason) + '</div></div></div></div>';
  }

  /* ---------- main flow ---------- */
  async function runCek() {
    if (busy) return;
    var url = inp.value.trim();
    if (!url) { inp.focus(); return; }
    if (url.indexOf('http') !== 0) url = 'https://' + url;

    // === SECURITY GATE ===
    var g = Sec.gate({
      honeypotValue: hp ? hp.value : '',
      captchaAnswer: captchaInp.value,
      url: url
    });
    if (!g.ok) {
      result.innerHTML = renderBlocked(g.reason);
      setSecStatus('ditolak', 'blocked');
      refreshCaptcha();
      return;
    }
    url = g.url;
    setSecStatus('lolos', 'ok');

    busy = true;
    btn.disabled = true;
    result.innerHTML = '<div class="step"><div class="step-hd"><span class="n">...</span>Ngecek Endpoint<span class="badge">loading</span></div><div class="step-body"><div class="loading"><span class="sp"></span>mengirim request ke ' + esc(url) + '...</div></div></div>';

    var info = await checkEndpoint(url);
    result.innerHTML = renderResult(info);

    // refresh captcha tiap selesai cek biar gak bisa dipakai ulang
    refreshCaptcha();
    busy = false;
    btn.disabled = false;
  }

  /* ---------- events ---------- */
  btn.addEventListener('click', runCek);
  inp.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); runCek(); }
  });
  captchaInp.addEventListener('input', function () {
    if (captchaInp.value.trim() !== '') setSecStatus('siap cek', 'pending');
  });
  captchaRefresh.addEventListener('click', refreshCaptcha);

  document.querySelectorAll('.quick button').forEach(function (b) {
    b.addEventListener('click', function () {
      inp.value = this.getAttribute('data-u');
      inp.focus();
    });
  });

  /* ---------- init ---------- */
  refreshCaptcha();

  // Blokir klik kanan & drag sederhana (opsional, tidak mengganggu UX utama)
  // (tidak diaktifkan agar tidak mengganggu user; bisa diaktifkan jika perlu)

  console.log('%cpynnzcek-end', 'font-size:20px;font-weight:800;color:#facc15;text-shadow:2px 2px 0 #111');
  console.log('%ccreate by pynnzdev', 'font-size:12px;color:#4a4a3a;font-weight:600');
  console.log('%c[security] anti-bot layer aktif: honeypot + UA-detect + time-gate + human-interaction + math-captcha + rate-limit + url-validation', 'font-size:10px;color:#25d366');
})();
