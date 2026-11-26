// Upload page: drag & drop, validation, and 3-stage progress
// (send to server -> AES-256-GCM encryption -> Firebase cloud backup).
(function () {
  'use strict';
  var cfg = window.UPLOAD_CONFIG;
  var zone = document.getElementById('dropzone');
  var input = document.getElementById('fileInput');
  var queue = document.getElementById('queue');

  document.getElementById('browseBtn').addEventListener('click', function (e) { e.stopPropagation(); input.click(); });
  zone.addEventListener('click', function () { input.click(); });
  zone.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('change', function () { handle(input.files); input.value = ''; });
  ['dragenter', 'dragover'].forEach(function (ev) {
    zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('drag'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('drag'); });
  });
  zone.addEventListener('drop', function (e) { handle(e.dataTransfer.files); });

  function fmt(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;   // textContent => no HTML injection
    return e;
  }

  function stage(label) {
    var row = el('div', 'stage');
    var name = el('span', null, label);
    var bar = el('div', 'bar'); var fill = el('i'); bar.appendChild(fill);
    var pct = el('span', null, '0%');
    row.append(name, bar, pct);
    return {
      row: row,
      set: function (p) { fill.style.width = p + '%'; pct.textContent = Math.round(p) + '%'; },
      done: function () { this.set(100); row.classList.add('done'); },
      fail: function () { row.classList.add('fail'); }
    };
  }

  function handle(files) {
    Array.prototype.forEach.call(files, function (file) { uploadOne(file); });
  }

  function uploadOne(file) {
    var item = el('div', 'q-item');
    var top = el('div', 'q-top');
    top.append(el('span', 'q-name', file.name), el('span', 'q-size', fmt(file.size)));
    item.appendChild(top);
    var msg = el('div', 'q-msg');
    queue.prepend(item);

    // Client-side validation (the server validates again - never trust the browser).
    var ext = file.name.indexOf('.') > -1 ? file.name.split('.').pop().toLowerCase() : '';
    if (cfg.allowed.indexOf(ext) === -1) return fail('File type ".' + ext + '" is not allowed.');
    if (file.size === 0) return fail('The file is empty.');
    if (file.size > cfg.maxBytes) return fail('File is larger than ' + (cfg.maxBytes / 1048576) + ' MB.');

    var s1 = stage('Sending to server'), s2 = stage('AES-256 encryption'), s3 = stage('Cloud upload');
    item.append(s1.row, s2.row, s3.row, msg);

    function fail(text, st) {
      if (st) st.fail();
      msg.className = 'q-msg err';
      msg.textContent = '✗ ' + text;
      if (!msg.parentNode) item.appendChild(msg);
    }

    // Step 1: upload to Flask, which encrypts the file before anything else happens.
    var fd = new FormData();
    fd.append('file', file);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload/encrypt');
    xhr.setRequestHeader('X-CSRFToken', window.csrfToken());
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) s1.set(e.loaded / e.total * 100);
    };
    xhr.upload.onload = function () { s1.done(); fakeProgress(s2); };
    xhr.onerror = function () { stopFake(); fail('Network error. Please try again.', s1); };
    xhr.onload = function () {
      stopFake();
      var data = safeJson(xhr.responseText);
      if (xhr.status !== 200) return fail(data.error || 'Encryption failed.', s2);
      s2.done();
      backup(data.token);
    };
    xhr.send(fd);

    var timer = null;
    function fakeProgress(st) {              // encryption runs server-side; show activity meanwhile
      var p = 0;
      timer = setInterval(function () { p = Math.min(p + (95 - p) * 0.15, 95); st.set(p); }, 150);
    }
    function stopFake() { if (timer) { clearInterval(timer); timer = null; } }

    // Step 2: server uploads ONLY the encrypted bytes to Firebase Storage.
    function backup(token) {
      var p = 0;
      var t = setInterval(function () { p = Math.min(p + (95 - p) * 0.12, 95); s3.set(p); }, 150);
      fetch('/api/upload/backup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.csrfToken() },
        body: JSON.stringify({ token: token })
      }).then(function (r) {
        return r.json().then(function (d) { return { ok: r.ok, d: d }; });
      }).then(function (res) {
        clearInterval(t);
        if (!res.ok) return fail(res.d.error || 'Cloud upload failed.', s3);
        s3.done();
        msg.className = 'q-msg ok';
        msg.textContent = '✓ Encrypted and safely backed up to the cloud.';
        item.appendChild(msg);
      }).catch(function () { clearInterval(t); fail('Network error during cloud upload.', s3); });
    }
  }

  function safeJson(t) { try { return JSON.parse(t); } catch (e) { return {}; } }
})();
