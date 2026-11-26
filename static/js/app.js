// Shared UI behaviour: sidebar, flash messages, password toggle, strength meter.
(function () {
  'use strict';

  window.csrfToken = function () {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : '';
  };

  // Mobile sidebar
  var sidebar = document.getElementById('sidebar');
  var scrim = document.getElementById('scrim');
  var menuBtn = document.getElementById('menuBtn');
  function toggleMenu(open) {
    if (!sidebar) return;
    sidebar.classList.toggle('open', open);
    scrim.classList.toggle('show', open);
  }
  if (menuBtn) menuBtn.addEventListener('click', function () { toggleMenu(!sidebar.classList.contains('open')); });
  if (scrim) scrim.addEventListener('click', function () { toggleMenu(false); });

  // Dismiss flash messages (and auto-hide after a few seconds)
  document.querySelectorAll('.flash').forEach(function (el) {
    el.querySelector('.flash-close').addEventListener('click', function () { el.remove(); });
    setTimeout(function () { el.remove(); }, 8000);
  });

  // Password show/hide
  document.querySelectorAll('.pw-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.dataset.target);
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
    });
  });

  // Password strength meter (register page)
  var pw1 = document.getElementById('pw1');
  var meter = document.querySelector('#strength i');
  if (pw1 && meter) {
    pw1.addEventListener('input', function () {
      var v = pw1.value, score = 0;
      if (v.length >= 8) score++;
      if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
      if (/\d/.test(v)) score++;
      if (/[^A-Za-z0-9]/.test(v) || v.length >= 12) score++;
      var colors = ['#f87171', '#f87171', '#fbbf24', '#60a5fa', '#34d399'];
      meter.style.width = (score * 25) + '%';
      meter.style.background = colors[score];
    });
  }
})();
