// My Secure Files page: search, type filter, and delete with confirmation.
(function () {
  'use strict';
  var table = document.getElementById('filesTable');
  if (!table) return;

  var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));
  var search = document.getElementById('fileSearch');
  var filter = document.getElementById('fileFilter');
  var noMatch = document.getElementById('noMatch');

  var groups = {
    doc: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'rtf'],
    image: ['png', 'jpg', 'jpeg', 'gif', 'webp'],
    media: ['mp3', 'mp4'],
    archive: ['zip']
  };

  function apply() {
    var q = search.value.trim().toLowerCase();
    var g = filter.value, visible = 0;
    rows.forEach(function (r) {
      var name = r.dataset.name;
      var ext = name.indexOf('.') > -1 ? name.split('.').pop() : '';
      var ok = (!q || name.indexOf(q) > -1) && (g === 'all' || groups[g].indexOf(ext) > -1);
      r.classList.toggle('hidden', !ok);
      if (ok) visible++;
    });
    noMatch.classList.toggle('hidden', visible > 0);
  }
  search.addEventListener('input', apply);
  filter.addEventListener('change', apply);

  // Delete flow
  var modal = document.getElementById('deleteModal');
  var delName = document.getElementById('delName');
  var confirmBtn = document.getElementById('delConfirm');
  var cancelBtn = document.getElementById('delCancel');
  var pendingId = null;

  function closeModal() { modal.classList.add('hidden'); pendingId = null; confirmBtn.disabled = false; confirmBtn.textContent = 'Delete permanently'; }

  table.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-delete]');
    if (!btn) return;
    pendingId = btn.dataset.delete;
    delName.textContent = btn.dataset.fname;
    modal.classList.remove('hidden');
    cancelBtn.focus();
  });
  cancelBtn.addEventListener('click', closeModal);
  modal.addEventListener('click', function (e) { if (e.target === modal) closeModal(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });

  confirmBtn.addEventListener('click', function () {
    if (!pendingId) return;
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Deleting…';
    var id = pendingId;
    fetch('/api/files/' + encodeURIComponent(id) + '/delete', {
      method: 'POST',
      headers: { 'X-CSRFToken': window.csrfToken() }
    }).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, d: d }; });
    }).then(function (res) {
      if (!res.ok) { alert(res.d.error || 'Could not delete the file.'); return closeModal(); }
      var row = table.querySelector('tr[data-id="' + id + '"]');
      if (row) { rows = rows.filter(function (r) { return r !== row; }); row.remove(); }
      closeModal();
      if (!rows.length) location.reload();
    }).catch(function () { alert('Network error. Please try again.'); closeModal(); });
  });
})();
