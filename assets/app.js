(function () {
  const toggle = document.querySelector('[data-nav-toggle]');
  const mobile = document.querySelector('[data-nav-mobile]');
  if (toggle && mobile) {
    toggle.addEventListener('click', () => {
      const isOpen = mobile.style.display === 'block';
      mobile.style.display = isOpen ? 'none' : 'block';
      toggle.setAttribute('aria-label', isOpen ? 'Abrir menú' : 'Cerrar menú');
    });
  }

  const toast = document.querySelector('[data-toast]');
  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('toast--show');
    window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => toast.classList.remove('toast--show'), 1600);
  }

  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const sel = btn.getAttribute('data-copy');
      const el = sel ? document.querySelector(sel) : null;
      const text = el ? el.textContent.trim() : '';
      if (!text) return showToast('Nada para copiar');
      try {
        await navigator.clipboard.writeText(text);
        showToast('Copiado');
      } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copiado');
      }
    });
  });

  // Close mobile nav on anchor click
  if (mobile) {
    mobile.querySelectorAll('a').forEach((a) => {
      a.addEventListener('click', () => {
        mobile.style.display = 'none';
      });
    });
  }
})();
