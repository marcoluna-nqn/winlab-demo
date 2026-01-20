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

  // Pricing buttons: fallback to WhatsApp when BUY_* is empty.
  const config = window.WINLAB_CONFIG || {};
  const whatsappUrl = (config.WHATSAPP_URL || '').trim();
  const resolveBuyUrl = (kind) => {
    if (kind === 'mp') return (config.BUY_MP_URL || '').trim();
    if (kind === 'stripe') return (config.BUY_STRIPE_URL || '').trim();
    if (kind === 'whatsapp') return whatsappUrl;
    return '';
  };

  document.querySelectorAll('[data-buy]').forEach((btn) => {
    const kind = btn.getAttribute('data-buy');
    let url = resolveBuyUrl(kind);
    if (!url) url = whatsappUrl;

    if (url) {
      btn.setAttribute('href', url);
      btn.setAttribute('target', '_blank');
      btn.setAttribute('rel', 'noopener');
      return;
    }

    btn.setAttribute('href', '#');
    btn.addEventListener('click', (event) => {
      event.preventDefault();
      showToast('Configura WHATSAPP_URL en assets/config.js');
    });
  });
})();
