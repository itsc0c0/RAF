// Applies the persisted theme before the application bundle loads (avoids a flash of the wrong theme).
// Served as a same-origin file so it complies with the backend CSP (no inline scripts).
(function () {
  'use strict';
  var theme = 'dark';
  try {
    var stored = window.localStorage.getItem('raf.theme');
    if (stored === 'light' || stored === 'dark') {
      theme = stored;
    }
  } catch {
    // Storage can be unavailable (private mode, blocked site data): keep the default.
  }
  document.documentElement.setAttribute('data-theme', theme);
})();
