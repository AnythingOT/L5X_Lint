/*
 * script.js — L5X Lint UI utilities
 *
 * Just the theme toggle. The report page and settings page each carry
 * their own inline JavaScript because both are tightly coupled to their
 * own DOM structures. There was a lot more in here at one point, but
 * none of it had any callers — dead code that looks live is worse than
 * dead code that looks dead, so it's gone.
 */

/* ── THEME ─────────────────────────────────────────────────────────── */
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const icon  = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (icon)  icon.textContent  = dark ? '☀️' : '🌙';
  if (label) label.textContent = dark ? 'Light mode' : 'Dark mode';
  localStorage.setItem('l5x-lint-theme', dark ? 'dark' : 'light');
}

function toggleTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  applyTheme(!isDark);
}

// Wire up the saved theme (the <head> of base.html already applied it before first paint).
(function() {
  applyTheme(localStorage.getItem('l5x-lint-theme') === 'dark');
})();
