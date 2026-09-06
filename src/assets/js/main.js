import AOS from 'aos';

const header = document.getElementById('header');
const themeToggle = document.getElementById('darkToggle');
const menuToggle = document.getElementById('menuToggle');
const menu = document.getElementById('menu');
const syncTheme = () => {
  themeToggle?.setAttribute('aria-label', `Switch to ${document.documentElement.classList.contains('dark') ? 'light' : 'dark'} theme`);
};
syncTheme();
themeToggle?.addEventListener('click', () => {
  const dark = document.documentElement.classList.toggle('dark');
  try { localStorage.setItem('dark_mode', String(dark)); } catch { /* Works without storage. */ }
  syncTheme();
});

function setMenu(open, restoreFocus = false) {
  header?.classList.toggle('menu-is-open', open);
  menuToggle?.setAttribute('aria-expanded', String(open));
  menuToggle?.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
  if (restoreFocus) menuToggle?.focus();
}
menuToggle?.addEventListener('click', () => setMenu(menuToggle.getAttribute('aria-expanded') !== 'true'));
menu?.querySelectorAll('a').forEach(link => link.addEventListener('click', () => setMenu(false)));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menuToggle?.getAttribute('aria-expanded') === 'true') setMenu(false, true);
});
document.addEventListener('click', event => {
  if (event.target instanceof Node && !header?.contains(event.target)) setMenu(false);
});
header?.addEventListener('focusout', () => {
  requestAnimationFrame(() => { if (!header.contains(document.activeElement)) setMenu(false); });
});
window.matchMedia('(min-width: 768px)').addEventListener('change', () => setMenu(false));
document.querySelectorAll('[data-aos]').forEach(element => {
  element.setAttribute('data-aos-delay', '0');
  element.setAttribute('data-aos-duration', '450');
});
AOS.init({ duration: 450, easing: 'ease-out', once: true, offset: 24, disable: window.matchMedia('(prefers-reduced-motion: reduce)').matches });
document.documentElement.classList.add('motion-ready');
