/**
 * CloudGate 2.0 Website Application Script
 * OS Detection, Interactive Terminal Tabs, Clipboard Helpers & UI Interactivity
 */

document.addEventListener('DOMContentLoaded', () => {
  detectUserOS();
  initNavbarScroll();
});

/**
 * Auto-detect user OS and dynamically adjust hero download CTA
 */
function detectUserOS() {
  const ua = window.navigator.userAgent;
  const platform = window.navigator.platform || '';
  const heroBtn = document.getElementById('btn-hero-download');
  const osBadge = document.getElementById('detected-os-badge');

  if (!heroBtn || !osBadge) return;

  if (/Mac|iPhone|iPad/i.test(ua) || /Mac/i.test(platform)) {
    // macOS
    heroBtn.href = 'downloads/cloudgate-v2.0.0.zip';
    heroBtn.setAttribute('download', 'cloudgate-v2.0.0.zip');
    osBadge.textContent = 'Detected: macOS (Apple Silicon & Intel) • .zip (31 KB)';
  } else if (/Win/i.test(ua) || /Win/i.test(platform)) {
    // Windows
    heroBtn.href = 'downloads/cloudgate-v2.0.0.zip';
    heroBtn.setAttribute('download', 'cloudgate-v2.0.0.zip');
    osBadge.textContent = 'Detected: Windows (WSL2 / PowerShell) • .zip (31 KB)';
  } else if (/Linux/i.test(ua) || /Linux/i.test(platform)) {
    // Linux
    heroBtn.href = 'downloads/cloudgate-v2.0.0.tar.gz';
    heroBtn.setAttribute('download', 'cloudgate-v2.0.0.tar.gz');
    osBadge.textContent = 'Detected: Linux (Ubuntu, Debian, Kali, RHEL) • .tar.gz (23 KB)';
  } else {
    // Fallback
    heroBtn.href = 'downloads/cloudgate-v2.0.0.tar.gz';
    heroBtn.setAttribute('download', 'cloudgate-v2.0.0.tar.gz');
    osBadge.textContent = 'Cross-Platform Universal Bundle • .tar.gz (23 KB)';
  }


}

/**
 * Switch tabs in the live interactive terminal simulator
 */
function switchTerminalTab(tabId) {
  // Update buttons
  const buttons = document.querySelectorAll('.terminal-tab');
  buttons.forEach(btn => btn.classList.remove('active'));

  const activeBtn = document.querySelector(`[onclick="switchTerminalTab('${tabId}')"]`);
  if (activeBtn) activeBtn.classList.add('active');

  // Update screens
  const screens = document.querySelectorAll('.terminal-screen');
  screens.forEach(screen => screen.classList.remove('active'));

  const activeScreen = document.getElementById(tabId);
  if (activeScreen) activeScreen.classList.add('active');
}

/**
 * Copy command to clipboard with visual feedback
 */
function copyCommand(elementId, btnRef) {
  let text = '';
  const el = document.getElementById(elementId);
  if (el) {
    text = el.innerText || el.textContent;
  } else if (typeof elementId === 'string') {
    text = elementId;
  }

  if (!navigator.clipboard) {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showCopyFeedback(btnRef);
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    showCopyFeedback(btnRef);
  }).catch(err => {
    console.error('Could not copy text: ', err);
  });
}

function showCopyFeedback(btnRef) {
  const toast = document.getElementById('toast');
  if (toast) {
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
  }

  if (btnRef && btnRef.querySelector) {
    const statusText = btnRef.querySelector('.copy-status');
    if (statusText) {
      const original = statusText.textContent;
      statusText.textContent = 'Copied!';
      btnRef.style.borderColor = 'var(--emerald)';
      setTimeout(() => {
        statusText.textContent = original;
        btnRef.style.borderColor = '';
      }, 2000);
    }
  }
}

/**
 * Toggle FAQ accordion panels
 */
function toggleFaq(item) {
  const isOpen = item.classList.contains('active');
  const allItems = document.querySelectorAll('.faq-item');
  allItems.forEach(i => i.classList.remove('active'));

  if (!isOpen) {
    item.classList.add('active');
  }
}

/**
 * Navbar blur and border glow on scroll
 */
function initNavbarScroll() {
  const navbar = document.getElementById('navbar');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      navbar.style.background = 'rgba(7, 9, 14, 0.9)';
      navbar.style.borderBottomColor = 'rgba(0, 229, 255, 0.2)';
    } else {
      navbar.style.background = 'rgba(7, 9, 14, 0.75)';
      navbar.style.borderBottomColor = 'var(--border-subtle)';
    }
  });
}
