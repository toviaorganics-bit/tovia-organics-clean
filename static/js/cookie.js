function checkCookieConsent() {
    const consent = (typeof Cookies !== 'undefined' && Cookies.get) ? Cookies.get(USER_PREFERENCES.COOKIE_CONSENT) : null;
    const banner = document.getElementById('cookie-banner');
    if (!consent && banner) {
        banner.style.transform = 'translateY(0)';
    }
    return consent === 'accepted';
}

function acceptCookies() {
    console.log('[debug] acceptCookies called');
    if (typeof Cookies !== 'undefined' && Cookies.set) Cookies.set(USER_PREFERENCES.COOKIE_CONSENT, 'accepted', { expires: 365 });
    const banner = document.getElementById('cookie-banner');
    if (banner) banner.style.transform = 'translateY(100%)';
    if (typeof loadUserPreferences === 'function') loadUserPreferences();
}

function rejectCookies() {
    if (typeof Cookies !== 'undefined' && Cookies.set) Cookies.set(USER_PREFERENCES.COOKIE_CONSENT, 'rejected', { expires: 365 });
    const banner = document.getElementById('cookie-banner');
    if (banner) banner.style.transform = 'translateY(100%)';
}

function loadUserPreferences() {
    if (typeof loadCart === 'function') loadCart();
}

// Export functions
window.checkCookieConsent = checkCookieConsent;
window.acceptCookies = acceptCookies;
window.rejectCookies = rejectCookies;
window.loadUserPreferences = loadUserPreferences;
