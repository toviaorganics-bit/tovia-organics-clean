// Debug helper: reports when initializer runs and logs clicks on key UI elements
console.log('[debug] debug.js loaded');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[debug] DOMContentLoaded fired');

    // report if core initializers are present
    console.log('[debug] initializeAuth', typeof initializeAuth === 'function');
    console.log('[debug] initializeNavigation', typeof initializeNavigation === 'function');
    console.log('[debug] loadCart', typeof loadCart === 'function');
    console.log('[debug] checkCookieConsent', typeof checkCookieConsent === 'function');

    // delegated click logging for important selectors
    const selectors = [
        '#signin-btn', '#signin-btn-mobile',
        '#signup-btn', '#signup-submit', '#signin-submit',
    '[data-add-to-cart]', '.add-to-cart',
    '#accept-cookies', '#decline-cookies',
    '#mobile-menu-btn', '#mobile-menu-toggle', '.mobile-menu-toggle',
    '#checkout-button', '.checkout-button'
    ];

    document.body.addEventListener('click', (e) => {
        const path = e.composedPath ? e.composedPath() : (e.path || []);
        const found = selectors.find(s => {
            try {
                if (s.startsWith('#')) return e.target.closest(s);
                return e.target.closest && e.target.closest(s);
            } catch (err) { return false; }
        });
        if (found) {
            const shortPath = (path && path.map) ? path.slice(0,5).map(p => (p.id || (p.className && p.className.toString()) || p.tagName)).filter(Boolean) : path;
            console.log('[debug] click on', found, 'target:', e.target, 'path:', shortPath);
        }
    }, true);
});
