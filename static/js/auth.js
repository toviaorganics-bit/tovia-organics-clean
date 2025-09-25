// Dynamic API base URL configuration
const API_BASE_URL = (() => {
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:5000';
    }
    // Replace with your actual backend URL for production
    return 'https://your-backend-domain.com';
})();

// Authentication state
let isLoggedIn = false;
let currentUser = null;
let authToken = null;

// Functions: signUp, signIn, signOut, handleAuthSuccess, updateAuthUI, initializeAuth
async function signUp(name, email, password) {
    try {
        // FIXED: Use /api/signup instead of /api/register to get verification email
        const response = await fetch(`${API_BASE_URL}/api/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ name, email, password })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Sign up failed');

        handleAuthSuccess(data);
        if (typeof showNotification === 'function') {
            showNotification('Account created successfully! Please check your email for verification.', 'success');
        }
        if (typeof closeModal === 'function') {
            closeModal(document.getElementById('signup-modal'), document.getElementById('signup-modal-content'));
        }
    } catch (error) {
        console.error('Sign up error:', error);
        const msg = (error && error.message && error.message.includes('Failed to fetch')) 
            ? 'Server unreachable. Make sure the backend is running.' 
            : (error.message || 'Failed to create account');
        if (typeof showNotification === 'function') showNotification(msg, 'error');
    }
}

async function signIn(email, password) {
    try {
        // FIXED: Use /api/login (this one is correct)
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Sign in failed');

        handleAuthSuccess(data);
        if (typeof showNotification === 'function') showNotification('Signed in successfully!', 'success');
        if (typeof closeModal === 'function') closeModal(document.getElementById('signin-modal'), document.getElementById('signin-modal-content'));
    } catch (error) {
        console.error('Sign in error:', error);
        const msg = (error && error.message && error.message.includes('Failed to fetch')) 
            ? 'Server unreachable. Make sure the backend is running.' 
            : (error.message || 'Failed to sign in');
        if (typeof showNotification === 'function') showNotification(msg, 'error');
    }
}

async function signOut() {
    try {
        // Get the current auth token before clearing it
        const token = authToken || (typeof Cookies !== 'undefined' ? Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session') : null);
        
        // Make logout request with proper headers
        const headers = {};
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const response = await fetch(`${API_BASE_URL}/api/logout`, { 
            method: 'POST', 
            credentials: 'include',
            headers: headers
        });
        
        // Clear local auth state regardless of server response
        // (since we want to log out the user even if server request fails)
        isLoggedIn = false;
        currentUser = null;
        authToken = null;
        
        // Keep globals in sync for other modules
        window.isLoggedIn = isLoggedIn;
        window.currentUser = currentUser;
        
        // Clear verification check interval
        if (verificationCheckInterval) {
            clearInterval(verificationCheckInterval);
            verificationCheckInterval = null;
        }
        
        // Clear cookies
        if (typeof Cookies !== 'undefined' && typeof Cookies.remove === 'function') {
            Cookies.remove(window.USER_PREFERENCES?.SESSION || 'tovia_session');
        }
        
        updateAuthUI();
        
        // Show success message regardless of server response
        if (typeof showNotification === 'function') {
            showNotification('Signed out successfully', 'success');
        }
        
        if (typeof closeModal === 'function') {
            closeModal(document.getElementById('account-modal'), document.getElementById('account-modal-content'));
            closeModal(document.getElementById('delete-modal'), document.getElementById('delete-modal-content'));
        }
        
        // Only log server errors, don't show them to user
        if (!response.ok) {
            console.warn('Server logout request failed, but user was logged out locally');
        }
        
    } catch (error) {
        console.error('Sign out error:', error);
        
        // Still clear local auth state even on error
        isLoggedIn = false;
        currentUser = null;
        authToken = null;
        window.isLoggedIn = isLoggedIn;
        window.currentUser = currentUser;
        
        if (verificationCheckInterval) {
            clearInterval(verificationCheckInterval);
            verificationCheckInterval = null;
        }
        
        if (typeof Cookies !== 'undefined' && typeof Cookies.remove === 'function') {
            Cookies.remove(window.USER_PREFERENCES?.SESSION || 'tovia_session');
        }
        
        updateAuthUI();
        
        // Show success message even on network error (user is logged out locally)
        if (typeof showNotification === 'function') {
            showNotification('Signed out successfully', 'success');
        }
        
        if (typeof closeModal === 'function') {
            closeModal(document.getElementById('account-modal'), document.getElementById('account-modal-content'));
            closeModal(document.getElementById('delete-modal'), document.getElementById('delete-modal-content'));
        }
    }
}

function handleAuthSuccess(data) {
    const { token, user } = data || {};
    if (token) {
        authToken = token;
        if (typeof Cookies !== 'undefined') {
            Cookies.set(window.USER_PREFERENCES?.SESSION || 'tovia_session', token, { expires: 7 });
        }
    }
    isLoggedIn = true;
    currentUser = user || null;
    window.isLoggedIn = isLoggedIn;
    window.currentUser = currentUser;
    
    // ALWAYS update UI immediately with the user data we received
    updateAuthUI();
    
    console.log('User verification status:', user?.verified);
    
    // Only start verification checking if user is explicitly unverified
    if (user && user.verified === false) {
        console.log('Starting verification check for unverified user');
        startVerificationCheck();
    } else {
        console.log('User is verified or verification status unknown, not starting check');
    }
}

// Add periodic verification check
let verificationCheckInterval = null;

function startVerificationCheck() {
    // Clear any existing interval
    if (verificationCheckInterval) {
        clearInterval(verificationCheckInterval);
    }
    
    console.log('Starting verification check interval (every 2 seconds)...');
    
    // Check every 2 seconds for verification status
    verificationCheckInterval = setInterval(async () => {
        try {
            const token = Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session');
            const response = await fetch(`${API_BASE_URL}/api/user`, {
                method: 'GET',
                credentials: 'include',
                headers: token ? {'Authorization': `Bearer ${token}`} : {}
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.user) {
                    const wasUnverified = currentUser && currentUser.verified === false;
                    const isNowVerified = data.user.verified === true;
                    
                    // Update current user
                    currentUser = data.user;
                    window.currentUser = currentUser;
                    updateVerificationUI(data.user.verified);
                    
                    // Only show notification if user was explicitly unverified and is now explicitly verified
                    if (wasUnverified && isNowVerified) {
                        clearInterval(verificationCheckInterval);
                        verificationCheckInterval = null;
                        if (typeof showNotification === 'function') {
                            showNotification('Your account has been verified!', 'success');
                        }
                        console.log('Account verified! Stopping verification check.');
                    }
                }
            }
        } catch (error) {
            console.error('Verification check error:', error);
        }
    }, 2000); // Changed to 2 seconds as requested
}

async function refreshVerificationStatus() {
    try {
        const token = Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session');
        const response = await fetch(`${API_BASE_URL}/api/user`, {
            method: 'GET',
            credentials: 'include',
            headers: token ? {'Authorization': `Bearer ${token}`} : {}
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.user) {
                const wasUnverified = currentUser && currentUser.verified === false;
                const isNowVerified = data.user.verified === true;
                
                currentUser = data.user;
                window.currentUser = currentUser;
                updateVerificationUI(data.user.verified);
                
                // Show notification only for actual verification changes
                if (wasUnverified && isNowVerified) {
                    if (typeof showNotification === 'function') {
                        showNotification('Your account has been verified!', 'success');
                    }
                    // Stop verification check if running
                    if (verificationCheckInterval) {
                        clearInterval(verificationCheckInterval);
                        verificationCheckInterval = null;
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error refreshing verification status:', error);
    }
}

function updateVerificationUI(isVerified) {
    const badge = document.getElementById('verification-badge');
    const icon = document.getElementById('verification-icon');
    const text = document.getElementById('verification-text');
    
    if (badge && icon && text) {
        if (isVerified === true) {
            badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800';
            icon.setAttribute('data-lucide', 'check-circle');
            text.textContent = 'Verified Account';
        } else if (isVerified === false) {
            badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-orange-100 text-orange-800';
            icon.setAttribute('data-lucide', 'alert-circle');
            text.textContent = 'Un-Verified Account';
        }
        // Update Lucide icons
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
    }
}

// Add function to check user status on page load/focus
async function checkUserStatusOnFocus() {
    if (isLoggedIn && currentUser && currentUser.verified === false) {
        await refreshVerificationStatus();
    }
}

// Add visibility change listener to refresh when user returns to the page
function setupVisibilityListener() {
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && isLoggedIn && currentUser && currentUser.verified === false) {
            console.log('Page became visible, checking verification status...');
            checkUserStatusOnFocus();
        }
    });
    
    window.addEventListener('focus', () => {
        if (isLoggedIn && currentUser && currentUser.verified === false) {
            console.log('Window gained focus, checking verification status...');
            checkUserStatusOnFocus();
        }
    });
}

function updateAuthUI() {
    // cache frequent elements once
    const signInBtn = document.getElementById('signin-btn');
    const signInBtnMobile = document.getElementById('signin-btn-mobile');
    const accountBtn = document.getElementById('account-btn');
    const accountBtnMobile = document.getElementById('account-btn-mobile');
    const accountNameEl = document.getElementById('account-name');
    const accountEmailEl = document.getElementById('account-email');
    const profileInitialEl = document.getElementById('profile-initial');

    const showAccount = Boolean(isLoggedIn);

    // Toggle visibility using classList.toggle where available to minimize DOM ops
    if (signInBtn && accountBtn) {
        signInBtn.classList.toggle('hidden', showAccount);
        accountBtn.classList.toggle('hidden', !showAccount);
    }
    if (signInBtnMobile && accountBtnMobile) {
        signInBtnMobile.classList.toggle('hidden', showAccount);
        accountBtnMobile.classList.toggle('hidden', !showAccount);
    }

    if (accountNameEl) accountNameEl.textContent = currentUser?.name || '';
    if (accountEmailEl) accountEmailEl.textContent = currentUser?.email || '';
    if (profileInitialEl && currentUser?.name) {
        const firstInitial = currentUser.name.trim().charAt(0).toUpperCase();
        profileInitialEl.textContent = firstInitial;
    }
    
    // Update verification UI if user is logged in
    if (currentUser && typeof currentUser.verified !== 'undefined') {
        updateVerificationUI(currentUser.verified);
    }
}

// Enhanced initialization to check user status on load
async function initializeUserStatus() {
    try {
        const token = Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session');
        if (token) {
            authToken = token;
            const response = await fetch(`${API_BASE_URL}/api/user`, {
                method: 'GET',
                credentials: 'include',
                headers: {'Authorization': `Bearer ${token}`}
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.user) {
                    isLoggedIn = true;
                    currentUser = data.user;
                    window.isLoggedIn = isLoggedIn;
                    window.currentUser = currentUser;
                    updateAuthUI();
                    
                    // Only start verification checking for unverified users
                    // Don't show any notifications during initialization
                    if (!currentUser.verified) {
                        startVerificationCheck();
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error initializing user status:', error);
    }
}

function initializeAuth() {
    // Initialize visibility listeners
    setupVisibilityListener();
    
    // Initialize user status
    initializeUserStatus();
    
    // load token from cookie if present (keeps Authorization header usable on reload)
    try {
        if (!authToken && typeof Cookies !== 'undefined' && Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session')) {
            authToken = Cookies.get(window.USER_PREFERENCES?.SESSION || 'tovia_session');
        }
    } catch (e) { /* ignore cookie errors */ }
    
    const signInForm = document.getElementById('signin-form');
    const signUpForm = document.getElementById('signup-form');
    const signOutBtn = document.getElementById('signout-btn');
    const changePasswordBtn = document.getElementById('change-password-btn');
    const deleteAccountBtn = document.getElementById('delete-account-btn');
    const changePasswordModal = document.getElementById('change-password-modal');
    const changePasswordContent = document.getElementById('change-password-modal-content');
    const changePasswordForm = document.getElementById('change-password-form');
    const closeChangePassword = document.getElementById('close-change-password-modal');
    const deleteAccountModal = document.getElementById('delete-account-modal');
    const deleteAccountContent = document.getElementById('delete-account-modal-content');
    const deleteAccountForm = document.getElementById('delete-account-form');
    const closeDeleteAccount = document.getElementById('close-delete-account-modal');
    const cancelDeleteAccount = document.getElementById('cancel-delete-account');
    const switchToSignUpBtn = document.getElementById('switch-to-signup');
    const switchToSignInBtn = document.getElementById('switch-to-signin');

    // Modal open/close buttons
    const signinBtn = document.getElementById('signin-btn');
    const signinBtnMobile = document.getElementById('signin-btn-mobile');
    const accountBtn = document.getElementById('account-btn');
    const closeSignin = document.getElementById('close-signin-modal');
    const closeSignup = document.getElementById('close-signup-modal');
    const closeAccount = document.getElementById('close-account-modal');

    // Helpers to open/close signin/signup/account modals safely
    const openSignin = () => {
        const modal = document.getElementById('signin-modal');
        const content = document.getElementById('signin-modal-content');
        if (modal && content && typeof openModal === 'function') return openModal(modal, content);
    };
    const openSignup = () => {
        const modal = document.getElementById('signup-modal');
        const content = document.getElementById('signup-modal-content');
        if (modal && content && typeof openModal === 'function') return openModal(modal, content);
    };
    const openAccount = () => {
        const modal = document.getElementById('account-modal');
        const content = document.getElementById('account-modal-content');
        if (modal && content && typeof openModal === 'function') return openModal(modal, content);
    };

    // Attach simple handlers - reuse shared handler to avoid creating functions in loops
    const handleOpenSignin = (e) => { if (e && e.preventDefault) e.preventDefault(); openSignin(); };
    if (signinBtn) signinBtn.addEventListener('click', handleOpenSignin);
    if (signinBtnMobile) signinBtnMobile.addEventListener('click', handleOpenSignin);
    if (accountBtn) accountBtn.addEventListener('click', (e) => { e.preventDefault(); openAccount(); });
    if (closeSignin) closeSignin.addEventListener('click', () => { if (typeof closeModal === 'function') closeModal(document.getElementById('signin-modal'), document.getElementById('signin-modal-content')); });
    if (closeSignup) closeSignup.addEventListener('click', () => { if (typeof closeModal === 'function') closeModal(document.getElementById('signup-modal'), document.getElementById('signup-modal-content')); });
    if (closeAccount) closeAccount.addEventListener('click', () => { if (typeof closeModal === 'function') closeModal(document.getElementById('account-modal'), document.getElementById('account-modal-content')); });

    if (signInForm) {
        signInForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            // capture values once
            const email = document.getElementById('signin-email').value;
            const password = document.getElementById('signin-password').value;
            const submitBtn = document.getElementById('signin-submit');
            const originalText = submitBtn?.innerHTML;
            if (submitBtn) { 
                submitBtn.innerHTML = '<span class="loader inline-block w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>'; 
                submitBtn.disabled = true; 
            }
            try { 
                await signIn(email, password); 
                signInForm.reset(); 
            } finally { 
                if (submitBtn) { 
                    submitBtn.innerHTML = originalText; 
                    submitBtn.disabled = false; 
                } 
            }
        });
    }

    // Show password toggles
    const signinShow = document.getElementById('signin-show-password');
    const signupShow = document.getElementById('signup-show-password');
    if (signinShow) signinShow.addEventListener('change', (e) => {
        const input = document.getElementById('signin-password');
        if (input) input.type = e.target.checked ? 'text' : 'password';
    });
    if (signupShow) signupShow.addEventListener('change', (e) => {
        const input = document.getElementById('signup-password');
        if (input) input.type = e.target.checked ? 'text' : 'password';
    });

    if (signUpForm) {
        signUpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            // capture values once
            const name = document.getElementById('signup-name').value;
            const email = document.getElementById('signup-email').value;
            const password = document.getElementById('signup-password').value;
            const minLen = parseInt(document.getElementById('password-min-length')?.textContent || '8', 10) || 8;
            if (!password || password.length < minLen) {
                if (typeof showNotification === 'function') showNotification(`Password must be at least ${minLen} characters`, 'error');
                return;
            }
            const submitBtn = document.getElementById('signup-submit');
            const originalText = submitBtn?.innerHTML;
            if (submitBtn) { 
                submitBtn.innerHTML = '<span class="loader inline-block w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>'; 
                submitBtn.disabled = true; 
            }
            try { 
                await signUp(name, email, password); 
                signUpForm.reset(); 
            } finally { 
                if (submitBtn) { 
                    submitBtn.innerHTML = originalText; 
                    submitBtn.disabled = false; 
                } 
            }
        });
    }

    if (switchToSignUpBtn) {
        switchToSignUpBtn.addEventListener('click', () => {
            if (typeof closeModal === 'function') closeModal(document.getElementById('signin-modal'), document.getElementById('signin-modal-content'));
            setTimeout(() => { if (typeof openModal === 'function') openModal(document.getElementById('signup-modal'), document.getElementById('signup-modal-content')); }, 350);
        });
    }

    if (switchToSignInBtn) {
        switchToSignInBtn.addEventListener('click', () => {
            if (typeof closeModal === 'function') closeModal(document.getElementById('signup-modal'), document.getElementById('signup-modal-content'));
            setTimeout(() => { if (typeof openModal === 'function') openModal(document.getElementById('signin-modal'), document.getElementById('signin-modal-content')); }, 350);
        });
    }

    if (signOutBtn) signOutBtn.addEventListener('click', signOut);
    
    // Open change password modal
    if (changePasswordBtn && changePasswordModal && changePasswordContent && typeof openModal === 'function') {
        changePasswordBtn.addEventListener('click', () => {
            // hide account modal while showing child modal
            if (typeof closeModal === 'function') closeModal(document.getElementById('account-modal'), document.getElementById('account-modal-content'));
            setTimeout(() => openModal(changePasswordModal, changePasswordContent), 200);
        });
    }
    if (closeChangePassword && typeof closeModal === 'function') closeChangePassword.addEventListener('click', () => {
        closeModal(changePasswordModal, changePasswordContent);
        setTimeout(() => { if (isLoggedIn && typeof openModal === 'function') openModal(document.getElementById('account-modal'), document.getElementById('account-modal-content')); }, 350);
    });

    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const current_password = document.getElementById('current-password').value;
            const new_password = document.getElementById('new-password').value;
            if (!current_password || !new_password) {
                if (typeof showNotification === 'function') showNotification('Please complete both fields', 'error');
                return;
            }
            try {
                const headers = { 'Content-Type': 'application/json' };
                if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
                const resp = await fetch(`${API_BASE_URL}/api/account/change-password`, {
                    method: 'POST',
                    headers,
                    credentials: 'include',
                    body: JSON.stringify({ current_password, new_password })
                });
                const data = await resp.json();
                if (!resp.ok) throw new Error(data.message || 'Password change failed');
                if (typeof showNotification === 'function') showNotification('Password changed successfully', 'success');
                if (typeof closeModal === 'function') closeModal(changePasswordModal, changePasswordContent);
                changePasswordForm.reset();
            } catch (err) {
                console.error('Change password error', err);
                if (typeof showNotification === 'function') showNotification(err.message || 'Error changing password', 'error');
            }
        });
    }

    // Delete account modal flow
    if (deleteAccountBtn && deleteAccountModal && deleteAccountContent && typeof openModal === 'function') {
        deleteAccountBtn.addEventListener('click', () => {
            if (typeof closeModal === 'function') closeModal(document.getElementById('account-modal'), document.getElementById('account-modal-content'));
            setTimeout(() => openModal(deleteAccountModal, deleteAccountContent), 200);
        });
    }
    if (closeDeleteAccount && typeof closeModal === 'function') closeDeleteAccount.addEventListener('click', () => {
        closeModal(deleteAccountModal, deleteAccountContent);
        // if still logged in, reopen account modal to return user to main account panel
        setTimeout(() => { if (isLoggedIn && typeof openModal === 'function') openModal(document.getElementById('account-modal'), document.getElementById('account-modal-content')); }, 350);
    });
    if (cancelDeleteAccount) cancelDeleteAccount.addEventListener('click', () => { if (typeof closeModal === 'function') closeModal(deleteAccountModal, deleteAccountContent); });

    // Handle opening the delete account modal
    if (deleteAccountBtn) {
        console.log('Found delete account button');
        deleteAccountBtn.addEventListener('click', (e) => {
            console.log('Delete account button clicked');
            e.preventDefault();
            // First close the account modal
            const accountModal = document.getElementById('account-modal');
            const accountContent = document.getElementById('account-modal-content');
            const deleteModal = document.getElementById('delete-account-modal');
            const deleteContent = document.getElementById('delete-account-modal-content');
            
            console.log('Modals:', { accountModal, accountContent, deleteModal, deleteContent });
            
            if (typeof closeModal === 'function') {
                console.log('Closing account modal');
                closeModal(accountModal, accountContent);
            }
            
            // Then open the delete modal after a short delay
            setTimeout(() => {
                if (typeof openModal === 'function') {
                    console.log('Opening delete modal');
                    openModal(deleteModal, deleteContent);
                }
            }, 200);
        });
    }

    // Handle the delete account form submission
    if (deleteAccountForm) {
        deleteAccountForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const confirmation = document.getElementById('delete-confirmation').value || '';
            if (confirmation.trim().toUpperCase() !== 'DELETE') {
                if (typeof showNotification === 'function') showNotification('Type DELETE to confirm account deletion', 'error');
                return;
            }
            try {
                const headers = { 'Content-Type': 'application/json' };
                if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
                const resp = await fetch(`${API_BASE_URL}/api/account/delete`, {
                    method: 'POST',
                    headers,
                    credentials: 'include',
                    body: JSON.stringify({ confirm: true })
                });
                const data = await resp.json();
                if (!resp.ok) throw new Error(data.message || 'Account deletion failed');
                if (typeof showNotification === 'function') showNotification('Account deleted', 'success');
                // First close the delete modal
                if (typeof closeModal === 'function') closeModal(document.getElementById('delete-account-modal'), document.getElementById('delete-account-modal-content'));
                // clear local auth state
                isLoggedIn = false; 
                currentUser = null; 
                window.isLoggedIn = false; 
                window.currentUser = null; 
                updateAuthUI();
                if (typeof closeModal === 'function') closeModal(deleteAccountModal, deleteAccountContent);
                deleteAccountForm.reset();
            } catch (err) {
                console.error('Delete account error', err);
                if (typeof showNotification === 'function') showNotification(err.message || 'Error deleting account', 'error');
            }
        });
    }
}

// Export to global
window.isLoggedIn = isLoggedIn;
window.currentUser = currentUser;
window.signUp = signUp;
window.signIn = signIn;
window.signOut = signOut;
window.updateAuthUI = updateAuthUI;
window.initializeAuth = initializeAuth;
window.refreshVerificationStatus = refreshVerificationStatus;