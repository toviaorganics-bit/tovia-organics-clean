let currentPage = 'home';

// Page Navigation
function showPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    document.getElementById(`${pageName}-page`).classList.add('active');
    currentPage = pageName;

    // Close mobile menu if open
    const mobileMenu = document.getElementById('mobile-menu');
    mobileMenu.classList.add('hidden');

    // Update cart display if showing cart page
    if (pageName === 'cart') {
        updateCartDisplay();
    }

    // Scroll to top
    window.scrollTo(0, 0);
}

// Product Categories
function showCategory(category) {
    // Update tab styles
    document.querySelectorAll('.category-tab').forEach(tab => {
        tab.classList.remove('bg-green-700', 'text-white');
        tab.classList.add('text-gray-600');
    });
    document.getElementById(`${category}-tab`).classList.add('bg-green-700', 'text-white');
    document.getElementById(`${category}-tab`).classList.remove('text-gray-600');

    // Show category content
    document.querySelectorAll('.category-content').forEach(content => {
        content.classList.add('hidden');
    });
    document.getElementById(`${category}-category`).classList.remove('hidden');
}

// Export functions
window.showPage = showPage;
window.showCategory = showCategory;

function initializeNavigation() {
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileMenuBtn && mobileMenu) {
        mobileMenuBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (mobileMenu.classList.contains('hidden')) {
                mobileMenu.classList.remove('hidden');
            } else {
                mobileMenu.classList.add('hidden');
            }
        });
    }
}

function showContactForm() {
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show contact form page
    const contactFormPage = document.getElementById('contact-form-page');
    if (contactFormPage) {
        contactFormPage.classList.add('active');
    }
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

window.initializeNavigation = initializeNavigation;
