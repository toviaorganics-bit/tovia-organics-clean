// Cart state
let cart = [];

// DOM Elements
const cartCountEl = document.getElementById('cart-count');
const mobileCartCountEl = document.getElementById('mobile-cart-count');

// Cart Functions
function updateCartCount() {
    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartCountEl.textContent = totalItems;
    mobileCartCountEl.textContent = totalItems;
    
    if (totalItems > 0) {
        cartCountEl.classList.remove('hidden');
    } else {
        cartCountEl.classList.add('hidden');
    }
}

function addToCart(productId, productName, price, quantity) {
    const existingItem = cart.find(item => item.id === productId);
    
    if (existingItem) {
        existingItem.quantity += quantity;
        if (existingItem.quantity > 5) {
            existingItem.quantity = 5;
            showNotification('Maximum quantity per product is 5', 'warning');
        }
    } else {
        cart.push({
            id: productId,
            name: productName,
            price: price,
            quantity: quantity,
            image: (products && products[productId] && products[productId].image) ? products[productId].image : ''
        });
    }
    
    updateCartCount();
    showNotification(`${productName} added to cart!`, 'success');
    saveCart();
}

function addToCartFromDetail(productId) {
    const quantity = parseInt(document.getElementById('product-quantity').value);
    const product = products[productId];
    addToCart(productId, product.name, product.price, quantity);
}

function updateCartDisplay() {
    const cartContent = document.getElementById('cart-content');
    const emptyCart = document.getElementById('empty-cart');

    if (cart.length === 0) {
        cartContent.innerHTML = '';
        emptyCart.classList.remove('hidden');
        return;
    }

    emptyCart.classList.add('hidden');

    const cartTotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    cartContent.innerHTML = `
        <div class="space-y-6">
            ${cart.map((item, index) => `
                <div class="bg-white rounded-lg shadow-md p-6 flex items-center space-x-6">
                    <img src="${item.image}" alt="${item.name}" class="w-20 h-20 object-cover rounded-lg">
                    <div class="flex-1">
                        <h3 class="font-semibold text-lg">${item.name}</h3>
                        <p class="text-gray-600">${item.price.toFixed(2)} each</p>
                    </div>
                    <div class="flex items-center space-x-3">
                        <button onclick="updateQuantity(${index}, -1)" class="bg-gray-200 text-gray-700 w-8 h-8 rounded-full hover:bg-gray-300 transition-colors">-</button>
                        <span class="font-semibold">${item.quantity}</span>
                        <button onclick="updateQuantity(${index}, 1)" class="bg-gray-200 text-gray-700 w-8 h-8 rounded-full hover:bg-gray-300 transition-colors">+</button>
                    </div>
                    <div class="text-right">
                        <p class="font-bold text-lg">${(item.price * item.quantity).toFixed(2)}</p>
                        <button onclick="removeFromCart(${index})" class="text-red-600 hover:text-red-800 text-sm">Remove</button>
                    </div>
                </div>
            `).join('')}
        </div>
        
        <div class="bg-white rounded-lg shadow-md p-6 mt-8">
            <div class="flex justify-between items-center text-xl font-bold mb-6">
                <span>Total: ${cartTotal.toFixed(2)}</span>
            </div>
            <div class="flex space-x-4">
                <button onclick="clearCart()" class="flex-1 bg-gray-200 text-gray-700 py-3 rounded-lg font-semibold hover:bg-gray-300 transition-colors">Clear Cart</button>
                <button onclick="checkout()" class="flex-1 bg-green-700 text-white py-3 rounded-lg font-semibold hover:bg-green-800 transition-colors">Checkout</button>
            </div>
        </div>
    `;
}

function updateQuantity(index, change) {
    cart[index].quantity += change;
    
    if (cart[index].quantity <= 0) {
        removeFromCart(index);
    } else if (cart[index].quantity > 5) {
        cart[index].quantity = 5;
        showNotification('Maximum quantity per product is 5', 'warning');
    }
    
    updateCartCount();
    updateCartDisplay();
    saveCart();
}

function removeFromCart(index) {
    const product = cart[index];
    cart.splice(index, 1);
    updateCartCount();
    updateCartDisplay();
    showNotification(`${product.name} removed from cart`, 'success');
    saveCart();
}

function clearCart() {
    if (confirm('Are you sure you want to clear your cart?')) {
        cart = [];
        updateCartCount();
        updateCartDisplay();
        showNotification('Cart cleared', 'success');
        saveCart();
    }
}

function checkout() {
    // Ensure we reference the latest auth state (auth.js exports window.isLoggedIn)
    const loggedIn = (typeof window.isLoggedIn !== 'undefined') ? window.isLoggedIn : isLoggedIn;
    if (!loggedIn) {
        if (typeof showNotification === 'function') showNotification('Please sign in to checkout', 'error');
        // Find sign-in modal elements in the DOM and open them via the modal helper if available
        const signinModalEl = document.getElementById('signin-modal');
        const signinModalContentEl = document.getElementById('signin-modal-content');
        if (signinModalEl && signinModalContentEl && typeof openModal === 'function') {
            openModal(signinModalEl, signinModalContentEl);
        } else {
            // Fallback: try to focus the signin button if present
            const signinBtn = document.getElementById('signin-btn');
            if (signinBtn) signinBtn.click();
        }
        return;
    }
    
    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    alert(`Thank you for your order! Total: $${total.toFixed(2)}\n\nThis is a demo - no payment has been processed.`);
    
    cart = [];
    updateCartCount();
    updateCartDisplay();
    showNotification('Order placed successfully!', 'success');
    saveCart();
}

// Cart persistence
function saveCart() {
    if (checkCookieConsent()) {
        localStorage.setItem(USER_PREFERENCES.CART, JSON.stringify(cart));
    }
}

function loadCart() {
    if (checkCookieConsent()) {
        const savedCart = localStorage.getItem(USER_PREFERENCES.CART);
        if (savedCart) {
            cart = JSON.parse(savedCart);
            updateCartCount();
        }
    }
}

// Export functions
window.updateCartCount = updateCartCount;
window.addToCart = addToCart;
window.addToCartFromDetail = addToCartFromDetail;
window.updateCartDisplay = updateCartDisplay;
window.updateQuantity = updateQuantity;
window.removeFromCart = removeFromCart;
window.clearCart = clearCart;
window.checkout = checkout;
window.loadCart = loadCart;
