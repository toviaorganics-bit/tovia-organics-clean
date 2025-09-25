const products = {
    'herbal-oil-blend': {
        name: 'Organic Herbal Oil Blend',
        price: 29.99,
        image: '/images/herbal-oil-blend.jpg',
        shortDescription: 'A potent, deeply nourishing fusion of the world\'s finest certified organic botanicals and essential oils. Meticulously crafted for those who desire both holistic wellness and radiant skin.',
        description: `Botanical Power for Skin & Senses

Introducing Tovia Organics Herbal Oil Blend—a potent, deeply nourishing fusion of the world's finest certified organic botanicals and essential oils. Meticulously crafted for those who desire both holistic wellness and radiant skin, this blend refreshes, restores, and revitalizes with every drop.

Our Herbal Oil Blend unites the legendary properties of Organic Black Seed Oil with a curated Organic Vitamin E Oil Blend—featuring Sunflower, Avocado, Apricot, Sweet Almond, Natural Vitamin E, Jojoba, Argan, Rosehip, and Lavender Oils. This rich botanical base is elevated by the targeted benefits of pure, certified organic essential oils, including Tea Tree, Lavender, Frankincense, Carrot Seed, Marjoram, Helichrysum, Cypress, Basil, and Ravintsara.

Why Tovia Organics Herbal Oil Blend Stands Out

Unlike ordinary oils, this blend is specially designed to support your skin's natural barrier, calm irritation, and promote luminous, healthy-looking skin. Each ingredient is selected for its unique synergy—delivering antioxidants, vitamins, and phytonutrients that help protect, soothe, and rejuvenate your skin and scalp.`,
        ingredients: [
            'Organic Black Seed Oil (Carrier oil)',
            'Sunflower Oil',
            'Avocado Oil',
            'Apricot Oil',
            'Sweet Almond Oil',
            'Natural Vitamin E Oil',
            'Jojoba Oil',
            'Argan Oil',
            'Rosehip Oil',
            'Lavender Oil',
            'Tea Tree Oil',
            'Lavender Oil',
            'Frankincense Oil',
            'Carrot Seed Oil',
            'Marjoram Oil',
            'Helichrysum Oil',
            'Cypress Oil',
            'Basil Oil',
            'Ravintsara Oil',
            'All essential oils are certified Organic'
        ],
        benefits: [
            'Supports skin\'s natural barrier function',
            'Calms and soothes skin irritation',
            'Provides deep nourishment and hydration',
            'Rich in antioxidants and vitamins',
            'Promotes skin elasticity and resilience',
            'Suitable for all skin types including sensitive',
            'Anti-inflammatory and healing properties',
            'Aromatherapeutic benefits for relaxation',
            'Helps improve skin tone and texture',
            'Protects against environmental stressors'
        ],
        usage: `How to Use:
Massage a few drops gently into clean skin, scalp, or nails as needed. Use daily for optimal results. Ideal for all skin types—including sensitive and mature skin.

For hydration – Apply to face, body, or scalp after cleansing.
For targeted care – Use as a spot treatment for dry or irritated areas.
For aromatherapy – Rub between your palms and inhale deeply for an uplifting botanical experience.

Why Choose Tovia Organics Herbal Oil Blend?
• 100% Certified Organic & Cold-Pressed Ingredients
• Free from parabens, sulfates, and synthetic additives
• Vegan, cruelty-free, and ethically sourced
• Packaged sustainably for a better planet

Reimagine your skincare ritual with the pure, potent botanicals of Tovia Organics Herbal Oil Blend—nature's answer for luminous, healthy skin and holistic well-being.`,
        category: 'skincare'
    },
    'rose-water-lotion': {
        name: 'Organic Rose Water Lotion',
        price: 19.99,
        image: '/images/rose-water-lotion.jpg',
        shortDescription: 'Nourish your skin with our rejuvenating face serum, made from 100% organic ingredients. This lotion provides deep hydration and a natural glow, perfect for all skin types.',
        description: `Radiant Hydration with Every Drop

Introducing Tovia Organics Rose Water Lotion—a luxurious, deeply hydrating lotion that blends the timeless beauty of organic rose water with modern skincare science. Crafted for those who seek a balance between nourishment and purity, this lotion is a daily indulgence that refreshes, hydrates, and soothes your skin, leaving it soft, supple, and glowing.

Infused with organic botanical extracts and nutrient-rich oils, our lotion is designed to suit all skin types, including sensitive skin. Its lightweight yet intensely moisturizing formula absorbs quickly without leaving a greasy residue, making it perfect for everyday use.`,
        ingredients: [
            'Organic Rose Water',
            'Organic Aloe Vera',
            'Organic Shea Butter',
            'Organic Grass-Fed Grass-Finished Beef Tallow',
            'Organic Sweet Almond Oil',
            'Organic Rose Absolute Oil',
            'Organic Cedarwood Oil',
            'Organic Avocado Oil',
            'Organic Blue Cypress Oil',
            'Organic Rosehip Seed Extract',
            'Organic Jojoba Seed Oil',
            'Organic Lavender Oil',
            'Organic Myrrh Oil',
            'Organic Wolfberry Seed Oil',
            'Organic Royal Hawaiian Sandalwood Oil'
        ],
        benefits: [
            'Deep, long-lasting hydration',
            'Suitable for all skin types',
            'Anti-inflammatory properties',
            'Natural antioxidant protection',
            'Enhances skin elasticity',
            'Promotes natural glow',
            'Calming and soothing',
            'Quick absorption'
        ],
        usage: `How to Use:
- Apply generously to clean skin, massaging in circular motions until fully absorbed
- Use daily for best results
- For dry skin: Apply morning and night
- For normal to combination skin: Use as needed
- For sensitive skin: Safe for regular use

Special Uses:
- Post-Sun Care
- Pre-Makeup Prep
- Full-Body Hydration`,
        category: 'skincare'
    },
    'soothing-cleanser': {
        name: 'Soothing Cream Cleanser',
        price: 22.00,
        image: 'https://placehold.co/600x400/E0EBE4/333333?text=Soothing+Cleanser',
        shortDescription: 'Gentle cream cleanser that removes impurities while maintaining skin\'s natural moisture.',
        description: 'Gentle cream cleanser that removes impurities while maintaining skin\'s natural moisture.',
        ingredients: ['Chamomile Extract', 'Green Tea', 'Coconut Oil', 'Glycerin'],
        benefits: ['Gentle cleansing', 'Calms irritation', 'Maintains moisture', 'Suitable for sensitive skin'],
        usage: 'Massage onto damp skin, rinse with warm water. Use morning and evening.',
        category: 'cleansers'
    },
    'hydrating-mist': {
        name: 'Hydrating Facial Mist',
        price: 18.00,
        image: 'https://placehold.co/600x400/E0EBE4/333333?text=Hydrating+Mist',
        shortDescription: 'Refreshing rosewater and aloe mist that hydrates and tones throughout the day.',
        description: 'Refreshing rosewater and aloe mist that hydrates and tones throughout the day.',
        ingredients: ['Rose Water', 'Aloe Vera', 'Glycerin', 'Botanical Extracts'],
        benefits: ['Instant hydration', 'Refreshes makeup', 'Balances pH', 'Calming effect'],
        usage: 'Spray 6-8 inches from face. Use throughout the day as needed.',
        category: 'treatments'
    },
};

// Review System Functions
let productReviews = {};

async function loadProductReviews(productId) {
    try {
        const response = await fetch(`/api/reviews/${productId}`);
        const data = await response.json();
        
        if (data.success) {
            productReviews[productId] = data;
            return data;
        }
    } catch (error) {
        console.error('Error loading reviews:', error);
    }
    return { reviews: [], total_reviews: 0, average_rating: 0 };
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    });
}

function renderStarRating(rating) {
    let stars = '';
    for (let i = 1; i <= 5; i++) {
        if (i <= rating) {
            stars += '<span class="text-yellow-400">★</span>';
        } else {
            stars += '<span class="text-gray-300">★</span>';
        }
    }
    return stars;
}

function renderReviewsSection(productId) {
    const reviewData = productReviews[productId] || { reviews: [], total_reviews: 0, average_rating: 0 };
    
    let reviewsHtml = `
        <div class="mb-6">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold">Customer Reviews</h3>
                <div class="flex items-center space-x-2">
                    <div class="flex">${renderStarRating(Math.round(reviewData.average_rating))}</div>
                    <span class="text-gray-600">(${reviewData.total_reviews} reviews)</span>
                </div>
            </div>
        </div>
    `;
    
    if (reviewData.reviews.length === 0) {
        reviewsHtml += `
            <div class="text-center py-8 bg-gray-50 rounded-lg">
                <div class="text-gray-400 mb-2">
                    <svg class="mx-auto h-12 w-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-3.582 8-8 8a8.013 8.013 0 01-7-4c0-4.418 3.582-8 8-8s8 3.582 8 8z"></path>
                    </svg>
                </div>
                <h4 class="text-lg font-medium text-gray-900 mb-1">No reviews yet</h4>
                <p class="text-gray-600">Be the first to review this product!</p>
            </div>
        `;
    } else {
        reviewsHtml += '<div class="space-y-6">';
        
        reviewData.reviews.forEach(review => {
            reviewsHtml += `
                <div class="border-b border-gray-200 pb-6">
                    <div class="flex items-start justify-between mb-2">
                        <div class="flex items-center space-x-2">
                            <span class="font-medium text-gray-900">${review.user_name}</span>
                            ${review.verified_purchase ? '<span class="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full">Verified Purchase</span>' : ''}
                        </div>
                        <div class="flex items-center space-x-2">
                            <div class="flex">${renderStarRating(review.rating)}</div>
                            <span class="text-gray-500 text-sm">${formatDate(review.created_at)}</span>
                        </div>
                    </div>
                    ${review.comment ? `<p class="text-gray-700 mt-2">${review.comment}</p>` : ''}
                </div>
            `;
        });
        
        reviewsHtml += '</div>';
    }
    
    return reviewsHtml;
}

// Enhanced Product Detail Function
async function showProductDetail(productId) {
    const product = products[productId];
    if (!product) return;

    // Load reviews for this product
    await loadProductReviews(productId);

    const detailContent = `
        <div class="max-w-7xl mx-auto">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 mb-8">
                <div>
                    <img src="${product.image}" alt="${product.name}" class="w-full rounded-lg shadow-lg">
                    <!-- Tabs Navigation -->
                    <div class="flex border-b border-gray-200 mt-8">
                        <button onclick="switchTab(event, 'description')" class="tab-button px-6 py-3 border-b-2 border-green-700 text-green-700 font-medium">Description</button>
                        <button onclick="switchTab(event, 'reviews')" class="tab-button px-6 py-3 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium">Reviews</button>
                        <button onclick="switchTab(event, 'ingredients')" class="tab-button px-6 py-3 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium">Ingredients</button>
                    </div>
                    <!-- Tab Content -->
                    <div class="py-6">
                        <div id="description" class="tab-content active">
                            <div class="prose max-w-none">
                                ${product.description.split('\n\n').map(p => `<p class="mb-4">${p}</p>`).join('')}
                            </div>
                        </div>
                        <div id="reviews" class="tab-content hidden">
                            ${renderReviewsSection(productId)}
                        </div>
                        <div id="ingredients" class="tab-content hidden">
                            <ul class="list-disc pl-5 space-y-2">
                                ${product.ingredients.map(ingredient => `<li class="text-gray-700">${ingredient}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
                <div>
                    <h1 class="text-3xl font-bold mb-4">${product.name}</h1>
                    <p class="text-2xl font-bold text-green-700 mb-6">${product.price.toFixed(2)}</p>
                    
                    <div class="mb-8">
                        <p class="text-gray-600 mb-6">${product.shortDescription}</p>
                    </div>

                    <div class="mb-8">
                        <h3 class="text-lg font-semibold mb-3">Key Ingredients</h3>
                        <div class="flex flex-wrap gap-2">
                            ${product.ingredients.slice(0, 5).map(ingredient => 
                                `<span class="bg-green-100 text-green-800 px-3 py-1 rounded-full text-sm">${ingredient}</span>`
                            ).join('')}
                        </div>
                    </div>

                    <div class="mb-8">
                        <h3 class="text-lg font-semibold mb-3">Benefits</h3>
                        <ul class="text-gray-600 space-y-1">
                            ${product.benefits.map(benefit => `<li>• ${benefit}</li>`).join('')}
                        </ul>
                    </div>

                    <div class="mb-8">
                        <h3 class="text-lg font-semibold mb-3">How to Use</h3>
                        <div class="text-gray-600">
                            ${product.usage.split('\n\n').map(section => `<p class="mb-3">${section.replace(/\n/g, '<br>')}</p>`).join('')}
                        </div>
                    </div>

                    <div class="flex items-center space-x-4">
                        <div class="flex items-center space-x-3">
                            <label for="quantity" class="text-sm font-medium">Quantity:</label>
                            <select id="product-quantity" class="border border-gray-300 rounded-lg px-3 py-2 focus:ring-green-500 focus:border-green-500">
                                <option value="1">1</option>
                                <option value="2">2</option>
                                <option value="3">3</option>
                                <option value="4">4</option>
                                <option value="5">5</option>
                            </select>
                        </div>
                        <button onclick="addToCartFromDetail('${productId}')" class="bg-green-700 text-white px-8 py-3 rounded-full font-semibold hover:bg-green-800 transition-colors">
                            Add to Cart
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('product-detail-content').innerHTML = detailContent;
    showPage('product-detail');
}

// Quick Add to Cart
function quickAddToCart(productId, fallbackName, fallbackPrice) {
    const product = products[productId];
    const name = (product && product.name) ? product.name : (fallbackName || 'Product');
    const price = (product && typeof product.price === 'number') ? product.price : (typeof fallbackPrice === 'number' ? fallbackPrice : 0);
    addToCart(productId, name, price, 1);
}

function switchTab(event, tabId) {
    // Remove active state from all tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
        button.classList.remove('border-green-700', 'text-green-700');
        button.classList.add('border-transparent', 'text-gray-500');
    });

    // Add active state to clicked tab button
    event.currentTarget.classList.remove('border-transparent', 'text-gray-500');
    event.currentTarget.classList.add('border-green-700', 'text-green-700');

    // Hide all tab content
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.add('hidden');
        content.classList.remove('active');
    });

    // Show selected tab content
    const selectedTab = document.getElementById(tabId);
    selectedTab.classList.remove('hidden');
    selectedTab.classList.add('active');
}

// Export functions and data
window.products = products;
window.showProductDetail = showProductDetail;
window.quickAddToCart = quickAddToCart;
window.switchTab = switchTab;
window.loadProductReviews = loadProductReviews;