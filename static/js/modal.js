// Modal Functions - hardware accelerated with minimal DOM ops
function openModal(modal, content) {
    console.log('Opening modal:', { modal, content });
    if (!modal || !content) {
        console.error('Modal or content is null/undefined');
        return;
    }
    
    // Calculate scrollbar width to prevent shift
    const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
    
    // Batch classList changes into one reflow
    requestAnimationFrame(() => {
        console.log('Adding modal classes');
        // Add padding to body to prevent shift
        document.body.style.paddingRight = scrollbarWidth + 'px';
        document.body.classList.add('modal-open');
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        // Add show in next frame for transition
        requestAnimationFrame(() => {
            console.log('Adding show class to content');
            content.classList.add('show');
        });
    });
}

function closeModal(modal, content) {
    // Remove show to start transition
    content.classList.remove('show');

    const cleanup = () => {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
        document.body.classList.remove('modal-open');
        document.body.style.paddingRight = '';
    };

    // Listen for the end of content transition
    const onTransitionEnd = (e) => {
        if (e.propertyName !== 'transform' && e.propertyName !== 'opacity') return;
        content.removeEventListener('transitionend', onTransitionEnd);
        cleanup();
    };

    content.addEventListener('transitionend', onTransitionEnd);
    // Fallback if transition fails
    setTimeout(cleanup, 300);
}

// Export functions
window.openModal = openModal;
window.closeModal = closeModal;