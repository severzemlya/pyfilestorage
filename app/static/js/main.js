// PyFileStorage - Main JavaScript

// ==================== Internationalization (i18n) ====================
const i18n = {
    currentLang: 'en',
    translations: {},
    
    async init() {
        this.currentLang = localStorage.getItem('lang') || navigator.language.split('-')[0] || 'en';
        // Fallback to 'en' if language is not supported
        if (!['en', 'ja'].includes(this.currentLang)) {
            this.currentLang = 'en';
        }
        await this.loadTranslations(this.currentLang);
        this.applyTranslations();
        this.updateLangAttribute();
    },
    
    async loadTranslations(lang) {
        try {
            const response = await fetch(`/static/locales/${lang}.json`);
            if (response.ok) {
                this.translations = await response.json();
            } else {
                console.warn(`Could not load translations for ${lang}, falling back to English`);
                if (lang !== 'en') {
                    const enResponse = await fetch('/static/locales/en.json');
                    if (enResponse.ok) {
                        this.translations = await enResponse.json();
                    }
                }
            }
        } catch (error) {
            console.error('Error loading translations:', error);
        }
    },
    
    t(key) {
        const keys = key.split('.');
        let value = this.translations;
        for (const k of keys) {
            if (value && typeof value === 'object' && k in value) {
                value = value[k];
            } else {
                return key; // Return key if translation not found
            }
        }
        return value;
    },
    
    applyTranslations() {
        // Translate elements with data-i18n attribute
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = this.t(key);
            if (translation !== key) {
                el.textContent = translation;
            }
        });
        
        // Translate placeholders
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            const translation = this.t(key);
            if (translation !== key) {
                el.placeholder = translation;
            }
        });
        
        // Translate titles
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            const key = el.getAttribute('data-i18n-title');
            const translation = this.t(key);
            if (translation !== key) {
                el.title = translation;
            }
        });
    },
    
    async setLanguage(lang) {
        this.currentLang = lang;
        localStorage.setItem('lang', lang);
        await this.loadTranslations(lang);
        this.applyTranslations();
        this.updateLangAttribute();
        this.updateLangDropdown();
    },
    
    updateLangAttribute() {
        document.documentElement.setAttribute('data-lang', this.currentLang);
        document.documentElement.setAttribute('lang', this.currentLang);
    },
    
    updateLangDropdown() {
        document.querySelectorAll('.lang-option').forEach(option => {
            if (option.dataset.lang === this.currentLang) {
                option.classList.add('active');
            } else {
                option.classList.remove('active');
            }
        });
    }
};

// Make i18n globally available
window.i18n = i18n;

// Initialize i18n when DOM is ready
// This ensures translations are loaded before other scripts need them
(function initI18n() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => i18n.init());
    } else {
        i18n.init();
    }
})();

// Language selector
(function() {
    const langToggle = document.getElementById('lang-toggle');
    const langDropdown = document.getElementById('lang-dropdown');
    
    if (langToggle && langDropdown) {
        langToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            langDropdown.classList.toggle('active');
        });
        
        document.addEventListener('click', () => {
            langDropdown.classList.remove('active');
        });
        
        document.querySelectorAll('.lang-option').forEach(option => {
            option.addEventListener('click', () => {
                const lang = option.dataset.lang;
                i18n.setLanguage(lang);
                langDropdown.classList.remove('active');
            });
        });
    }
    
    // Initialize active state
    i18n.updateLangDropdown();
})();

// Theme Management
(function() {
    const themeToggle = document.getElementById('theme-toggle');
    const html = document.documentElement;
    
    // Get saved theme or system preference
    function getPreferredTheme() {
        const saved = localStorage.getItem('theme');
        if (saved) return saved;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    
    // Apply theme
    function setTheme(theme) {
        html.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        updateThemeIcon(theme);
    }
    
    // Update toggle button icon
    function updateThemeIcon(theme) {
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
            }
        }
    }
    
    // Initialize theme
    setTheme(getPreferredTheme());
    
    // Toggle theme on click
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const current = html.getAttribute('data-theme');
            setTheme(current === 'dark' ? 'light' : 'dark');
        });
    }
    
    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
            setTheme(e.matches ? 'dark' : 'light');
        }
    });
})();

// Auto-dismiss alerts after 5 seconds
document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        setTimeout(() => alert.remove(), 300);
    }, 5000);
});

// File card click navigation (for folders)
document.querySelectorAll('.folder-card .file-name').forEach(link => {
    const card = link.closest('.file-card');
    if (card) {
        card.style.cursor = 'pointer';
        card.addEventListener('click', (e) => {
            if (!e.target.closest('.file-actions') && !e.target.closest('form')) {
                link.click();
            }
        });
    }
});

// Copy to clipboard with feedback
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        const originalHtml = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
            button.innerHTML = originalHtml;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Escape to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }
    
    // Ctrl/Cmd + K for search focus
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('.search-box input');
        if (searchInput) {
            searchInput.focus();
            searchInput.select();
        }
    }
});

// Form validation feedback
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn && !submitBtn.disabled) {
            submitBtn.disabled = true;
            const originalHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
            
            // Re-enable after timeout (in case of error)
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalHtml;
            }, 10000);
        }
    });
});

// Confirm dangerous actions
document.querySelectorAll('[data-confirm]').forEach(element => {
    element.addEventListener('click', (e) => {
        if (!confirm(element.dataset.confirm)) {
            e.preventDefault();
        }
    });
});

// File size formatting helper
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Drag and drop visual feedback for file cards
document.querySelectorAll('.file-card[draggable="true"]').forEach(card => {
    card.addEventListener('dragstart', (e) => {
        card.classList.add('dragging');
        e.dataTransfer.setData('text/plain', card.dataset.fileId);
    });
    
    card.addEventListener('dragend', () => {
        card.classList.remove('dragging');
    });
});

// Folder drop targets
document.querySelectorAll('.folder-card').forEach(folder => {
    folder.addEventListener('dragover', (e) => {
        e.preventDefault();
        folder.classList.add('drag-over');
    });
    
    folder.addEventListener('dragleave', () => {
        folder.classList.remove('drag-over');
    });
    
    folder.addEventListener('drop', (e) => {
        e.preventDefault();
        folder.classList.remove('drag-over');
        const fileId = e.dataTransfer.getData('text/plain');
        const folderId = folder.dataset.folderId;
        
        if (fileId && folderId) {
            // Move file to folder via AJAX
            const formData = new FormData();
            formData.append('folder_id', folderId);
            
            fetch(`/file/${fileId}/move`, {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    alert(data.error || 'Failed to move file');
                }
            })
            .catch(err => {
                console.error('Move failed:', err);
                alert('Failed to move file');
            });
        }
    });
});

// Image lazy loading
if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                if (img.dataset.src) {
                    img.src = img.dataset.src;
                    img.removeAttribute('data-src');
                }
                observer.unobserve(img);
            }
        });
    });
    
    document.querySelectorAll('img[data-src]').forEach(img => {
        imageObserver.observe(img);
    });
}

// Service worker registration (for PWA support)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        // navigator.serviceWorker.register('/sw.js').catch(() => {});
    });
}

// ==================== Share Link Modal ====================
function showShareLinkModal(url) {
    const modal = document.getElementById('share-link-modal');
    const input = document.getElementById('share-link-input');
    
    if (modal && input) {
        input.value = url;
        modal.classList.add('active');
        
        // Auto-copy to clipboard
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).catch(() => {
                // Fallback: select the text
                input.select();
            });
        } else {
            input.select();
            try {
                document.execCommand('copy');
            } catch (e) {
                // Copy not supported
            }
        }
    }
}

function closeShareLinkModal() {
    const modal = document.getElementById('share-link-modal');
    if (modal) {
        modal.classList.remove('active');
        // Reload the page to show the updated share link list
        // Only reload if on a share page
        if (window.location.pathname.includes('/share/')) {
            window.location.reload();
        }
    }
}

function copyShareLinkAgain() {
    const input = document.getElementById('share-link-input');
    if (input) {
        const url = input.value;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(() => {
                showToastGlobal('success', window.i18n ? window.i18n.t('share.link_copied') : 'Link copied to clipboard!');
            }).catch(() => {
                input.select();
                document.execCommand('copy');
                showToastGlobal('success', window.i18n ? window.i18n.t('share.link_copied') : 'Link copied to clipboard!');
            });
        } else {
            input.select();
            document.execCommand('copy');
            showToastGlobal('success', window.i18n ? window.i18n.t('share.link_copied') : 'Link copied to clipboard!');
        }
    }
}

// Global toast function (for use from main.js)
function showToastGlobal(type, message) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'fa-info-circle';
    if (type === 'success') icon = 'fa-check-circle';
    else if (type === 'error') icon = 'fa-exclamation-circle';
    else if (type === 'warning') icon = 'fa-exclamation-triangle';
    
    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span>${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.classList.add('toast-fadeout');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ==================== Delete Confirmation Modal ====================
let pendingDeleteForm = null;

function showDeleteConfirmModal(message, form) {
    const modal = document.getElementById('delete-confirm-modal');
    const messageEl = document.getElementById('delete-confirm-message');
    const confirmBtn = document.getElementById('delete-confirm-btn');
    
    if (modal && messageEl && confirmBtn) {
        messageEl.textContent = message;
        pendingDeleteForm = form;
        modal.classList.add('active');
        
        // Remove previous event listener and add new one
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
        newConfirmBtn.addEventListener('click', confirmDelete);
    }
}

function closeDeleteConfirmModal() {
    const modal = document.getElementById('delete-confirm-modal');
    if (modal) {
        modal.classList.remove('active');
        pendingDeleteForm = null;
    }
}

function confirmDelete() {
    if (pendingDeleteForm) {
        pendingDeleteForm.submit();
    }
    closeDeleteConfirmModal();
}

// Make functions globally available
window.showShareLinkModal = showShareLinkModal;
window.closeShareLinkModal = closeShareLinkModal;
window.copyShareLinkAgain = copyShareLinkAgain;
window.showDeleteConfirmModal = showDeleteConfirmModal;
window.closeDeleteConfirmModal = closeDeleteConfirmModal;
window.confirmDelete = confirmDelete;

console.log('PyFileStorage initialized');
