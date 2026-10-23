        // utils.js - Utility functions used across DashGate

        // --- CSRF Protection ---
        // Override window.fetch to automatically include the CSRF token header
        // on all state-changing requests (POST, PUT, DELETE, PATCH).
        // The server sets a "dashgate_csrf" cookie on every response. JS reads
        // it and sends it back as the X-CSRF-Token header (double-submit cookie pattern).
        (function() {
            const _originalFetch = window.fetch;
            window.fetch = function(url, options) {
                options = options || {};
                const method = (options.method || 'GET').toUpperCase();
                if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
                    const csrfMatch = document.cookie.match(/(?:^|;\s*)dashgate_csrf=([^;]*)/);
                    if (csrfMatch) {
                        const token = decodeURIComponent(csrfMatch[1]);
                        if (options.headers instanceof Headers) {
                            if (!options.headers.has('X-CSRF-Token')) {
                                options.headers.set('X-CSRF-Token', token);
                            }
                        } else if (Array.isArray(options.headers)) {
                            const hasToken = options.headers.some(function(h) {
                                return h[0] && h[0].toLowerCase() === 'x-csrf-token';
                            });
                            if (!hasToken) {
                                options.headers.push(['X-CSRF-Token', token]);
                            }
                        } else {
                            options.headers = options.headers || {};
                            if (!options.headers['X-CSRF-Token']) {
                                options.headers['X-CSRF-Token'] = token;
                            }
                        }
                    }
                }
                return _originalFetch.call(this, url, options);
            };
        })();

        function escapeHtml(text) {
            if (text === null || text === undefined) return '';
            const div = document.createElement('div');
            div.appendChild(document.createTextNode(String(text)));
            return div.innerHTML.replace(/'/g, '&#39;').replace(/"/g, '&quot;');
        }

        function showToast(msg) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2500);
        }

        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
