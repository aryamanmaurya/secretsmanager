// Enhanced JavaScript for Password Manager

// Dark Mode Functionality
class DarkMode {
    static init() {
        this.loadTheme();
        this.bindEvents();
    }

    static loadTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
        this.updateToggleIcon(savedTheme);
    }

    static toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-bs-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';

        document.documentElement.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        this.updateToggleIcon(newTheme);
    }

    static updateToggleIcon(theme) {
        const toggleBtn = document.getElementById('darkModeToggle');
        if (toggleBtn) {
            const icon = toggleBtn.querySelector('i');
            if (icon) {
                icon.className = theme === 'light' ? 'bi bi-moon' : 'bi bi-sun';
            }
        }
    }

    static bindEvents() {
        const toggleBtn = document.getElementById('darkModeToggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleTheme());
        }
    }
}

// AJAX Helper Functions
class AjaxHelper {
    static getCSRFToken() {
        // Try multiple ways to get the CSRF token
        const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ||
                     document.querySelector('input[name="csrf_token"]')?.value ||
                     document.querySelector('input[name="csrf-token"]')?.value;

        if (!token) {
            console.warn('CSRF token not found');
        }
        return token;
    }

    static async post(url, data = {}) {
        let csrfToken = this.getCSRFToken();

        // If no CSRF token found, try to get it from the form
        if (!csrfToken) {
            console.warn('CSRF token not found in meta tags, checking forms...');
            // Look for any form with CSRF token
            const formWithToken = document.querySelector('form');
            if (formWithToken) {
                const formToken = formWithToken.querySelector('input[name="csrf_token"]');
                if (formToken) {
                    csrfToken = formToken.value;
                }
            }
        }

        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(data)
        };

        // Add CSRF token to headers if available
        if (csrfToken) {
            options.headers['X-CSRFToken'] = csrfToken;
        } else {
            console.error('No CSRF token available for request to:', url);
        }

        try {
            const response = await fetch(url, options);

            // Check if response is JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                const text = await response.text();
                console.error('Non-JSON response received. Status:', response.status, 'Response:', text.substring(0, 200));

                // Create a structured error based on status code
                let errorMessage = 'Request failed';
                if (response.status === 400) {
                    if (text.includes('CSRF')) {
                        errorMessage = 'CSRF token missing or invalid. Please refresh the page and try again.';
                    } else {
                        errorMessage = 'Bad request. Please check your input.';
                    }
                } else if (response.status === 403) {
                    errorMessage = 'Access denied. You may not have permission for this action.';
                } else if (response.status === 404) {
                    errorMessage = 'Requested resource not found.';
                } else if (response.status === 500) {
                    errorMessage = 'Server error. Please try again later.';
                }

                throw new Error(`${errorMessage} (Status: ${response.status})`);
            }
        } catch (error) {
            console.error('Fetch error for', url, ':', error);
            throw error;
        }
    }

    static async delete(url) {
        const csrfToken = this.getCSRFToken();

        const response = await fetch(url, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': csrfToken
            }
        });

        return await response.json();
    }

    static showAlert(message, type = 'info') {
        // Remove existing alerts
        document.querySelectorAll('.alert-dismissible').forEach(alert => {
            alert.remove();
        });

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        const container = document.querySelector('.container.mt-3');
        if (container) {
            container.appendChild(alertDiv);
        } else {
            document.body.insertBefore(alertDiv, document.body.firstChild);
        }

        // Auto dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    static setLoading(element, isLoading) {
        if (!element) return;

        if (isLoading) {
            element.classList.add('loading');
            element.disabled = true;
            // Add spinner if not exists
            if (!element.querySelector('.loading-spinner')) {
                const spinner = document.createElement('span');
                spinner.className = 'loading-spinner spinner-border spinner-border-sm me-1';
                element.prepend(spinner);
            }
        } else {
            element.classList.remove('loading');
            element.disabled = false;
            // Remove spinner
            const spinner = element.querySelector('.loading-spinner');
            if (spinner) {
                spinner.remove();
            }
        }
    }
}

// Admin Management
class AdminManager {
    static init() {
        this.bindAdminEvents();
        console.log('AdminManager initialized');
    }

    static bindAdminEvents() {
        console.log('Binding admin events...');

        // Use event delegation for all admin buttons
        document.addEventListener('click', (e) => {
            const button = e.target.closest('.btn-toggle-admin, .btn-toggle-active, .btn-toggle-sharing, .btn-reset-password');
            
            if (!button) return;

            // Prevent multiple rapid clicks
            if (button.disabled || button.getAttribute('data-processing') === 'true') {
                e.preventDefault();
                e.stopPropagation();
                return;
            }

            // Mark as processing
            button.setAttribute('data-processing', 'true');

            // Route to appropriate handler
            if (button.classList.contains('btn-toggle-admin')) {
                this.handleToggleAdmin(e);
            } else if (button.classList.contains('btn-toggle-active')) {
                this.handleToggleActive(e);
            } else if (button.classList.contains('btn-toggle-sharing')) {
                this.handleToggleSharing(e);
            } else if (button.classList.contains('btn-reset-password')) {
                this.handleResetPassword(e);
            }

            // Remove processing flag after a delay
            setTimeout(() => {
                button.removeAttribute('data-processing');
            }, 2000);
        });

        // Password reset modal
        const confirmBtn = document.getElementById('confirmPasswordReset');
        if (confirmBtn) {
            confirmBtn.addEventListener('click', () => {
                this.confirmPasswordReset();
            });
        }
    }

    static async handleToggleAdmin(e) {
        const btn = e.target.closest('.btn-toggle-admin');
        if (!btn) return;

        const userId = btn.dataset.userId;
        console.log('Toggling admin for user:', userId);

        if (!confirm('Are you sure you want to change admin status?')) {
            btn.removeAttribute('data-processing');
            return;
        }

        AjaxHelper.setLoading(btn, true);

        try {
            const response = await AjaxHelper.post(`/admin/users/${userId}/toggle_admin`);
            console.log('Toggle admin response:', response);

            if (response.success) {
                AjaxHelper.showAlert('Admin status updated successfully', 'success');
                this.updateAdminUI(userId, response.is_admin);
            } else {
                AjaxHelper.showAlert(response.error || 'Unknown error', 'danger');
            }
        } catch (error) {
            console.error('Error toggling admin status:', error);
            AjaxHelper.showAlert('Error updating admin status. Please try again.', 'danger');
        } finally {
            AjaxHelper.setLoading(btn, false);
            btn.removeAttribute('data-processing');
        }
    }

    static async handleToggleActive(e) {
        const btn = e.target.closest('.btn-toggle-active');
        if (!btn) return;

        const userId = btn.dataset.userId;
        const action = btn.querySelector('.btn-active-text')?.textContent?.trim() || 'change status';
        console.log('Toggling active for user:', userId, 'Action:', action);

        if (!confirm(`Are you sure you want to ${action.toLowerCase()} this user?`)) {
            btn.removeAttribute('data-processing');
            return;
        }

        AjaxHelper.setLoading(btn, true);

        try {
            const response = await AjaxHelper.post(`/admin/users/${userId}/toggle_active`);
            console.log('Toggle active response:', response);

            if (response.success) {
                AjaxHelper.showAlert('User status updated successfully', 'success');
                this.updateActiveUI(userId, response.is_active);
            } else {
                AjaxHelper.showAlert(response.error || 'Unknown error', 'danger');
            }
        } catch (error) {
            console.error('Error toggling user status:', error);
            AjaxHelper.showAlert('Error updating user status. Please try again.', 'danger');
        } finally {
            AjaxHelper.setLoading(btn, false);
            btn.removeAttribute('data-processing');
        }
    }

    static async handleToggleSharing(e) {
        const btn = e.target.closest('.btn-toggle-sharing');
        if (!btn) return;

        const userId = btn.dataset.userId;
        const action = btn.querySelector('.btn-sharing-text')?.textContent?.trim() || 'change sharing';
        console.log('Toggling sharing for user:', userId, 'Action:', action);

        if (!confirm(`Are you sure you want to ${action.toLowerCase()} for this user?`)) {
            btn.removeAttribute('data-processing');
            return;
        }

        AjaxHelper.setLoading(btn, true);

        try {
            const response = await AjaxHelper.post(`/admin/users/${userId}/toggle_sharing`);
            console.log('Toggle sharing response:', response);

            if (response.success) {
                AjaxHelper.showAlert('Sharing status updated successfully', 'success');
                this.updateSharingUI(userId, response.sharing_enabled);
            } else {
                AjaxHelper.showAlert(response.error || 'Unknown error', 'danger');
            }
        } catch (error) {
            console.error('Error toggling sharing status:', error);
            AjaxHelper.showAlert('Error updating sharing status. Please try again.', 'danger');
        } finally {
            AjaxHelper.setLoading(btn, false);
            btn.removeAttribute('data-processing');
        }
    }

    static handleResetPassword(e) {
        const btn = e.target.closest('.btn-reset-password');
        if (!btn) return;

        const userId = btn.dataset.userId;
        const userName = btn.dataset.userName;

        console.log('Reset password for user:', userId, userName);

        // Check if modal elements exist
        const resetUserId = document.getElementById('reset-user-id');
        const resetUserName = document.getElementById('reset-user-name');

        if (!resetUserId || !resetUserName) {
            console.error('Password reset modal elements not found');
            AjaxHelper.showAlert('Password reset modal not available. Please refresh the page.', 'danger');
            btn.removeAttribute('data-processing');
            return;
        }

        // Show modal instead of prompt
        resetUserId.value = userId;
        resetUserName.textContent = userName;

        const modalElement = document.getElementById('passwordResetModal');
        if (modalElement) {
            const modal = new bootstrap.Modal(modalElement);
            modal.show();
        } else {
            console.error('Password reset modal not found');
            AjaxHelper.showAlert('Password reset modal not available. Please refresh the page.', 'danger');
        }

        btn.removeAttribute('data-processing');
    }

    static async confirmPasswordReset() {
        const userId = document.getElementById('reset-user-id')?.value;
        const newPassword = document.getElementById('newPassword')?.value;
        const confirmPassword = document.getElementById('confirmPassword')?.value;
        const btn = document.getElementById('confirmPasswordReset');

        if (!userId) {
            AjaxHelper.showAlert('User ID not found', 'danger');
            return;
        }

        // Validate passwords
        if (!newPassword || !confirmPassword) {
            AjaxHelper.showAlert('Please fill in both password fields', 'danger');
            return;
        }

        if (newPassword !== confirmPassword) {
            AjaxHelper.showAlert('Passwords do not match', 'danger');
            return;
        }

        if (newPassword.length < 8) {
            AjaxHelper.showAlert('Password must be at least 8 characters long', 'danger');
            return;
        }

        // Check password complexity
        const hasUpperCase = /[A-Z]/.test(newPassword);
        const hasLowerCase = /[a-z]/.test(newPassword);
        const hasNumbers = /\d/.test(newPassword);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);

        if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
            AjaxHelper.showAlert('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character', 'danger');
            return;
        }

        AjaxHelper.setLoading(btn, true);

        try {
            const response = await AjaxHelper.post(`/admin/users/${userId}/reset_password`, {
                new_password: newPassword
            });

            if (response.success) {
                AjaxHelper.showAlert('Password reset successfully', 'success');
                // Close modal and reset form
                const modalElement = document.getElementById('passwordResetModal');
                if (modalElement) {
                    const modal = bootstrap.Modal.getInstance(modalElement);
                    if (modal) {
                        modal.hide();
                    }
                }
                const form = document.getElementById('passwordResetForm');
                if (form) {
                    form.reset();
                }
            } else {
                AjaxHelper.showAlert(response.error || 'Unknown error occurred', 'danger');
            }
        } catch (error) {
            console.error('Error resetting password:', error);
            AjaxHelper.showAlert('Error resetting password. Please try again.', 'danger');
        } finally {
            AjaxHelper.setLoading(btn, false);
        }
    }

    static updateAdminUI(userId, isAdmin) {
        // Update badge
        const badge = document.getElementById(`admin-badge-${userId}`);
        if (badge) {
            badge.textContent = isAdmin ? 'Yes' : 'No';
            badge.className = isAdmin ? 'badge bg-warning' : 'badge bg-secondary';
        }

        // Update button text
        const buttons = document.querySelectorAll(`.btn-toggle-admin[data-user-id="${userId}"]`);
        buttons.forEach(btn => {
            const textSpan = btn.querySelector('.btn-admin-text');
            if (textSpan) {
                textSpan.textContent = isAdmin ? 'Revoke Admin' : 'Make Admin';
            }
        });
    }

    static updateActiveUI(userId, isActive) {
        // Update badge
        const badge = document.getElementById(`status-badge-${userId}`);
        if (badge) {
            badge.textContent = isActive ? 'Active' : 'Inactive';
            badge.className = isActive ? 'badge bg-success' : 'badge bg-danger';
        }

        // Update buttons
        const buttons = document.querySelectorAll(`.btn-toggle-active[data-user-id="${userId}"]`);
        buttons.forEach(btn => {
            // Update icon
            const icon = btn.querySelector('i');
            if (icon) {
                icon.className = isActive ? 'bi bi-x-circle' : 'bi bi-check-circle';
            }

            // Update text
            const textSpan = btn.querySelector('.btn-active-text');
            if (textSpan) {
                textSpan.textContent = isActive ? 'Deactivate' : 'Activate';
            }

            // Update button class
            btn.className = isActive
                ? 'btn btn-outline-danger btn-toggle-active btn-sm'
                : 'btn btn-outline-success btn-toggle-active btn-sm';
        });
    }

    static updateSharingUI(userId, sharingEnabled) {
        // Update badge
        const badge = document.getElementById(`sharing-badge-${userId}`);
        if (badge) {
            badge.textContent = sharingEnabled ? 'Enabled' : 'Disabled';
            badge.className = sharingEnabled ? 'badge bg-success' : 'badge bg-danger';
        }

        // Update button text
        const buttons = document.querySelectorAll(`.btn-toggle-sharing[data-user-id="${userId}"]`);
        buttons.forEach(btn => {
            const textSpan = btn.querySelector('.btn-sharing-text');
            if (textSpan) {
                textSpan.textContent = sharingEnabled ? 'Disable Sharing' : 'Enable Sharing';
            }
        });
    }
}

// Project Management
class ProjectManager {
    static init() {
        this.bindProjectEvents();
    }

    static bindProjectEvents() {
        // Add CSRF token to all forms
        document.querySelectorAll('form').forEach(form => {
            if (!form.querySelector('input[name="csrf_token"]')) {
                const csrfInput = document.createElement('input');
                csrfInput.type = 'hidden';
                csrfInput.name = 'csrf_token';
                csrfInput.value = AjaxHelper.getCSRFToken();
                form.appendChild(csrfInput);
            }
        });
    }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing application...');
    
    // Initialize core functionality
    DarkMode.init();
    ProjectManager.init();

    // Initialize AdminManager if we're on an admin page
    if (document.querySelector('.btn-toggle-admin') || document.getElementById('usersTable')) {
        AdminManager.init();
    }

    // Auto-dismiss alerts after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.alert').forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

// Make helper functions globally available
window.AjaxHelper = AjaxHelper;
window.showAlert = AjaxHelper.showAlert;
