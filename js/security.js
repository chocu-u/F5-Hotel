// Security and Authentication Functions

// Check if admin is logged in
function checkAdminAuth() {
    const adminLoggedIn = sessionStorage.getItem('adminLoggedIn');
    const adminToken = localStorage.getItem('adminAuthToken');
    
    if (!adminLoggedIn || !adminToken) {
        alert('Unauthorized access. Please login as administrator.');
        window.location.href = 'adminlogin.html';
        return false;
    }
    return true;
}

// Check if user is logged in
function checkUserAuth() {
    const userLoggedIn = sessionStorage.getItem('userLoggedIn');
    const userToken = localStorage.getItem('authToken');
    
    if (!userLoggedIn || !userToken) {
        alert('Please login to access this page.');
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

// Admin logout function
function handleAdminLogout() {
    if (confirm('Are you sure you want to logout?')) {
        sessionStorage.removeItem('adminLoggedIn');
        sessionStorage.removeItem('adminUsername');
        localStorage.removeItem('adminAuthToken');
        localStorage.removeItem('adminUserData');
        
        window.location.href = 'adminlogin.html';
    }
}

// User logout function
function handleUserLogout() {
    if (confirm('Are you sure you want to logout?')) {
        sessionStorage.removeItem('userLoggedIn');
        sessionStorage.removeItem('username');
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
        
        window.location.href = 'login.html';
    }
}

// Initialize logout button for admin pages
function initializeAdminLogout() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            handleAdminLogout();
        });
    }
}

// Initialize logout button for user pages
function initializeUserLogout() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            handleUserLogout();
        });
    }
}

// Get auth token from storage
function getAuthToken() {
    return localStorage.getItem('authToken') || localStorage.getItem('adminAuthToken');
}

// Get admin token from storage
function getAdminAuthToken() {
    return localStorage.getItem('adminAuthToken');
}

// Sanitize user input to prevent XSS
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Validate and sanitize form data
function sanitizeFormData(formData) {
    const sanitized = {};
    for (const [key, value] of Object.entries(formData)) {
        if (typeof value === 'string') {
            sanitized[key] = sanitizeInput(value);
        } else {
            sanitized[key] = value;
        }
    }
    return sanitized;
}
