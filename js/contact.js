// Contact/Profile Page Functionality

let currentUser = null;

// Initialize contact page
window.addEventListener('load', function() {
    if (!checkUserAuth()) {
        return;
    }
    
    // Load user profile
    const token = getAuthToken();
    if (token) {
        loadUserProfile();
    } else {
        // If no token, display from localStorage
        const userData = JSON.parse(localStorage.getItem('userData') || '{}');
        if (userData.firstName || userData.username) {
            displayUserName();
            displayUserProfile(userData);
            initializeProfileForm(userData);
            currentUser = userData;
        }
    }
    
    // Initialize event listeners
    setupProfileEventListeners();
    
    // Initialize logout
    initializeUserLogout();
});

// Load user profile from backend
function loadUserProfile() {
    const token = getAuthToken();
    
    if (!token) {
        console.log('No token found, using localStorage data');
        return;
    }
    
    fetch('/api/auth/profile', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        }
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error('Failed to load profile');
        }
        return response.json();
    })
    .then(function(data) {
        if (data.success) {
            currentUser = data.user;
            displayUserProfile(currentUser);
            initializeProfileForm(currentUser);
            
            // Update header
            const userNameElement = document.getElementById('userName');
            if (userNameElement) {
                const fullName = currentUser.firstName && currentUser.lastName 
                    ? currentUser.firstName + ' ' + currentUser.lastName 
                    : (currentUser.username || 'User');
                userNameElement.innerHTML = '<i class="fas fa-user"></i> ' + fullName;
            }
        }
    })
    .catch(function(error) {
        console.error('Error loading profile:', error);
        // Fallback to localStorage data
        const userData = JSON.parse(localStorage.getItem('userData') || '{}');
        if (userData.firstName || userData.username) {
            displayUserName();
            displayUserProfile(userData);
            initializeProfileForm(userData);
            currentUser = userData;
        }
    });
}

// Display user profile in view mode
function displayUserProfile(user) {
    const viewFirstNameElement = document.getElementById('viewFirstName');
    const viewLastNameElement = document.getElementById('viewLastName');
    const viewMiddleNameElement = document.getElementById('viewMiddleName');
    const viewEmailElement = document.getElementById('viewEmail');
    const viewContactNumberElement = document.getElementById('viewContactNumber');
    const viewUsernameElement = document.getElementById('viewUsername');
    const viewDateOfBirthElement = document.getElementById('viewDateOfBirth');
    
    if (viewFirstNameElement) viewFirstNameElement.textContent = user.firstName || '-';
    if (viewLastNameElement) viewLastNameElement.textContent = user.lastName || '-';
    if (viewMiddleNameElement) viewMiddleNameElement.textContent = user.middleName || '-';
    if (viewEmailElement) viewEmailElement.textContent = user.email || '-';
    if (viewContactNumberElement) viewContactNumberElement.textContent = user.contactNumber || '-';
    if (viewUsernameElement) viewUsernameElement.textContent = user.username || '-';
    
    if (user.dateOfBirth && viewDateOfBirthElement) {
        const date = new Date(user.dateOfBirth);
        viewDateOfBirthElement.textContent = date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    } else if (viewDateOfBirthElement) {
        viewDateOfBirthElement.textContent = '-';
    }
}

// Initialize edit form with current user data
function initializeProfileForm(user) {
    const editFirstNameElement = document.getElementById('editFirstName');
    const editLastNameElement = document.getElementById('editLastName');
    const editMiddleNameElement = document.getElementById('editMiddleName');
    const editEmailElement = document.getElementById('editEmail');
    const editContactNumberElement = document.getElementById('editContactNumber');
    const editUsernameElement = document.getElementById('editUsername');
    const editDateOfBirthElement = document.getElementById('editDateOfBirth');
    
    if (editFirstNameElement) editFirstNameElement.value = user.firstName || '';
    if (editLastNameElement) editLastNameElement.value = user.lastName || '';
    if (editMiddleNameElement) editMiddleNameElement.value = user.middleName || '';
    if (editEmailElement) editEmailElement.value = user.email || '';
    if (editContactNumberElement) editContactNumberElement.value = user.contactNumber || '';
    if (editUsernameElement) editUsernameElement.value = user.username || '';
    
    if (user.dateOfBirth && editDateOfBirthElement) {
        const date = new Date(user.dateOfBirth);
        const yyyy = date.getFullYear();
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const dd = String(date.getDate()).padStart(2, '0');
        editDateOfBirthElement.value = yyyy + '-' + mm + '-' + dd;
    }
}

// Setup profile event listeners
function setupProfileEventListeners() {
    const editBtn = document.getElementById('editBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const updateProfileForm = document.getElementById('updateProfileForm');
    
    if (editBtn) {
        editBtn.addEventListener('click', function() {
            const profileView = document.getElementById('profileView');
            const profileEdit = document.getElementById('profileEdit');
            const updateMessage = document.getElementById('updateMessage');
            
            if (profileView) profileView.style.display = 'none';
            if (profileEdit) profileEdit.style.display = 'block';
            if (updateMessage) updateMessage.style.display = 'none';
        });
    }
    
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function() {
            const profileView = document.getElementById('profileView');
            const profileEdit = document.getElementById('profileEdit');
            const updateMessage = document.getElementById('updateMessage');
            
            if (profileView) profileView.style.display = 'block';
            if (profileEdit) profileEdit.style.display = 'none';
            if (updateMessage) updateMessage.style.display = 'none';
        });
    }
    
    if (updateProfileForm) {
        updateProfileForm.addEventListener('submit', handleProfileUpdate);
    }
}

// Handle profile update
function handleProfileUpdate(e) {
    e.preventDefault();
    
    const token = getAuthToken();
    const messageDiv = document.getElementById('updateMessage');
    const saveBtn = document.getElementById('saveBtn');
    
    if (!token) {
        if (messageDiv) {
            messageDiv.style.display = 'block';
            messageDiv.style.background = '#f8d7da';
            messageDiv.style.color = '#721c24';
            messageDiv.textContent = 'No authentication token found. Please login again.';
        }
        return;
    }
    
    const formData = {
        firstName: document.getElementById('editFirstName').value,
        lastName: document.getElementById('editLastName').value,
        middleName: document.getElementById('editMiddleName').value,
        email: document.getElementById('editEmail').value,
        contactNumber: document.getElementById('editContactNumber').value,
        dateOfBirth: document.getElementById('editDateOfBirth').value
    };

    // Sanitize form data
    const sanitizedData = sanitizeFormData(formData);

    // Show loading message
    if (messageDiv) {
        messageDiv.style.display = 'block';
        messageDiv.style.background = '#e8f4f8';
        messageDiv.style.color = '#0066cc';
        messageDiv.textContent = 'Updating profile...';
    }
    if (saveBtn) saveBtn.disabled = true;

    fetch('/api/auth/profile', {
        method: 'PUT',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(sanitizedData)
    })
    .then(function(response) {
        if (!response.ok) {
            throw new Error('Failed to update profile');
        }
        return response.json();
    })
    .then(function(data) {
        if (data.success) {
            currentUser = data.user;
            displayUserProfile(currentUser);
            
            if (messageDiv) {
                messageDiv.style.display = 'block';
                messageDiv.style.background = '#d4edda';
                messageDiv.style.color = '#155724';
                messageDiv.textContent = 'Profile updated successfully!';
            }
            
            // Update localStorage
            localStorage.setItem('userData', JSON.stringify({
                firstName: currentUser.firstName,
                lastName: currentUser.lastName,
                email: currentUser.email,
                username: currentUser.username
            }));
            
            // Update header name
            const userNameElement = document.getElementById('userName');
            if (userNameElement) {
                const fullName = currentUser.firstName && currentUser.lastName 
                    ? currentUser.firstName + ' ' + currentUser.lastName 
                    : (currentUser.username || 'User');
                userNameElement.innerHTML = '<i class="fas fa-user"></i> ' + fullName;
            }
            
            setTimeout(function() {
                const profileView = document.getElementById('profileView');
                const profileEdit = document.getElementById('profileEdit');
                
                if (profileView) profileView.style.display = 'block';
                if (profileEdit) profileEdit.style.display = 'none';
                if (messageDiv) messageDiv.style.display = 'none';
                if (saveBtn) saveBtn.disabled = false;
            }, 2000);
        } else {
            throw new Error(data.message || 'Update failed');
        }
    })
    .catch(function(error) {
        console.error('Error updating profile:', error);
        if (messageDiv) {
            messageDiv.style.display = 'block';
            messageDiv.style.background = '#f8d7da';
            messageDiv.style.color = '#721c24';
            messageDiv.textContent = error.message || 'Error updating profile. Please try again.';
        }
        if (saveBtn) saveBtn.disabled = false;
    });
}
