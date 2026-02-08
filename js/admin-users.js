// Admin Users Page Functionality

// Load admin data
function loadAdminData() {
    const adminData = localStorage.getItem('adminData');
    if (adminData) {
        try {
            const admin = JSON.parse(adminData);
            const fullName = admin.firstName + ' ' + admin.lastName;
            const initials = (admin.firstName[0] + admin.lastName[0]).toUpperCase();
            
            const adminNameElement = document.getElementById('adminNameHeader');
            const adminAvatarElement = document.getElementById('adminAvatar');
            
            if (adminNameElement) {
                adminNameElement.innerHTML = '<i class="fas fa-user" style="margin-right: 8px;"></i>' + fullName;
            }
            if (adminAvatarElement) {
                adminAvatarElement.textContent = initials;
            }
        } catch (e) {
            console.error('Error loading admin data:', e);
        }
    }
}

// Format date
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric'
    });
}

// Format date time
function formatDateTime(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Fetch all users
async function loadUsers() {
    const token = getAdminAuthToken();
    const container = document.getElementById('usersTableContainer');

    if (!container) return;

    container.innerHTML = '<div class="loading"><i class="fa fa-spinner fa-spin"></i> Loading users...</div>';

    try {
        const response = await fetch('/api/auth/users', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            displayUsers(data.users);
        } else {
            container.innerHTML = '<div class="no-data">Failed to load users</div>';
        }
    } catch (error) {
        console.error('Error fetching users:', error);
        container.innerHTML = '<div class="no-data">Error loading users. Make sure the server is running.</div>';
    }
}

// Display users in table
function displayUsers(users) {
    const container = document.getElementById('usersTableContainer');
    
    if (!users || users.length === 0) {
        container.innerHTML = '<div class="no-data">No users found</div>';
        const userCountElement = document.getElementById('userCount');
        if (userCountElement) {
            userCountElement.textContent = '(0 users)';
        }
        return;
    }

    const userCountElement = document.getElementById('userCount');
    if (userCountElement) {
        userCountElement.textContent = '(' + users.length + ' users)';
    }

    let tableHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>First Name</th>
                    <th>Middle Name</th>
                    <th>Last Name</th>
                    <th>Role</th>
                    <th>Registered</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;

    users.forEach(function(user, index) {
        const roleTag = user.isAdmin 
            ? '<span class="admin-tag">ADMIN</span>' 
            : '<span class="user-tag">USER</span>';
        
        tableHTML += `
            <tr>
                <td>${index + 1}</td>
                <td><strong>${sanitizeInput(user.username)}</strong></td>
                <td>${sanitizeInput(user.email)}</td>
                <td>${sanitizeInput(user.firstName)}</td>
                <td>${user.middleName ? sanitizeInput(user.middleName) : '-'}</td>
                <td>${sanitizeInput(user.lastName)}</td>
                <td>${roleTag}</td>
                <td>${formatDateTime(user.createdAt)}</td>
                <td>${formatDateTime(user.lastLogin)}</td>
                <td>
                    <button class="action-btn delete-btn" data-user-id="${user._id}" data-username="${sanitizeInput(user.username)}">
                        <i class="fa fa-trash"></i> Delete
                    </button>
                </td>
            </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    container.innerHTML = tableHTML;

    // Attach delete event listeners
    attachDeleteListeners();
}

// Attach event listeners to delete buttons
function attachDeleteListeners() {
    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            const userId = this.getAttribute('data-user-id');
            const username = this.getAttribute('data-username');
            deleteUser(userId, username);
        });
    });
}

// Delete user
async function deleteUser(userId, username) {
    if (!confirm('Are you sure you want to delete user "' + username + '"? This action cannot be undone.')) {
        return;
    }

    const token = getAdminAuthToken();

    try {
        const response = await fetch('/api/auth/users/' + userId, {
            method: 'DELETE',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert('User deleted successfully!');
            loadUsers();
        } else {
            alert('Failed to delete user: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        alert('Error deleting user. Please try again.');
    }
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    if (checkAdminAuth()) {
        loadAdminData();
        loadUsers();
        initializeAdminLogout();
    }
});
