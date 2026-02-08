// User Page Authentication and Functionality

// Check if user is logged in
window.addEventListener('load', function() {
    if (!checkUserAuth()) {
        return;
    }
    
    // Display user name
    displayUserName();
    
    // Initialize logout button
    initializeUserLogout();
});

// Display user name in header
function displayUserName() {
    const userData = JSON.parse(localStorage.getItem('userData') || '{}');
    const userNameElement = document.getElementById('userName');
    
    if (userNameElement) {
        if (userData.firstName || userData.username) {
            const fullName = userData.firstName && userData.lastName 
                ? userData.firstName + ' ' + userData.lastName 
                : (userData.username || 'User');
            userNameElement.innerHTML = '<i class="fas fa-user"></i> ' + fullName;
        }
    }
}
