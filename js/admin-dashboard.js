// Admin Dashboard Functionality

// Load admin data
function loadAdminData() {
    const adminData = localStorage.getItem('adminData');
    if (adminData) {
        try {
            const admin = JSON.parse(adminData);
            const fullName = admin.firstName + ' ' + admin.lastName;
            const initials = (admin.firstName[0] + admin.lastName[0]).toUpperCase();
            
            const adminNameHeaderElement = document.getElementById('adminNameHeader');
            const adminNameElement = document.getElementById('adminName');
            const avatarEl = document.getElementById('adminAvatar');
            
            if (adminNameHeaderElement) {
                adminNameHeaderElement.innerHTML = '<i class="fas fa-user" style="margin-right: 8px;"></i>' + fullName;
            }
            if (adminNameElement) {
                adminNameElement.textContent = fullName;
            }
            if (avatarEl) {
                avatarEl.textContent = initials;
            }
        } catch (e) {
            const adminNameHeaderElement = document.getElementById('adminNameHeader');
            const adminNameElement = document.getElementById('adminName');
            
            if (adminNameHeaderElement) {
                adminNameHeaderElement.innerHTML = '<i class="fas fa-user" style="margin-right: 8px;"></i>Administrator';
            }
            if (adminNameElement) {
                adminNameElement.textContent = 'Administrator';
            }
        }
    }
}

// Fetch statistics
async function fetchStats() {
    const token = getAdminAuthToken();

    try {
        // Fetch users data
        const usersResponse = await fetch('/api/auth/users', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const usersData = await usersResponse.json();

        if (usersResponse.ok && usersData.success) {
            const totalUsers = usersData.users.length;
            const totalAdmins = usersData.users.filter(function(u) { 
                return u.isAdmin; 
            }).length;
            
            const totalUsersElement = document.getElementById('totalUsers');
            const totalAdminsElement = document.getElementById('totalAdmins');
            
            if (totalUsersElement) totalUsersElement.textContent = totalUsers;
            if (totalAdminsElement) totalAdminsElement.textContent = totalAdmins;
        }

        // Fetch bookings data
        const bookingsResponse = await fetch('/api/bookings/all', {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            }
        });

        const bookingsData = await bookingsResponse.json();

        if (bookingsResponse.ok && bookingsData.success) {
            // Count only confirmed bookings
            const confirmedBookings = bookingsData.bookings.filter(function(b) { 
                return b.status === 'Confirmed'; 
            }).length;
            
            const totalBookingsElement = document.getElementById('totalBookings');
            if (totalBookingsElement) totalBookingsElement.textContent = confirmedBookings;
            
            // Calculate total rooms booked (sum of numberOfRooms from confirmed bookings)
            const totalRoomsBooked = bookingsData.bookings
                .filter(function(b) { return b.status === 'Confirmed'; })
                .reduce(function(sum, booking) { 
                    return sum + booking.numberOfRooms; 
                }, 0);
            
            // Calculate available rooms (50 total - total rooms booked)
            const totalRooms = 50;
            const availableRooms = totalRooms - totalRoomsBooked;
            
            const availableRoomsElement = document.getElementById('availableRooms');
            if (availableRoomsElement) availableRoomsElement.textContent = availableRooms;
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    if (checkAdminAuth()) {
        loadAdminData();
        fetchStats();
        initializeAdminLogout();
    }
});
