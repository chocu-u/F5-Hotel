// Footer functionality - dynamically set copyright year

document.addEventListener('DOMContentLoaded', function() {
    // Set current year in copyright footer
    const yearElements = document.querySelectorAll('.copyright-year');
    const currentYear = new Date().getFullYear();
    
    yearElements.forEach(function(element) {
        element.textContent = currentYear;
    });
});
