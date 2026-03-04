console.log("PhishDetect loaded ");

//  تأثير ضغط الأزرار
document.querySelectorAll('button, .btn').forEach(btn => {
  btn.addEventListener('click', () => {
    btn.style.transform = 'scale(0.95)';
    setTimeout(() => {
      btn.style.transform = 'scale(1)';
    }, 100);
  });
});

//  انميشن دخول الكروت
window.addEventListener('load', () => {
  document.querySelectorAll('.card').forEach((card, i) => {
    card.classList.add('fade-in');
    card.style.animationDelay = `${i * 0.1}s`;
  });
});

// 📁 Scan File interaction
const fileInput = document.getElementById('fileInput');
const fileForm = document.getElementById('fileForm');
const selectedFileName = document.getElementById('selectedFileName');

if (fileInput && fileForm && selectedFileName) {
  fileInput.addEventListener('change', (event) => {
    const file = event.target.files[0];
    if (file) {
      selectedFileName.textContent = file.name;
      console.log(" File selected:", file.name);
      fileForm.submit(); // Auto-submit after selection
    }
  });
}