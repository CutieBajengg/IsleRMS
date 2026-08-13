// public/auth/auth.js

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.querySelector("#loginFormElem");
  const signupForm = document.querySelector("#signupFormElem");

  const showError = (message) => {
    alert("❌ " + message);
  };

  const showSuccess = (message) => {
    alert("✅ " + message);
  };

  // LOGIN FORM
  if (loginForm) {
    loginForm.addEventListener("submit", () => {
      // Let the form submit normally
      showSuccess("Logging in...");
    });
  }

  // SIGNUP FORM
  if (signupForm) {
    signupForm.addEventListener("submit", (e) => {
      const phoneInput = document.getElementById("phoneInput");

      // Validate phone before submit
      if (phoneInput.value.length !== 11) {
        e.preventDefault();
        showError("Phone must be exactly 11 digits.");
        return;
      }

      showSuccess("Creating your account...");
      // allow normal submit
    });
  }
});