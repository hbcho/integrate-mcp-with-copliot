document.addEventListener("DOMContentLoaded", () => {
  const activitiesList = document.getElementById("activities-list");
  const activitySelect = document.getElementById("activity");
  const signupForm = document.getElementById("signup-form");
  const messageDiv = document.getElementById("message");
  const signupContainer = document.getElementById("signup-container");
  const authForm = document.getElementById("auth-form");
  const authMessage = document.getElementById("auth-message");
  const logoutButton = document.getElementById("logout-button");
  let accessToken = null;
  let currentUser = null;

  function clearSession() {
    accessToken = null;
    currentUser = null;
    signupContainer.classList.add("hidden");
    logoutButton.classList.add("hidden");
    activitiesList.innerHTML = "<p>Sign in to view activities.</p>";
  }

  function showAuthMessage(message, className) {
    authMessage.textContent = message;
    authMessage.className = className;
    authMessage.classList.remove("hidden");
  }

  function handleUnauthorized() {
    clearSession();
    showAuthMessage("Your session has expired. Please sign in again.", "error");
  }

  async function refreshSession() {
    const response = await fetch("/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) return false;

    const result = await response.json();
    accessToken = result.access_token;
    currentUser = result.user;
    return true;
  }

  async function authenticatedFetch(url, options = {}) {
    const sendRequest = () =>
      fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          Authorization: `Bearer ${accessToken}`,
        },
      });

    let response = await sendRequest();
    if (response.status === 401 && await refreshSession()) {
      response = await sendRequest();
    }
    if (response.status === 401) handleUnauthorized();
    return response;
  }

  // Function to fetch activities from API
  async function fetchActivities() {
    if (!accessToken) {
      activitiesList.innerHTML = "<p>Sign in to view activities.</p>";
      return;
    }

    try {
      const response = await authenticatedFetch("/activities");
      if (response.status === 401) return;
      if (!response.ok) throw new Error("Failed to load activities");
      const activities = await response.json();
      const canManageActivities = ["teacher", "admin"].includes(currentUser?.role);
      signupContainer.classList.toggle("hidden", !canManageActivities);
      logoutButton.classList.remove("hidden");

      // Clear loading message
      activitiesList.innerHTML = "";
      activitySelect.innerHTML = '<option value="">-- Select an activity --</option>';

      // Populate activities list
      Object.entries(activities).forEach(([name, details]) => {
        const activityCard = document.createElement("div");
        activityCard.className = "activity-card";

        const spotsLeft =
          details.max_participants - details.participants.length;

        // Create participants HTML with delete icons instead of bullet points
        const participantsHTML =
          details.participants.length > 0
            ? `<div class="participants-section">
              <h5>Participants:</h5>
              <ul class="participants-list">
                ${details.participants
                  .map(
                    (email) =>
                      `<li><span class="participant-email">${email}</span>${canManageActivities ? `<button class="delete-btn" data-activity="${name}" data-email="${email}" aria-label="Unregister ${email}">Remove</button>` : ""}</li>`
                  )
                  .join("")}
              </ul>
            </div>`
            : `<p><em>No participants yet</em></p>`;

        activityCard.innerHTML = `
          <h4>${name}</h4>
          <p>${details.description}</p>
          <p><strong>Schedule:</strong> ${details.schedule}</p>
          <p><strong>Availability:</strong> ${spotsLeft} spots left</p>
          <div class="participants-container">
            ${participantsHTML}
          </div>
        `;

        activitiesList.appendChild(activityCard);

        // Add option to select dropdown
        const option = document.createElement("option");
        option.value = name;
        option.textContent = name;
        activitySelect.appendChild(option);
      });

      // Add event listeners to delete buttons
      document.querySelectorAll(".delete-btn").forEach((button) => {
        button.addEventListener("click", handleUnregister);
      });
    } catch (error) {
      activitiesList.innerHTML =
        "<p>Failed to load activities. Please try again later.</p>";
      console.error("Error fetching activities:", error);
    }
  }

  // Handle unregister functionality
  async function handleUnregister(event) {
    const button = event.target;
    const activity = button.getAttribute("data-activity");
    const email = button.getAttribute("data-email");

    try {
      const response = await authenticatedFetch(
        `/activities/${encodeURIComponent(
          activity
        )}/unregister?email=${encodeURIComponent(email)}`,
        {
          method: "DELETE",
        }
      );

      if (response.status === 401) return;

      const result = await response.json();

      if (response.ok) {
        messageDiv.textContent = result.message;
        messageDiv.className = "success";

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.className = "error";
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to unregister. Please try again.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      console.error("Error unregistering:", error);
    }
  }

  // Handle form submission
  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const otpCode = document.getElementById("otp-code").value;

    try {
      const response = await fetch("/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, otp_code: otpCode || null }),
      });
      const result = await response.json();
      if (!response.ok) {
        showAuthMessage(result.detail?.message || "Sign in failed.", "error");
        return;
      }

      accessToken = result.access_token;
      currentUser = result.user;
      authForm.reset();
      showAuthMessage(`Signed in as ${currentUser.username} (${currentUser.role}).`, "success");
      await fetchActivities();
    } catch (error) {
      showAuthMessage("Unable to sign in. Please try again.", "error");
      console.error("Error signing in:", error);
    }
  });

  logoutButton.addEventListener("click", async () => {
    try {
      if (accessToken) await authenticatedFetch("/auth/logout", { method: "POST" });
    } finally {
      clearSession();
      authMessage.classList.add("hidden");
      messageDiv.classList.add("hidden");
    }
  });

  signupForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const activity = document.getElementById("activity").value;

    try {
      const response = await authenticatedFetch(
        `/activities/${encodeURIComponent(
          activity
        )}/signup?email=${encodeURIComponent(email)}`,
        {
          method: "POST",
        }
      );

      if (response.status === 401) return;

      const result = await response.json();

      if (response.ok) {
        messageDiv.textContent = result.message;
        messageDiv.className = "success";
        signupForm.reset();

        // Refresh activities list to show updated participants
        fetchActivities();
      } else {
        messageDiv.textContent = result.detail || "An error occurred";
        messageDiv.className = "error";
      }

      messageDiv.classList.remove("hidden");

      // Hide message after 5 seconds
      setTimeout(() => {
        messageDiv.classList.add("hidden");
      }, 5000);
    } catch (error) {
      messageDiv.textContent = "Failed to sign up. Please try again.";
      messageDiv.className = "error";
      messageDiv.classList.remove("hidden");
      console.error("Error signing up:", error);
    }
  });

  // Initialize app
  clearSession();
  refreshSession()
    .then((restored) => {
      if (restored) fetchActivities();
    })
    .catch((error) => console.error("Error restoring session:", error));
});
