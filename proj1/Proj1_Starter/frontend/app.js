const API_URL = "http://localhost:3000";

// Initialize Keychain
async function initializeKeychain() {
    const password = prompt("Enter master password:");
    if (!password) {
        alert("Master password is required!");
        return;
    }

    const response = await fetch(`${API_URL}/init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
    });

    const data = await response.json();
    if (response.ok) {
        alert(data.message);
        loadPasswords();
    } else {
        alert(`Error: ${data.error}`);
    }
}
document.getElementById('init-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('master-password').value;

    const response = await fetch('/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
    });
    const data = await response.json();
    alert(data.message);
});

document.getElementById('set-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('domain').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/set', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, password }),
    });
    const data = await response.json();
    alert(data.message);
});

document.getElementById('get-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('retrieve-domain').value;

    const response = await fetch('/get', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
    });
    const data = await response.json();
    if (data.error) {
        alert(data.error);
    } else {
        alert(`Password for ${data.domain}: ${data.password}`);
    }
});

// Add password
document.getElementById("add-password").addEventListener("click", async () => {
    const name = document.getElementById("site-name").value;
    const password = document.getElementById("site-password").value;

    if (!name || !password) return alert("Please fill all fields!");

    const response = await fetch(`${API_URL}/set`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: name, password }),
    });

    const data = await response.json();
    if (response.ok) {
        alert(data.message);
    } else {
        alert(`Error: ${data.error}`);
    }

    document.getElementById("site-name").value = "";
    document.getElementById("site-password").value = "";
    loadPasswords();
});

// Load passwords
async function loadPasswords() {
    try {
        const response = await fetch(`${API_URL}/get`, { method: "POST" });
        const passwords = await response.json();

        const passwordList = document.getElementById("passwords");
        passwordList.innerHTML = "";

        passwords.forEach((entry) => {
            const li = document.createElement("li");
            li.innerHTML = `
              ${entry.domain}: ${entry.password}
              <button onclick="deletePassword('${entry.id}')">Delete</button>
            `;
            passwordList.appendChild(li);
        });
    } catch (error) {
        console.error('Error loading passwords:', error);
        alert('Failed to load passwords.');
    }
}

// Delete password
async function deletePassword(domain) {
    const response = await fetch(`${API_URL}/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
    });

    const data = await response.json();
    if (response.ok) {
        alert(data.message);
    } else {
        alert(`Error: ${data.message}`);
    }

    loadPasswords();
}

// Initial load: prompt for master password
initializeKeychain();
