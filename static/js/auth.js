const AUTH_STORAGE_KEY = "nova_auth";

function getStoredAuth() {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) {
        return null;
    }
    try {
        return JSON.parse(raw);
    } catch {
        localStorage.removeItem(AUTH_STORAGE_KEY);
        return null;
    }
}

function saveAuth(payload) {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(payload));
}

function clearAuth() {
    localStorage.removeItem(AUTH_STORAGE_KEY);
}

function getAccessToken() {
    return getStoredAuth()?.access_token || null;
}

function getRefreshToken() {
    return getStoredAuth()?.refresh_token || null;
}

function getCurrentUser() {
    return getStoredAuth()?.user || null;
}

function requireAdminPage() {
    const auth = getStoredAuth();
    if (!auth?.access_token) {
        window.location.href = "/login";
        return false;
    }
    if (!auth.user?.is_admin) {
        clearAuth();
        window.location.href = "/login";
        return false;
    }
    return true;
}

function populateOperatorLabel() {
    const user = getCurrentUser();
    const label = document.getElementById("operatorLabel");
    if (label && user?.username) {
        label.textContent = user.username;
    }
}

async function refreshAccessToken() {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
        return null;
    }

    const response = await fetch(`${CONFIG.BASE_URL}/auth/refresh`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${refreshToken}`,
            "Content-Type": "application/json",
        },
    });

    if (!response.ok) {
        clearAuth();
        return null;
    }

    const data = await response.json();
    const auth = getStoredAuth();
    if (!auth) {
        return null;
    }

    auth.access_token = data.access_token;
    saveAuth(auth);
    return auth.access_token;
}

async function authFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = getAccessToken();

    if (token) {
        headers.set("Authorization", `Bearer ${token}`);
    }
    if (!headers.has("Content-Type") && options.body) {
        headers.set("Content-Type", "application/json");
    }

    let response = await fetch(url, { ...options, headers });

    if (response.status === 401) {
        const newToken = await refreshAccessToken();
        if (!newToken) {
            window.location.href = "/login";
            return response;
        }
        headers.set("Authorization", `Bearer ${newToken}`);
        response = await fetch(url, { ...options, headers });
    }

    return response;
}

function buildSseUrl(path, params = {}) {
    const token = getAccessToken();
    const search = new URLSearchParams(params);
    if (token) {
        search.set("token", token);
    }
    return `${path}?${search.toString()}`;
}

async function loginWithEmail(email, password) {
    let response;
    try {
        response = await fetch(`${CONFIG.BASE_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });
    } catch {
        throw new Error("Cannot reach the server. Make sure the dashboard is running on http://127.0.0.1:5000");
    }

    let data = {};
    try {
        data = await response.json();
    } catch {
        throw new Error(`Login failed (HTTP ${response.status}). Check that the server is running.`);
    }
    if (!response.ok) {
        throw new Error(data.error || "Login failed.");
    }

    if (!data.user?.is_admin) {
        throw new Error("Admin access is required for the NOVA dashboard.");
    }

    saveAuth({
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        user: data.user,
    });

    return data;
}

async function logoutUser() {
    const refreshToken = getRefreshToken();
    if (refreshToken) {
        try {
            await fetch(`${CONFIG.BASE_URL}/auth/logout`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${refreshToken}`,
                    "Content-Type": "application/json",
                },
            });
        } catch {
            // Best-effort logout; clear local session regardless.
        }
    }
    clearAuth();
    window.location.href = "/login";
}
