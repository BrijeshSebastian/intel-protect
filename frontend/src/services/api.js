import axios from 'axios';

// Volatile in-memory token storage (NEVER written to localStorage or sessionStorage)
let inMemoryAccessToken = null;

export const setAccessToken = (token) => {
  inMemoryAccessToken = token;
};

export const getAccessToken = () => {
  return inMemoryAccessToken;
};

export const clearAccessToken = () => {
  inMemoryAccessToken = null;
};

// Base API configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  withCredentials: true, // Required to send/receive HttpOnly refresh cookie
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
});

// Request interceptor: attach in-memory Bearer token
api.interceptors.request.use(
  (config) => {
    if (inMemoryAccessToken && !config.headers['Authorization']) {
      config.headers['Authorization'] = `Bearer ${inMemoryAccessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Concurrency control for silent refresh
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

// Response interceptor: handle token expiration and automatic token rotation
api.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    const originalRequest = error.config;
    const status = error.response?.status;
    const errorData = error.response?.data?.error || {};

    // Bypass refresh logic for login/register/refresh endpoints to avoid infinite loops
    const isAuthRoute = originalRequest?.url?.includes('/auth/login') ||
                        originalRequest?.url?.includes('/auth/register') ||
                        originalRequest?.url?.includes('/auth/refresh');

    if (status === 401 && !isAuthRoute && !originalRequest?._retry) {
      if (isRefreshing) {
        // Queue parallel requests until refresh completes
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((newToken) => {
            originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Attempt token rotation using HttpOnly cookie
        const refreshResponse = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          {},
          { withCredentials: true }
        );

        const newAccessToken = refreshResponse.data?.data?.access_token;
        if (!newAccessToken) {
          throw new Error('Refresh failed to return new access token.');
        }

        setAccessToken(newAccessToken);
        processQueue(null, newAccessToken);

        originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshErr) {
        processQueue(refreshErr, null);
        clearAccessToken();
        // Dispatch session expired event for AuthContext listener
        window.dispatchEvent(new CustomEvent('auth:session_expired'));
        return Promise.reject(refreshErr.response?.data?.error || {
          code: 'SESSION_EXPIRED',
          message: 'Your session has expired. Please log in again.'
        });
      } finally {
        isRefreshing = false;
      }
    }

    // Normalize standard error response envelope
    const errorPayload = error.response?.data?.error || {
      code: error.code || 'NETWORK_ERROR',
      message: error.message || 'Unable to connect to the backend server.',
      details: {},
    };
    return Promise.reject(errorPayload);
  }
);

// ==============================================================================
// Authentication API Calls
// ==============================================================================

export const checkHealth = async () => {
  return await api.get('/health');
};

export const registerApi = async (userData) => {
  return await api.post('/auth/register', userData);
};

export const loginApi = async (credentials) => {
  return await api.post('/auth/login', credentials);
};

export const refreshApi = async () => {
  return await api.post('/auth/refresh');
};

export const logoutApi = async () => {
  return await api.post('/auth/logout');
};

export const getCurrentUserApi = async () => {
  return await api.get('/auth/me');
};

// ==============================================================================
// Documents API Calls
// ==============================================================================

export const uploadDocumentApi = async (formData, onProgress) => {
  return await api.post('/documents/scan', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(percent);
      }
    },
  });
};

export const getDocumentsApi = async (page = 1, limit = 10) => {
  return await api.get('/documents', {
    params: { page, limit },
  });
};

export const getDocumentByIdApi = async (id) => {
  return await api.get(`/documents/${id}`);
};

export const deleteDocumentApi = async (id) => {
  return await api.delete(`/documents/${id}`);
};

export const getDocumentFindingsApi = async (id) => {
  return await api.get(`/documents/${id}/findings`);
};

export const getDocumentRiskApi = async (id) => {
  return await api.get(`/documents/${id}/risk`);
};

// ==============================================================================
// Exposure Monitor API Calls
// ==============================================================================

export const analyzeExposureApi = async (payload) => {
  return await api.post('/exposure/analyze', payload);
};

export const getExposureHistoryApi = async (page = 1, limit = 10) => {
  return await api.get('/exposure/history', {
    params: { page, limit },
  });
};

export const getExposureByIdApi = async (id) => {
  return await api.get(`/exposure/${id}`);
};

export const deleteExposureApi = async (id) => {
  return await api.delete(`/exposure/${id}`);
};

// ==============================================================================
// Breach Monitor & Recommendations API Calls
// ==============================================================================

export const checkBreachesApi = async (payload) => {
  return await api.post('/breaches/check', payload);
};

export const getBreachHistoryApi = async (page = 1, limit = 10) => {
  return await api.get('/breaches/history', {
    params: { page, limit },
  });
};

export const getBreachByIdApi = async (id) => {
  return await api.get(`/breaches/${id}`);
};

export const deleteBreachApi = async (id) => {
  return await api.delete(`/breaches/${id}`);
};

export const getBreachCatalogApi = async (page = 1, limit = 50) => {
  return await api.get('/breaches/catalog', {
    params: { page, limit },
  });
};

export const getRecommendationsApi = async (active = true) => {
  return await api.get('/recommendations', {
    params: { active },
  });
};

export const dismissRecommendationApi = async (id) => {
  return await api.patch(`/recommendations/${id}/dismiss`);
};

// ==============================================================================
// Unified Threat Dashboard API Calls
// ==============================================================================

export const getDashboardApi = async () => {
  return await api.get('/dashboard');
};

export default api;


