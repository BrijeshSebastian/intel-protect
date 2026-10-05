import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { 
  loginApi, 
  registerApi, 
  logoutApi, 
  refreshApi, 
  getCurrentUserApi, 
  setAccessToken, 
  clearAccessToken 
} from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessTokenState, setAccessTokenState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  // Updates in-memory access token in both React state and Axios service
  const updateAccessToken = useCallback((token) => {
    setAccessTokenState(token);
    if (token) {
      setAccessToken(token);
    } else {
      clearAccessToken();
    }
  }, []);

  // Silent session restore using HttpOnly cookie on application startup
  const restoreSession = useCallback(async () => {
    setLoading(true);
    setAuthError(null);
    try {
      const response = await refreshApi();
      const token = response?.data?.access_token;
      const userData = response?.data?.user;

      if (token && userData) {
        updateAccessToken(token);
        setUser(userData);
      } else {
        updateAccessToken(null);
        setUser(null);
      }
    } catch (err) {
      // Expected when user is not logged in / no refresh cookie present
      updateAccessToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [updateAccessToken]);

  useEffect(() => {
    restoreSession();

    // Event listener for session expired signal from Axios interceptor
    const handleSessionExpired = () => {
      updateAccessToken(null);
      setUser(null);
    };

    window.addEventListener('auth:session_expired', handleSessionExpired);
    return () => {
      window.removeEventListener('auth:session_expired', handleSessionExpired);
    };
  }, [restoreSession, updateAccessToken]);

  // Login handler
  const login = async (email, password) => {
    setAuthError(null);
    try {
      const response = await loginApi({ email, password });
      const token = response?.data?.access_token;
      const userData = response?.data?.user;

      if (!token || !userData) {
        throw new Error('Authentication response missing access token or user profile.');
      }

      updateAccessToken(token);
      setUser(userData);
      return { success: true, user: userData };
    } catch (err) {
      const msg = err.message || 'Login failed. Please check your credentials.';
      setAuthError(msg);
      throw err;
    }
  };

  // Register handler
  const register = async (userData) => {
    setAuthError(null);
    try {
      const response = await registerApi(userData);
      return { success: true, data: response?.data };
    } catch (err) {
      const msg = err.message || 'Registration failed. Please try again.';
      setAuthError(msg);
      throw err;
    }
  };

  // Logout handler
  const logout = async () => {
    try {
      await logoutApi();
    } catch (err) {
      console.warn('Logout request completed with warning:', err);
    } finally {
      updateAccessToken(null);
      setUser(null);
    }
  };

  const value = {
    user,
    accessToken: accessTokenState,
    isAuthenticated: Boolean(user && accessTokenState),
    loading,
    authError,
    login,
    register,
    logout,
    restoreSession,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
