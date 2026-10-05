import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import LoadingSpinner from './LoadingSpinner';

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-[50vh] flex items-center justify-center">
        <LoadingSpinner size="lg" text="Verifying session credentials..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    // Redirect unauthenticated requests to login, preserving intended return route
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}
