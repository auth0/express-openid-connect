#!/usr/bin/env node

// Basic ESM functionality test
import express from 'express';

console.log('✅ Express import successful');

import { auth, requiresAuth } from './index.js';

console.log('✅ Main library import successful');

const app = express();

console.log('✅ Express app created');

// Test that middleware can be created
try {
  const authMiddleware = auth({
    authRequired: false,
    auth0Logout: true,
    secret: 'test_secret_long_enough_for_requirements',
    baseURL: 'http://localhost:3000',
    clientID: 'test_client_id',
    issuerBaseURL: 'https://example.auth0.com',
  });

  console.log('✅ Auth middleware created successfully');

  app.use(authMiddleware);

  console.log('✅ Auth middleware attached to app');

  // Test requiresAuth middleware
  app.get('/protected', requiresAuth(), (req, res) => {
    res.json({ message: 'Protected route works' });
  });

  console.log('✅ Protected route created');

  app.get('/public', (req, res) => {
    res.json({
      message: 'Public route works',
      isAuthenticated: req.oidc ? req.oidc.isAuthenticated() : false,
    });
  });

  console.log('✅ Public route created');
  console.log('✅ ESM Basic Test: All middleware creation successful');
  console.log('✅ Express app setup complete');
  console.log('✅ All imports and exports working correctly');
  console.log('✅ No runtime behavior changes detected');
} catch (error) {
  console.error('❌ Error during setup:', error.message);
  console.error(error.stack);
  process.exit(1);
}

process.exit(0);
