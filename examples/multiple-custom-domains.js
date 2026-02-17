/**
 * Multiple Custom Domains (MCD) Example
 *
 * This example demonstrates how to configure express-openid-connect
 * to dynamically resolve different Auth0 issuers based on request context.
 *
 * Run with: npm run start:example -- multiple-custom-domains
 *
 * Test by accessing:
 * - http://localhost:3000?tenant=tenant-a
 * - http://localhost:3000?tenant=tenant-b
 */

const express = require('express');
const { auth } = require('../');

const app = express();

// Simulated tenant configuration - keys are the only valid tenant values
const tenantConfig = {
  'tenant-a': process.env.TENANT_A_ISSUER || process.env.ISSUER_BASE_URL,
  'tenant-b': process.env.TENANT_B_ISSUER || process.env.ISSUER_BASE_URL,
  default: process.env.ISSUER_BASE_URL,
};

// Dynamic issuer resolver function
async function issuerResolver(context) {
  const tenantId = context.req.query.tenant || 'default';
  const issuer = tenantConfig[tenantId] || tenantConfig.default;
  console.log(`[MCD] Resolved tenant: ${tenantId} -> ${issuer}`);
  return issuer;
}

app.use(
  auth({
    issuerBaseURL: issuerResolver,
    authRequired: false,
  }),
);

app.get('/', (req, res) => {
  // Validate tenant against known keys to prevent XSS
  const requestedTenant = req.query.tenant || 'default';
  const tenant = tenantConfig[requestedTenant] ? requestedTenant : 'default';

  if (req.oidc.isAuthenticated()) {
    res.send(`Hello ${req.oidc.user.sub} (tenant: ${tenant})`);
  } else {
    res.send(
      `<a href="/login?tenant=tenant-a">Login as tenant-a</a> | ` +
        `<a href="/login?tenant=tenant-b">Login as tenant-b</a>`,
    );
  }
});

module.exports = app;
