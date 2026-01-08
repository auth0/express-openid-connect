#!/bin/bash

# Convert test files to ESM
TEST_FILES=(
  "test/requiresAuth.tests.js"
  "test/attemptSilentLogin.tests.js"
  "test/transientHandler.tests.js"
  "test/callback.tests.js"
  "test/logout.tests.js"
  "test/client.tests.js"
  "test/login.tests.js"
  "test/backchannelLogout.tests.js"
)

for file in "${TEST_FILES[@]}"; do
  echo "Converting $file..."
  
  # Basic CommonJS to ESM conversions
  sed -i '' "s/const { assert } = require('chai')/import { assert } from 'chai'/g" "$file"
  sed -i '' "s/const assert = require('chai')\.assert/import { assert } from 'chai'/g" "$file"
  sed -i '' "s/const sinon = require('sinon')/import sinon from 'sinon'/g" "$file"
  sed -i '' "s/const nock = require('nock')/import nock from 'nock'/g" "$file"
  sed -i '' "s/const express = require('express')/import express from 'express'/g" "$file"
  sed -i '' "s/const { JWT } = require('jose')/import { JWT } from 'jose'/g" "$file"
  
  # Request-related imports  
  sed -i '' "s/const request = require('request-promise-native')\.defaults({/import request from 'request-promise-native';\nconst requestDefaults = request.defaults({/g" "$file"
  sed -i '' "s/request\./requestDefaults./g" "$file"
  sed -i '' "s/requestDefaults\.jar()/request.jar()/g" "$file"
  sed -i '' "s/ request(/ requestDefaults(/g" "$file"
  
  # Library imports
  sed -i '' "s/require('\.\.\/lib\/appSession')/import appSession from '..\/lib\/appSession.js'/g" "$file"
  sed -i '' "s/require('\.\.\/lib\/config')/import { get as getConfig } from '..\/lib\/config.js'/g" "$file"
  sed -i '' "s/require('\.\.\/lib\/client')/import { get as getClient } from '..\/lib\/client.js'/g" "$file"
  sed -i '' "s/require('\.\.\/lib\/context')/import { RequestContext, ResponseContext } from '..\/lib\/context.js'/g" "$file"
  sed -i '' "s/require('\.\.\/lib\/transientHandler')/import TransientCookieHandler from '..\/lib\/transientHandler.js'/g" "$file"
  
  # Middleware imports
  sed -i '' "s/require('\.\.\/middleware\/auth')/import auth from '..\/middleware\/auth.js'/g" "$file"
  sed -i '' "s/require('\.\.\/middleware\/requiresAuth')/import * as requiresAuthExports from '..\/middleware\/requiresAuth.js'/g" "$file"
  sed -i '' "s/require('\.\.\/middleware\/attemptSilentLogin')/import attemptSilentLogin from '..\/middleware\/attemptSilentLogin.js'/g" "$file"
  
  # Fixture imports
  sed -i '' "s/require('\.\/fixture\/server')/import { create as createServer } from '.\/fixture\/server.js'/g" "$file"
  sed -i '' "s/require('\.\/fixture\/cert')/import * as cert from '.\/fixture\/cert.js'/g" "$file"
  sed -i '' "s/require('\.\/fixture\/sessionEncryption')/import sessionEncryption from '.\/fixture\/sessionEncryption.js'/g" "$file"
  
  # Fix destructuring from fixture imports
  sed -i '' "s/cert\.makeIdToken/cert.makeIdToken/g" "$file"
  sed -i '' "s/cert\.makeLogoutToken/cert.makeLogoutToken/g" "$file"
  sed -i '' "s/cert\.jwks/cert.jwks/g" "$file"
  sed -i '' "s/cert\.key/cert.keyPEM/g" "$file"
  
  # Fix requiresAuth destructuring
  sed -i '' "s/const { requiresAuth, claimEquals, claimIncludes, claimCheck } = require/const { requiresAuth, claimEquals, claimIncludes, claimCheck } = requiresAuthExports/g" "$file"
  
  echo "Converted $file"
done

echo "Basic conversion complete!"
