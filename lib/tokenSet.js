// Simple TokenSet replacement for openid-client v6 migration
class TokenSet {
  constructor(tokens = {}) {
    Object.assign(this, tokens);
  }

  expired() {
    if (!this.expires_at) return false;
    return this.expires_at <= Math.floor(Date.now() / 1000);
  }

  claims() {
    if (!this.id_token) return {};

    try {
      // Decode JWT without verification (just for claims extraction)
      const [, payload] = this.id_token.split('.');
      const decodedPayload = Buffer.from(payload, 'base64url').toString('utf8');
      return JSON.parse(decodedPayload);
    } catch {
      return {};
    }
  }
}

module.exports = { TokenSet };
