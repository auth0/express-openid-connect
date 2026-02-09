/**
 * ⚠️ WARNING: TEST KEYS ONLY - DO NOT USE IN PRODUCTION ⚠️
 *
 * This file contains RSA private keys that are INTENTIONALLY PUBLIC for testing.
 * These keys are:
 * - FOR TESTING ONLY - Never use in production
 * - PUBLICLY COMMITTED - Not secret, safe for test fixtures
 * - DETERMINISTIC - Same keys every test run for reproducibility
 *
 * Pre-generated RSA-2048 key pair for testing.
 *
 * Note: jose v6 only provides async key generation (generateKeyPair), which cannot
 * be used at module load time. Using a static key here is preferable for tests as it:
 * - Ensures deterministic test results
 * - Improves test performance (no generation overhead)
 * - Simplifies debugging with consistent test data
 *
 * This key was originally sourced from examples/private-key.pem and matches the
 * private key JWT example in the codebase.
 *
 * See end-to-end/fixture/README.md for more information on test key security.
 *
 * To regenerate if needed:
 * ```
 * const { generateKeyPair, exportPKCS8, exportSPKI, exportJWK } = require('jose');
 * const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
 * const privatePEM = await exportPKCS8(privateKey);
 * const publicPEM = await exportSPKI(publicKey);
 * const privateJWK = await exportJWK(privateKey);
 * const publicJWK = await exportJWK(publicKey);
 * ```
 */

const privatePEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDbTKOQLtaZ6U1k
3fcYCMVoy8poieNPPcbj15TCLOm4Bbox73/UUxIArqczVcjtUGnL+jn5982V5EiB
y8W51m5K9mIBgEFLYdLkXk+OW5UTE/AdMPtfsIjConGrrs3mxN4WSH9kvh9Yr41r
hWUUSwqFyMOssbGE8K46Cv0WYvS7RXH9MzcyTcMSFp/60yUXH4rdHYZElF7XCdiE
63WxebxI1Qza4xkjTlbp5EWfWBQB1Ms10JO8NjrtkCXrDI57Bij5YanPAVhctcO9
z5/y9i5xEzcer8ZLO8VDiXSdEsuP/fe+UKDyYHUITD8u51p3O2JwCKvdTHduemej
3Kd1RlHrAgMBAAECggEATWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qe
Kdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL+cTFsu8ORI+Fpi9+Tl
r6gGUfQhkXF85bhBfN6n9P2J2akxrz/njrf6wXrrL+V5C498tQuus1YFls0+zIpD
N+GngNOPHlGeY3gW4K/HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV/SmsIo7z+s
8CLjp/qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b+ETim35i
D/hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB+gQKBgQDvaZ1jG/FNPnKdayYv
z5yTOhKM6JTB+WjB0GSx8rebtbFppiHGgVhOd1bLIzli9uMOPdCNuXh7CKzIgSA6
Q76Wxfuaw8F6CBIdlG9bZNL6x8wp6zF8tGz/BgW7fFKBwFYSWzTcStGr2QGtwr6F
9p1gYPSGfdERGOQc7RmhoNNHcQKBgQDqfkhpPfJlP/SdFnF7DDUvuMnaswzUsM6D
ZPhvfzdMBV8jGc0WjCW2Vd3pvsdPgWXZqAKjN7+A5HiT/8qv5ruoqOJSR9ZFZI/B
8v+8gS9Af7K56mCuCFKZmOXUmaL+3J2FKtzAyOlSLjEYyLuCgmhEA9Zo+duGR5xX
AIjx7N/ZGwKBgCZAYqQeJ8ymqJtcLkq/Sg3/3kzjMDlZxxIIYL5JwGpBemod4BGe
QuSujpCAPUABoD97QuIR+xz1Qt36O5LzlfTzBwMwOa5ssbBGMhCRKGBnIcikylBZ
Z3zLkojlES2n9FiUd/qmfZ+OWYVQsy4mO/jVJNyEJ64qou+4NjsrvfYRAoGAORki
3K1+1nSqRY3vd/zS/pnKXPx4RVoADzKI4+1gM5yjO9LOg40AqdNiw8X2lj9143fr
nH64nNQFIFSKsCZIz5q/8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ+X1
9uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0CgYB85pvPhBqqfcWi6qaVQtK1
ukIdiJtMNPwePfsT/2KqrbnftQnAKNnhsgcYGo8NAvntX4FokOAEdunyYmm85mLp
BGKYgVXJqnm6+TJyCRac1ro3noG898P/LZ8MOBoaYQtWeWRpDc46jPrA0FqUJy+i
ca/T0LLtgmbMmxSv/MmzIg==
-----END PRIVATE KEY-----`;

const publicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA20yjkC7WmelNZN33GAjF
aMvKaInjTz3G49eUwizpuAW6Me9/1FMSAK6nM1XI7VBpy/o5+ffNleRIgcvFudZu
SvZiAYBBS2HS5F5PjluVExPwHTD7X7CIwqJxq67N5sTeFkh/ZL4fWK+Na4VlFEsK
hcjDrLGxhPCuOgr9FmL0u0Vx/TM3Mk3DEhaf+tMlFx+K3R2GRJRe1wnYhOt1sXm8
SNUM2uMZI05W6eRFn1gUAdTLNdCTvDY67ZAl6wyOewYo+WGpzwFYXLXDvc+f8vYu
cRM3Hq/GSzvFQ4l0nRLLj/33vlCg8mB1CEw/LudadzticAir3Ux3bnpno9yndUZR
6wIDAQAB
-----END PUBLIC KEY-----`;

// For JWK format
const privateJWK = {
  kty: 'RSA',
  kid: 'key-1',
  use: 'sig',
  alg: 'RS256',
  n: '20yjkC7WmelNZN33GAjFaMvKaInjTz3G49eUwizpuAW6Me9_1FMSAK6nM1XI7VBpy_o5-ffNleRIgcvFudZuSvZiAYBBS2HS5F5PjluVExPwHTD7X7CIwqJxq67N5sTeFkh_ZL4fWK-Na4VlFEsKhcjDrLGxhPCuOgr9FmL0u0Vx_TM3Mk3DEhaf-tMlFx-K3R2GRJRe1wnYhOt1sXm8SNUM2uMZI05W6eRFn1gUAdTLNdCTvDY67ZAl6wyOewYo-WGpzwFYXLXDvc-f8vYucRM3Hq_GSzvFQ4l0nRLLj_33vlCg8mB1CEw_LudadzticAir3Ux3bnpno9yndUZR6w',
  e: 'AQAB',
  d: 'TWdzpASkQpcSdjPSb21JIIAt5VAmJ2YKuYjyPMdVh1qeKdn7KJpZlFwRMBFrZjgn35Nmu1A4BFwbK5UdKUcCjvsABL-cTFsu8ORI-Fpi9-Tlr6gGUfQhkXF85bhBfN6n9P2J2akxrz_njrf6wXrrL-V5C498tQuus1YFls0-zIpDN-GngNOPHlGeY3gW4K_HjGuHwuJOvWNmE4KNQhBijdd50Am824Y4NV_SmsIo7z-s8CLjp_qtihwnE4rkUHnR6M4u5lpzXOnodzkDTG8euOJds0T8DwLNTx1b-ETim35iD_hOCVwl8QFoj2aatjuJ5LXZtZUEpGpBF2TQecB-gQ',
  p: '72mdYxvxTT5ynWsmL8-ckzoSjOiUwflowdBksfK3m7WxaaYhxoFYTndWyyM5YvbjDj3Qjbl4ewisyIEgOkO-lsX7msPBeggSHZRvW2TS-sfMKesxfLRs_wYFu3xSgcBWEls03ErRq9kBrcK-hfadYGD0hn3RERjkHO0ZoaDTR3E',
  q: '6n5IaT3yZT_0nRZxeww1L7jJ2rMM1LDOg2T4b383TAVfIxnNFowltlXd6b7HT4Fl2agCoze_gOR4k__Kr-a7qKjiUkfWRWSPwfL_vIEvQH-yuepgrghSmZjl1Jmi_tydhSrcwMjpUi4xGMi7goJoRAPWaPnbhkecVwCI8ezf2Rs',
  dp: 'JkBipB4nzKaom1wuSr9KDf_eTOMwOVnHEghgvknAakF6ah3gEZ5C5K6OkIA9QAGgP3tC4hH7HPVC3fo7kvOV9PMHAzA5rmyxsEYyEJEoYGchyKTKUFlnfMuSiOURLaf0WJR3-qZ9n45ZhVCzLiY7-NUk3IQnriqi77g2Oyu99hE',
  dq: 'ORki3K1-1nSqRY3vd_zS_pnKXPx4RVoADzKI4-1gM5yjO9LOg40AqdNiw8X2lj9143frnH64nNQFIFSKsCZIz5q_8TUY0bDY6GsZJnd2YAg4JtkRTY8tPcVjQU9fxxtFJ-X19uN1HNOulNBcCD1k0hr1HH6qm5nYUb8JmY8KOr0',
  qi: 'fOabz4Qaqn3FouqmlULStbpCHYibTDT8Hj37E_9iqq2537UJwCjZ4bIHGBqPDQL57V-BaJDgBHbp8mJpvOZi6QRimIFVyap5uvkycgkWnNa6N56BvPfD_y2fDDgaGmELVnlkaQ3OOoz6wNBalCcvonGv09Cy7YJmzJsUr_zJsyI',
};

const publicJWK = {
  kty: 'RSA',
  kid: 'key-1',
  use: 'sig',
  alg: 'RS256',
  n: '20yjkC7WmelNZN33GAjFaMvKaInjTz3G49eUwizpuAW6Me9_1FMSAK6nM1XI7VBpy_o5-ffNleRIgcvFudZuSvZiAYBBS2HS5F5PjluVExPwHTD7X7CIwqJxq67N5sTeFkh_ZL4fWK-Na4VlFEsKhcjDrLGxhPCuOgr9FmL0u0Vx_TM3Mk3DEhaf-tMlFx-K3R2GRJRe1wnYhOt1sXm8SNUM2uMZI05W6eRFn1gUAdTLNdCTvDY67ZAl6wyOewYo-WGpzwFYXLXDvc-f8vYucRM3Hq_GSzvFQ4l0nRLLj_33vlCg8mB1CEw_LudadzticAir3Ux3bnpno9yndUZR6w',
  e: 'AQAB',
};

module.exports.privateJWK = privateJWK;
module.exports.publicJWK = publicJWK;
module.exports.privatePEM = privatePEM;
module.exports.publicPEM = publicPEM;
