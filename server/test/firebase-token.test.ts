import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from 'jose';
import { verifyFirebaseIdToken } from '../src/common/auth/firebase-token.verifier.js';

const PROJECT = 'inventory-dashboard-teste';
const KID = 'chave-teste';

type Key = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let signingKey: Key;
let otherKey: Key;
let keys: JWTVerifyGetKey;

/** ID token como o Firebase emite para um login com Google (claims sobrescrevíveis). */
async function idToken(overrides: Record<string, unknown> = {}, options: { key?: Key; iss?: string; aud?: string; expSeconds?: number } = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email: 'fulano@sebratel.com.br',
    email_verified: true,
    name: 'Fulano de Tal',
    picture: 'https://lh3.googleusercontent.com/foto',
    auth_time: now - 60,
    firebase: { sign_in_provider: 'google.com', identities: {} },
    ...overrides,
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuer(options.iss ?? `https://securetoken.google.com/${PROJECT}`)
    .setAudience(options.aud ?? PROJECT)
    .setSubject('uid-123')
    .setIssuedAt(now - 60)
    .setExpirationTime(now + (options.expSeconds ?? 3600))
    .sign(options.key ?? signingKey);
}

describe('validação do ID token do Firebase', () => {
  before(async () => {
    const pair = await generateKeyPair('RS256');
    signingKey = pair.privateKey;
    otherKey = (await generateKeyPair('RS256')).privateKey;
    const jwk = { ...(await exportJWK(pair.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };
    keys = createLocalJWKSet({ keys: [jwk] });
  });

  it('aceita login com Google do nosso projeto e devolve e-mail, nome e foto', async () => {
    const user = await verifyFirebaseIdToken(await idToken({ email: 'Fulano@Sebratel.com.br' }), PROJECT, keys);
    assert.deepEqual(user, { email: 'fulano@sebratel.com.br', name: 'Fulano de Tal', picture: 'https://lh3.googleusercontent.com/foto' });
  });

  it('recusa token de OUTRO projeto Firebase (aud e iss diferentes)', async () => {
    const token = await idToken({}, { aud: 'outro-projeto', iss: 'https://securetoken.google.com/outro-projeto' });
    assert.equal(await verifyFirebaseIdToken(token, PROJECT, keys), null);
  });

  it('recusa emissor errado mesmo com a audiência certa', async () => {
    const token = await idToken({}, { iss: 'https://accounts.google.com' });
    assert.equal(await verifyFirebaseIdToken(token, PROJECT, keys), null);
  });

  it('recusa assinatura de chave que não é do Firebase', async () => {
    assert.equal(await verifyFirebaseIdToken(await idToken({}, { key: otherKey }), PROJECT, keys), null);
  });

  it('recusa token vencido', async () => {
    assert.equal(await verifyFirebaseIdToken(await idToken({}, { expSeconds: -120 }), PROJECT, keys), null);
  });

  it('recusa login que não foi pelo Google (ex.: e-mail e senha)', async () => {
    const token = await idToken({ firebase: { sign_in_provider: 'password' } });
    assert.equal(await verifyFirebaseIdToken(token, PROJECT, keys), null);
  });

  it('recusa e-mail não verificado', async () => {
    assert.equal(await verifyFirebaseIdToken(await idToken({ email_verified: false }), PROJECT, keys), null);
  });

  it('recusa login com auth_time no futuro', async () => {
    const token = await idToken({ auth_time: Math.floor(Date.now() / 1000) + 3600 });
    assert.equal(await verifyFirebaseIdToken(token, PROJECT, keys), null);
  });

  it('recusa tudo se o servidor estiver sem FIREBASE_PROJECT_ID', async () => {
    assert.equal(await verifyFirebaseIdToken(await idToken(), '', keys), null);
  });

  it('recusa texto que não é JWT', async () => {
    assert.equal(await verifyFirebaseIdToken('nao-e-um-jwt-de-verdade', PROJECT, keys), null);
  });
});
