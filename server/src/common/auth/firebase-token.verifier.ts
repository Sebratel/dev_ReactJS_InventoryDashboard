import { createRemoteJWKSet, errors, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { logger } from '../helpers/logger.helper.js';

/**
 * Validação do ID token do Firebase Authentication (login com Google pelo
 * projeto Firebase do InventoryDashboard). O token é um JWT assinado pelo
 * Google; a conferência é local, com as chaves públicas do Firebase:
 *
 *   - assinatura RS256 com uma das chaves de `securetoken@system.gserviceaccount.com`;
 *   - `iss` = https://securetoken.google.com/<projeto> e `aud` = <projeto>: token
 *     de OUTRO projeto Firebase não entra;
 *   - `exp`, `iat`, `auth_time` e `sub` presentes e coerentes;
 *   - entrou pelo Google (`firebase.sign_in_provider` = google.com), com e-mail
 *     verificado. O domínio (@sebratel.com.br) quem confere é o middleware.
 *
 * Não existe senha nossa em lugar nenhum. As chaves públicas ficam em cache
 * (o jose só busca de novo quando aparece um `kid` desconhecido ou o cache vence).
 */
export interface SignedInUser {
  email: string;
  name: string;
  picture: string | null;
}

const FIREBASE_KEYS_URL = new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
const CLOCK_TOLERANCE_S = 5;

let remoteKeys: JWTVerifyGetKey | null = null;
const firebaseKeys = (): JWTVerifyGetKey => {
  remoteKeys ??= createRemoteJWKSet(FIREBASE_KEYS_URL, {
    timeoutDuration: 10_000,
    cooldownDuration: 30_000,
    cacheMaxAge: 6 * 60 * 60_000,
  });
  return remoteKeys;
};

/** Erro de rotina (token vencido, assinatura ou claim errada) não vai para o log: é só um 401. */
function isRoutine(err: unknown): boolean {
  return err instanceof errors.JOSEError && !(err instanceof errors.JWKSTimeout);
}

/**
 * @param keys só para teste (chaves locais); em produção, as chaves públicas do Firebase.
 */
export async function verifyFirebaseIdToken(
  token: string,
  projectId: string,
  keys: JWTVerifyGetKey = firebaseKeys(),
): Promise<SignedInUser | null> {
  if (!projectId) return null;

  let claims: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(token, keys, {
      algorithms: ['RS256'],
      issuer: `https://securetoken.google.com/${projectId}`,
      audience: projectId,
      requiredClaims: ['exp', 'iat', 'sub', 'auth_time'],
      clockTolerance: CLOCK_TOLERANCE_S,
    });
    claims = payload;
  } catch (err) {
    if (!isRoutine(err)) {
      logger.warn('auth', `falha ao validar o token do Firebase: ${err instanceof Error ? err.message : String(err)}`);
    }
    return null;
  }

  const nowS = Date.now() / 1000;
  if (typeof claims.sub !== 'string' || !claims.sub) return null;
  if (typeof claims.auth_time !== 'number' || claims.auth_time > nowS + CLOCK_TOLERANCE_S) return null;

  const provider = (claims.firebase as { sign_in_provider?: unknown } | undefined)?.sign_in_provider;
  if (provider !== 'google.com') {
    logger.warn('auth', `token recusado: login pelo provedor '${String(provider ?? '-')}', só Google é aceito`);
    return null;
  }

  const email = typeof claims.email === 'string' ? claims.email : '';
  if (!email || claims.email_verified !== true) return null;

  return {
    email: email.toLowerCase(),
    name: typeof claims.name === 'string' && claims.name ? claims.name : email,
    picture: typeof claims.picture === 'string' ? claims.picture : null,
  };
}
