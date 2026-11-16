/**
 * Login com Google pelo Firebase Authentication (projeto Firebase do
 * InventoryDashboard). O front abre o popup do Google pelo SDK do Firebase e
 * manda o ID token do Firebase em cada requisição; o servidor confere a
 * assinatura, o projeto, o provedor (Google) e o domínio. Não existe senha nossa.
 *
 * O SDK guarda a sessão no IndexedDB do navegador (sobrevive ao F5) e renova o
 * ID token (~1 h de vida) sozinho: `getIdToken()` devolve o atual ou um novo.
 * A CSP do servidor é o que protege contra script injetado lê-lo.
 *
 * Só os pacotes do login (`@firebase/app` e `@firebase/auth`), não o `firebase`
 * completo: o Firestore dele traz `@grpc/grpc-js`, com alertas de segurança.
 * O SDK é carregado sob demanda (import dinâmico): fica num pedaço próprio do
 * bundle, fora do carregamento inicial da tela.
 */
import type { Auth } from '@firebase/auth';
import type { FirebasePublicConfig } from './types';

export type SessionEndReason = 'EXPIRED' | 'LOGOUT';

/** chave da versão anterior do login (Google Identity Services): só é apagada */
const LEGACY_STORAGE_KEY = 'inventory-dashboard.auth';

let auth: Auth | null = null;
let initializing: Promise<Auth> | null = null;
let renewing: Promise<string> | null = null;
const sessionEndListeners = new Set<(reason: SessionEndReason) => void>();

function forgetLegacyToken(): void {
  try {
    window.localStorage.removeItem(LEGACY_STORAGE_KEY);
  } catch {
    // storage bloqueado: nada a limpar
  }
}

/**
 * Inicializa o Firebase com a configuração pública que o servidor entrega
 * (`/auth/config`) e espera o SDK restaurar a sessão salva, se houver.
 */
export function initAuth(config: FirebasePublicConfig): Promise<Auth> {
  if (auth) return Promise.resolve(auth);
  initializing ??= (async () => {
    forgetLegacyToken();
    const [{ initializeApp }, { getAuth }] = await Promise.all([import('@firebase/app'), import('@firebase/auth')]);
    const app = initializeApp({ apiKey: config.apiKey, authDomain: config.authDomain, projectId: config.projectId });
    const instance = getAuth(app);
    await instance.authStateReady();
    auth = instance;
    return instance;
  })().catch((err: unknown) => {
    initializing = null;
    throw err instanceof Error ? err : new Error('Falha ao carregar o login do Google.');
  });
  return initializing;
}

/** Há sessão salva (alguém já entrou neste navegador e não saiu). */
export const hasSession = (): boolean => Boolean(auth?.currentUser);

/** ID token atual (o SDK renova sozinho perto do vencimento); null sem sessão. */
export async function getIdToken(): Promise<string | null> {
  const user = auth?.currentUser;
  if (!user) return null;
  try {
    return await user.getIdToken();
  } catch {
    return null;
  }
}

const FRIENDLY_ERRORS: Record<string, string> = {
  'auth/popup-closed-by-user': 'A janela do Google foi fechada antes de concluir.',
  'auth/cancelled-popup-request': 'A janela do Google foi fechada antes de concluir.',
  'auth/user-cancelled': 'A janela do Google foi fechada antes de concluir.',
  'auth/popup-blocked': 'O navegador bloqueou a janela do Google. Libere pop-ups para este site e tente de novo.',
  'auth/unauthorized-domain': 'Este endereço não está liberado no login (Firebase: domínios autorizados). Fale com o suporte.',
  'auth/operation-not-allowed': 'O login com Google não está ativado no projeto Firebase. Fale com o suporte.',
  'auth/network-request-failed': 'Falha de rede ao falar com o Google. Tente de novo.',
  'auth/too-many-requests': 'Muitas tentativas seguidas. Aguarde um pouco e tente de novo.',
};

function friendly(err: unknown): Error {
  const code = typeof err === 'object' && err && 'code' in err ? String((err as { code: unknown }).code) : '';
  return new Error(FRIENDLY_ERRORS[code] ?? 'Não foi possível entrar com o Google.');
}

/**
 * Abre o popup do Google. `hd` sugere ao Google mostrar só contas do domínio —
 * é conveniência: quem barra outro domínio de verdade é o servidor.
 */
export async function signInWithGoogle(allowedDomain: string): Promise<void> {
  if (!auth) throw new Error('Login não inicializado.');
  const { GoogleAuthProvider, signInWithPopup } = await import('@firebase/auth');
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account', ...(allowedDomain ? { hd: allowedDomain } : {}) });
  try {
    await signInWithPopup(auth, provider);
  } catch (err) {
    throw friendly(err);
  }
}

/** Força um ID token novo (usado no 401: o servidor pode ter recusado um token velho). */
export function renewIdToken(): Promise<string> {
  const user = auth?.currentUser;
  if (!user) return Promise.reject(new Error('Sem sessão.'));
  renewing ??= user.getIdToken(true).finally(() => {
    renewing = null;
  });
  return renewing;
}

export function endSession(reason: SessionEndReason): void {
  if (!auth?.currentUser && reason === 'EXPIRED') return;
  const instance = auth;
  if (instance) {
    void import('@firebase/auth').then(({ signOut }) => signOut(instance)).catch(() => undefined);
  }
  sessionEndListeners.forEach((listener) => listener(reason));
}

export function onSessionEnd(listener: (reason: SessionEndReason) => void): () => void {
  sessionEndListeners.add(listener);
  return () => sessionEndListeners.delete(listener);
}
