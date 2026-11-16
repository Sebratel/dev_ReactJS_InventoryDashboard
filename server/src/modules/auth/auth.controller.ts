import { Router } from 'express';
import { requireAuth } from '../../common/auth/auth.middleware.js';
import { sendOk } from '../../common/http/api-response.js';
import { appConfig } from '../../config/env.config.js';
import { recordLogin } from '../users/user.service.js';

export const authRouter = Router();

/**
 * Configuração pública do login: a configuração web do Firebase não é segredo
 * (é a mesma que qualquer app Firebase embute no navegador). Vem do servidor, e
 * não do build, para a mesma imagem servir staging e produção.
 */
authRouter.get('/config', (_req, res) => {
  sendOk(res, {
    enabled: appConfig.auth.enabled,
    allowedDomain: appConfig.auth.allowedDomain,
    firebase: appConfig.auth.enabled ? appConfig.auth.firebase : null,
  });
});

/** Quem está logado e a permissão (Padrão, Edição ou Admin). */
authRouter.get('/me', requireAuth(), (req, res) => {
  sendOk(res, req.user);
});

/**
 * O front avisa logo depois do clique em "Entrar com Google": é o "último
 * login" da tela de Administração (abrir o painel com a sessão ainda válida
 * não conta como login).
 */
authRouter.post('/logins', requireAuth(), (req, res) => {
  if (appConfig.auth.enabled) recordLogin(req.user!.email);
  res.status(204).end();
});
