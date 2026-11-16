import { Router } from 'express';
import { appConfig } from '../../config/env.config.js';
import { sendOk } from '../../common/http/api-response.js';
import { getModel } from '../../model/model.store.js';

/**
 * Verificação de vida para o healthcheck do Docker. Pública e sem detalhe de
 * fonte: quem não está logado não precisa saber qual banco falhou. Traz a
 * versão da aplicação (a do package.json), para conferir o que está no ar.
 */
export const healthRouter = Router();

healthRouter.get('/', (_req, res) => {
  const model = getModel();
  sendOk(res, { status: 'UP', version: appConfig.version, modelLoaded: model.version > 0 });
});
