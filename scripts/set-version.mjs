// Troca a versão da aplicação em todos os lugares de uma vez (padrão de deploy da Sebratel):
// package.json da raiz, do servidor e do front, os package-lock.json e o valor padrão
// ${APP_VERSION:-X.Y.Z} do docker-compose.portainer.yml (tag da imagem no Portainer).
//
// Uso: npm run version:set -- 1.2.3
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  console.error('Informe a versão no formato X.Y.Z (ex.: npm run version:set -- 1.2.3).');
  process.exit(1);
}

const editJson = (file, change) => {
  const path = join(ROOT, file);
  const data = JSON.parse(readFileSync(path, 'utf8'));
  change(data);
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`${file}: ${version}`);
};

for (const file of ['package.json', 'server/package.json', 'web/package.json']) {
  editJson(file, (pkg) => { pkg.version = version; });
}
for (const file of ['server/package-lock.json', 'web/package-lock.json']) {
  editJson(file, (lock) => {
    lock.version = version;
    if (lock.packages?.['']) lock.packages[''].version = version;
  });
}

const compose = join(ROOT, 'docker-compose.portainer.yml');
const text = readFileSync(compose, 'utf8');
const updated = text.replace(/\$\{APP_VERSION:-\d+\.\d+\.\d+\}/g, `\${APP_VERSION:-${version}}`);
if (updated === text && !text.includes(`\${APP_VERSION:-${version}}`)) {
  console.error('docker-compose.portainer.yml: não achei ${APP_VERSION:-X.Y.Z} para trocar.');
  process.exit(1);
}
writeFileSync(compose, updated);
console.log(`docker-compose.portainer.yml: ${version}`);
