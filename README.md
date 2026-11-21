# DriveRadar

Painel de verificação cruzada de versões de drivers NVIDIA, AMD e Intel e atualizações Windows.

## Princípios de dados

- A versão candidata é descoberta em fonte primária oficial ou fonte técnica estruturada e confirmada em artefato ou página do fabricante.
- Publishers são deduplicados: duas URLs da mesma organização contam uma vez.
- Corroborações de versão exigem correspondência exata com limites de versão e contexto do fabricante, preservando o link direto da matéria ou nota oficial.
- Conflitos externos detectam versões mais recentes reportadas por publicações confiáveis (ex.: hotfixes recentes ainda não promovidos a WHQL).
- Comunidades não participam do score de confiança.
- Ausência de relatos nunca é convertida em “estável”. Sem telemetria verificável, a estabilidade é `Indeterminado`.
- Falhas de coleta ficam expostas como `stale` ou `unavailable`; o último valor válido é preservado.

## Score de confiança

- 72 pontos: confirmação por fabricante ou autoridade.
- +8 pontos por publisher independente concordante, limitado a 24.
- -20 pontos por valor conflitante.
- -20 pontos quando apenas o último valor persistido está disponível.
- Limite de 98 para evitar certeza absoluta.

O score confirma versão e data. Não prevê estabilidade numa configuração específica de hardware.

## Histórico e alertas

- Até 24 versões primariamente verificadas são preservadas por fabricante.
- Cada item do histórico expõe versão, canal/build, lançamento, data de verificação, snapshot do Crossover, notas oficiais estruturadas (destaques, correções e problemas conhecidos), resumo técnico da IA e links rastreáveis.
- Itens sem resumo técnico são enriquecidos automaticamente em segundo plano e sob demanda ao abrir os detalhes.
- O botão **Configurar alertas** solicita permissão do navegador e avisa sobre novos alertas relevantes encontrados nas atualizações periódicas enquanto o site estiver aberto.
- O service worker já aceita eventos Web Push para futura integração com um provedor de push.

## Crossover e pool de IAs

O crossover é determinístico: confirma versão e data pela fonte primária, concordância entre publishers, conflitos e idade do dado. Ele permanece disponível mesmo se todas as IAs falharem.

Insights textuais e resumos técnicos do histórico usam um pool com failover:

1. Google Gemini API (`GEMINI_API_KEY_FILE`, padrão `/run/secrets/gemini_api_key`);
2. modelos gratuitos disponíveis no OpenCode Zen (fallback opcional);
3. NVIDIA NIM (fallback opcional);
4. última análise validada persistida quando todos os providers estão temporariamente indisponíveis.

Respostas são aceitas somente em JSON, precisam cobrir os quatro itens e repetir exatamente as versões coletadas. Citações só podem apontar para IDs existentes no registro de evidências do backend.

## Publicidade

Google AdSense Auto Ads está configurado para `ca-pub-7513394193260475`. O gateway publica o registro obrigatório em `/ads.txt`; CSP permite apenas os endpoints Google necessários e recursos do próprio site.

## Fontes

O registro em `sources.py` contém mais de 55 fontes de fabricantes, autoridades, equipes de pesquisa e publicações técnicas. Cada auditoria publica quantas estavam acessíveis e o estado individual de cada uma.

## Execução

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8512/driveradar/health
```

Variáveis opcionais:

- `CACHE_TTL_SECONDS`: intervalo de coleta; padrão 3600.
- `API_SECRET_KEY`: habilita `/api/data` no serviço interno da porta 8513. Sem valor, o endpoint retorna 503.
- `API_ALLOWED_ORIGINS`: origens CORS da API interna.
- `APP_UID` e `APP_GID`: IDs usados pelo usuário não privilegiado do container.
- `GEMINI_API_KEY_FILE`: secret do Google Gemini; padrão `/run/secrets/gemini_api_key`.
- `GEMINI_MODELS`: ordem dos modelos Gemini separados por vírgulas.
- `OPENCODE_ZEN_MODELS`: ordem do pool gratuito Zen, separada por vírgulas.
- `OPENCODE_ZEN_API_KEY_FILE`: secret opcional do Zen; padrão `/run/secrets/opencode_zen_api_key`.
- `NVIDIA_API_KEY_FILE`: secret opcional do fallback NIM; padrão `/run/secrets/nvidia_api_key`.

## Aplicativo Desktop para Windows

O diretório `desktop/` contém o aplicativo Electron minimalista para Windows 10/11:

- **Bandeja do sistema (System Tray)**: fechamento ou minimização discreta para a bandeja, com indicador visual de novos alertas e início automático opcional com o Windows (`--hidden`).
- **Notificações nativas do Windows**: avisos para novas versões de drivers/Windows, conflitos de hotfix e alertas de segurança filtrados por fabricante, severidade e horário silencioso.
- **Atualizações automáticas**: alimentadas via `electron-updater` apontando para `https://optlabs.com.br/driveradar/updates/` (artefatos montados em `./releases:/app/releases:ro`).
- **Build e Release**: a workflow [.github/workflows/release-desktop.yml](.github/workflows/release-desktop.yml) compila `DriveRadar-Setup-*.exe`, `.blockmap`, `latest.yml` e `DriveRadar-Portable-*.exe` em `windows-latest` ao publicar uma tag `v*`.

## Testes

```bash
python -m unittest discover -s tests -v
node --check static/js/app.js
docker compose config -q
```
