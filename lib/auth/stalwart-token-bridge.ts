import { logger } from '@/lib/logger';

interface TokenResponse {
  access_token: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  [key: string]: unknown;
}

interface PrincipalRecord {
  id: string;
  type?: string;
  name?: string;
  email?: string;
  description?: string;
}

/**
 * Exchange / augment external OAuth tokens (e.g. Casdoor OIDC) for an official
 * Stalwart Mail Server JMAP API Key.
 *
 * This bridge operates completely dynamically:
 * 1. Inspects JWT claims (preferred_username, email, sub, name) without hardcoded domains.
 * 2. Queries the Stalwart JMAP Principal Directory (urn:ietf:params:jmap:principals)
 *    to find the matching internal account ID and primary identity.
 * 3. Falls back to impersonation probe against configured or auto-detected mail domains.
 * 4. Mints a long-lived Stalwart API Key (default 30 days) so webmail sessions stay active.
 */
export async function mintStalwartToken<T extends TokenResponse>(tokens: T): Promise<T> {
  const adminUser = process.env.STALWART_ADMIN_USER || 'admin';
  const adminPass = process.env.STALWART_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD;

  if (!adminPass) {
    logger.debug('[sso-bridge] STALWART_ADMIN_PASSWORD not set; skipping Stalwart API key minting');
    return tokens;
  }

  const idJwt = tokens.id_token || tokens.access_token;
  if (!idJwt || typeof idJwt !== 'string') return tokens;

  const parts = idJwt.split('.');
  if (parts.length < 2) return tokens;

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
  } catch {
    return tokens;
  }

  logger.info('[sso-bridge] Processing SSO token exchange for claims:', {
    email: payload.email,
    preferred_username: payload.preferred_username,
    name: payload.name,
    sub: payload.sub,
  });

  const serverUrl = (
    process.env.STALWART_INTERNAL_URL ||
    process.env.JMAP_SERVER_URL ||
    'http://stalwart:8080'
  ).replace(/\/+$/, '');

  const tokenTtl = parseInt(process.env.STALWART_TOKEN_TTL || '2592000', 10); // default: 30 days
  const adminAuth = Buffer.from(`${adminUser}:${adminPass}`).toString('base64');

  try {
    // 1. Fetch Stalwart JMAP session to discover apiUrl and capabilities
    const sessionRes = await fetch(`${serverUrl}/jmap/session`, {
      headers: { Authorization: `Basic ${adminAuth}` },
    });

    if (!sessionRes.ok) {
      logger.warn(`[sso-bridge] Stalwart session query failed: HTTP ${sessionRes.status}`);
      return tokens;
    }

    const sessionData = await sessionRes.json();
    const apiUrl = sessionData.apiUrl || `${serverUrl}/jmap/`;
    const principalsAccountId =
      sessionData.primaryAccounts?.['urn:ietf:params:jmap:principals'] ||
      Object.values(sessionData.primaryAccounts || {})[0];

    // 2. Extract search terms dynamically from JWT claims
    const searchTerms = new Set<string>();
    const addTerm = (raw: unknown) => {
      if (typeof raw !== 'string') return;
      const clean = raw.trim();
      if (clean.length > 0) searchTerms.add(clean);
    };

    addTerm(payload.preferred_username);
    if (typeof payload.email === 'string') {
      const email = payload.email.trim();
      addTerm(email);
      const atIndex = email.indexOf('@');
      if (atIndex > 0) {
        addTerm(email.substring(0, atIndex));
      }
    }
    addTerm(payload.sub);
    addTerm(payload.name);

    let matchedAccountId: string | null = null;
    let matchedUsername: string | null = null;

    // 3. Dynamic lookup via Stalwart Directory (Principal/query)
    if (principalsAccountId) {
      for (const term of searchTerms) {
        if (!term || term.length < 2) continue;
        try {
          const qRes = await fetch(apiUrl, {
            method: 'POST',
            headers: {
              Authorization: `Basic ${adminAuth}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:principals'],
              methodCalls: [
                ['Principal/query', { accountId: principalsAccountId, filter: { text: term }, limit: 5 }, '0'],
                ['Principal/get', { accountId: principalsAccountId, '#ids': { resultOf: '0', name: 'Principal/query', path: '/ids' } }, '1'],
              ],
            }),
          });

          if (!qRes.ok) continue;

          const qData = await qRes.json();
          const list = (qData.methodResponses?.[1]?.[1]?.list || []) as PrincipalRecord[];
          if (list.length > 0) {
            const candidate = list.find((p) => p.type === 'individual') || list[0];
            matchedAccountId = candidate.id;
            matchedUsername = candidate.email || candidate.name || candidate.id;
            logger.info(`[sso-bridge] Matched Stalwart principal via term "${term}" -> ${matchedUsername} (id: ${matchedAccountId})`);
            break;
          }
        } catch {
          // Continue trying next term
        }
      }
    }

    // 4. Fallback lookup via domain candidates probe
    if (!matchedAccountId) {
      const domains = new Set<string>();
      if (process.env.STALWART_DOMAINS) {
        process.env.STALWART_DOMAINS.split(',').forEach((d) => {
          const trimmed = d.trim().toLowerCase();
          if (trimmed) domains.add(trimmed);
        });
      }
      try {
        const jmapUrlObj = new URL(process.env.JMAP_SERVER_URL || serverUrl);
        const hostParts = jmapUrlObj.hostname.split('.');
        if (hostParts.length >= 2) {
          domains.add(hostParts.slice(-2).join('.'));
          domains.add(jmapUrlObj.hostname);
        }
      } catch {
        // ignore URL parsing error
      }

      const candidateUsernames: string[] = [];
      for (const term of searchTerms) {
        candidateUsernames.push(term);
        if (!term.includes('@')) {
          for (const d of domains) {
            candidateUsernames.push(`${term}@${d}`);
          }
        }
      }

      for (const candidate of candidateUsernames) {
        try {
          const auth = Buffer.from(`${candidate}%${adminUser}:${adminPass}`).toString('base64');
          const r = await fetch(`${serverUrl}/jmap/session`, {
            headers: { Authorization: `Basic ${auth}` },
          });
          if (r.ok) {
            const data = await r.json();
            const accId = data.primaryAccounts && data.primaryAccounts['urn:ietf:params:jmap:mail'];
            if (accId) {
              matchedAccountId = accId;
              matchedUsername = data.username || candidate;
              logger.info(`[sso-bridge] Matched account via candidate "${candidate}" -> ${matchedUsername} (acc: ${accId})`);
              break;
            }
          }
        } catch {
          // ignore individual candidate probe failure
        }
      }
    }

    // 5. Mint official Stalwart API key for the resolved account
    if (matchedAccountId) {
      const qRes = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${adminAuth}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          using: ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'],
          methodCalls: [['x:ApiKey/get', { accountId: matchedAccountId, ids: null }, '0']],
        }),
      });

      const qData = await qRes.json();
      const oldKeys = ((qData.methodResponses?.[0]?.[1]?.list || []) as Array<{ id: string; description?: string }>)
        .filter((k) => k.description && k.description.includes('SSO'))
        .map((k) => k.id);

      const setRes = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${adminAuth}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          using: ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'],
          methodCalls: [
            [
              'x:ApiKey/set',
              {
                accountId: matchedAccountId,
                destroy: oldKeys,
                create: { sso: { description: 'Bulwark SSO Key' } },
              },
              '0',
            ],
          ],
        }),
      });

      const setData = await setRes.json();
      const secret = setData.methodResponses?.[0]?.[1]?.created?.sso?.secret;
      if (secret) {
        logger.info(`[sso-bridge] Successfully minted Stalwart API key for ${matchedUsername} (valid for ${tokenTtl}s)`);
        tokens.access_token = secret;
        tokens.expires_in = tokenTtl;
      }
    } else {
      logger.warn('[sso-bridge] No matching Stalwart account found for claims:', [...searchTerms]);
    }
  } catch (err) {
    logger.error('[sso-bridge] Token minting error:', {
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  }

  return tokens;
}
