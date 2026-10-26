import { logger } from '@/lib/logger';

interface TokenResponse {
  access_token: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  [key: string]: unknown;
}

/**
 * Exchange/augment Casdoor OAuth tokens for a long-lived Stalwart API Key.
 *
 * Casdoor issues its own OAuth access tokens which expire quickly (1 hour) and are
 * not directly recognized by Stalwart Mail Server as JMAP bearer tokens.
 * This bridge inspects the JWT payload claims (email, username, etc.), resolves
 * the corresponding account in Stalwart Mail Server, and mints an official Stalwart API
 * key valid for 30 days so webmail sessions remain active without sudden expirations.
 */
export async function mintStalwartToken<T extends TokenResponse>(tokens: T): Promise<T> {
  try {
    const idJwt = tokens.id_token || tokens.access_token;
    if (!idJwt || typeof idJwt !== 'string') return tokens;

    const parts = idJwt.split('.');
    if (parts.length < 2) return tokens;

    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
    logger.info('[sso-bridge] Payload claims:', {
      email: payload.email,
      name: payload.name,
      preferred_username: payload.preferred_username,
      sub: payload.sub,
    });

    const candidates: string[] = [];
    const addCandidate = (c: unknown) => {
      if (!c || typeof c !== 'string') return;
      const trimmed = c.trim().toLowerCase();
      if (trimmed && !candidates.includes(trimmed)) candidates.push(trimmed);
    };

    if (payload.email && typeof payload.email === 'string') {
      addCandidate(payload.email);
      const localPart = payload.email.split('@')[0];
      addCandidate(`${localPart}@tirtapatriot.id`);
      addCandidate(`${localPart}@tirtapatriot.co.id`);
      addCandidate(localPart);
    }
    if (payload.name && typeof payload.name === 'string') {
      const cleanName = payload.name.replace(/[^a-zA-Z0-9._-]/g, '');
      addCandidate(`${cleanName}@tirtapatriot.id`);
      addCandidate(`${cleanName}@tirtapatriot.co.id`);
      addCandidate(cleanName);
    }
    if (payload.preferred_username && typeof payload.preferred_username === 'string') {
      const cleanU = payload.preferred_username.replace(/[^a-zA-Z0-9._-]/g, '');
      addCandidate(`${cleanU}@tirtapatriot.id`);
      addCandidate(`${cleanU}@tirtapatriot.co.id`);
      addCandidate(cleanU);
    }
    if (payload.sub && typeof payload.sub === 'string') {
      addCandidate(`${payload.sub}@tirtapatriot.id`);
      addCandidate(payload.sub);
    }

    let matchedAccountId: string | null = null;
    let matchedUsername: string | null = null;
    const adminUser = process.env.STALWART_ADMIN_USER || 'patriot';
    const adminPass = process.env.STALWART_ADMIN_PASSWORD || 'Yzg2NDE5ODA2NGYwYzU3Mwo';
    const stalwartInternalUrl = process.env.STALWART_INTERNAL_URL || 'http://stalwart:8080';

    for (const c of candidates) {
      try {
        const auth = Buffer.from(`${c}%${adminUser}:${adminPass}`).toString('base64');
        const r = await fetch(`${stalwartInternalUrl}/jmap/session`, {
          headers: { Authorization: `Basic ${auth}` },
        });
        if (r.ok) {
          const data = await r.json();
          const accId = data.primaryAccounts && data.primaryAccounts['urn:ietf:params:jmap:mail'];
          if (accId) {
            matchedAccountId = accId;
            matchedUsername = data.username;
            logger.info(`[sso-bridge] Matched ${c} -> ${matchedUsername} (acc: ${accId})`);
            break;
          }
        }
      } catch {
        // Continue searching next candidate
      }
    }

    if (matchedAccountId) {
      const adminAuth = Buffer.from(`${adminUser}:${adminPass}`).toString('base64');
      const qRes = await fetch(`${stalwartInternalUrl}/jmap/`, {
        method: 'POST',
        headers: { Authorization: `Basic ${adminAuth}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          using: ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'],
          methodCalls: [['x:ApiKey/get', { accountId: matchedAccountId, ids: null }, '0']],
        }),
      });
      const qData = await qRes.json();
      const oldKeys = ((qData.methodResponses?.[0]?.[1]?.list || []) as Array<{ id: string; description?: string }>)
        .filter((k) => k.description && k.description.includes('SSO'))
        .map((k) => k.id);

      const setRes = await fetch(`${stalwartInternalUrl}/jmap/`, {
        method: 'POST',
        headers: { Authorization: `Basic ${adminAuth}`, 'Content-Type': 'application/json' },
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
        logger.info(`[sso-bridge] Minted Stalwart API key for ${matchedUsername}`);
        tokens.access_token = secret;
        tokens.expires_in = 2592000; // 30 days
      }
    } else {
      logger.warn(`[sso-bridge] No Stalwart account match found for candidates: ${candidates.join(', ')}`);
    }
  } catch (err) {
    logger.error('[sso-bridge] Token minting error:', {
      error: err instanceof Error ? err.message : 'Unknown error',
    });
  }
  return tokens;
}
