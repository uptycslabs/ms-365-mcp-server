import logger from './logger.js';
import type AuthManager from './auth.js';

const GUID_LEN = 36;

export function isGuid(value: string): boolean {
  return value.length === GUID_LEN && (value.match(/-/g) || []).length === 4;
}

export function escapeOData(value: string): string {
  return value.replace(/'/g, "''");
}

export interface DataverseGetParams {
  [key: string]: string | number | boolean | undefined;
}

/**
 * Thin Dataverse Web API (OData v4) client. Auth comes from AuthManager —
 * we ask for a token scoped to `<orgUrl>/.default` on each request (MSAL caches it).
 *
 * Mirrors the shape of the Python D365Client in the reference implementation.
 */
export class DataverseClient {
  private readonly orgUrl: string;
  private readonly apiBase: string;
  private readonly scope: string;

  constructor(
    private readonly auth: AuthManager,
    orgUrl: string
  ) {
    this.orgUrl = orgUrl.replace(/\/$/, '');
    this.apiBase = `${this.orgUrl}/api/data/v9.2`;
    this.scope = `${this.orgUrl}/.default`;
  }

  getOrgUrl(): string {
    return this.orgUrl;
  }

  private async headers(prefer?: string): Promise<Record<string, string>> {
    const token = await this.auth.acquireTokenForScopes([this.scope]);
    const h: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
      'OData-MaxVersion': '4.0',
      'OData-Version': '4.0',
      'Content-Type': 'application/json; charset=utf-8',
    };
    if (prefer) {
      h.Prefer = prefer;
    }
    return h;
  }

  private buildUrl(path: string, params?: DataverseGetParams): string {
    const cleanPath = path.replace(/^\//, '');
    const url = new URL(`${this.apiBase}/${cleanPath}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null) continue;
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  async get<T = unknown>(path: string, params?: DataverseGetParams, prefer?: string): Promise<T> {
    const url = this.buildUrl(path, params);
    const res = await fetch(url, { method: 'GET', headers: await this.headers(prefer) });
    return (await this.handleResponse(res)) as T;
  }

  async post<T = unknown>(path: string, body: unknown, prefer?: string): Promise<T | null> {
    const url = this.buildUrl(path);
    const res = await fetch(url, {
      method: 'POST',
      headers: await this.headers(prefer),
      body: JSON.stringify(body),
    });
    if (res.status === 204) {
      await res.body?.cancel?.();
      this.assertOk(res, '');
      return null;
    }
    return (await this.handleResponse(res)) as T;
  }

  async patch(path: string, body: unknown): Promise<void> {
    const url = this.buildUrl(path);
    const res = await fetch(url, {
      method: 'PATCH',
      headers: await this.headers(),
      body: JSON.stringify(body),
    });
    if (res.status === 204) {
      await res.body?.cancel?.();
      this.assertOk(res, '');
      return;
    }
    await this.handleResponse(res);
  }

  private async handleResponse(res: Response): Promise<unknown> {
    const text = await res.text();
    this.assertOk(res, text);
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  private assertOk(res: Response, text: string): void {
    if (res.ok) return;
    let message = `${res.status}: ${text || res.statusText}`;
    try {
      const parsed = text ? JSON.parse(text) : null;
      const err = parsed?.error;
      if (err) {
        message = `${res.status} ${err.code ?? ''}: ${err.message ?? text}`.trim();
      }
    } catch {
      // not JSON; leave default message
    }
    logger.error(`[Dataverse] ${res.url} -> ${message}`);
    throw new Error(message);
  }

  /**
   * Resolve a queue identifier (GUID or display name) to its GUID.
   * Mirrors `_resolve_queue` in the reference Python server.
   */
  async resolveQueue(queueIdOrName: string): Promise<string> {
    if (isGuid(queueIdOrName)) {
      return queueIdOrName;
    }
    const res = await this.get<{ value?: Array<{ queueid: string; name: string }> }>('queues', {
      $select: 'queueid,name',
      $filter: `name eq '${escapeOData(queueIdOrName)}'`,
      $top: 1,
    });
    const items = res.value ?? [];
    if (items.length === 0) {
      throw new Error(`Queue '${queueIdOrName}' not found`);
    }
    return items[0].queueid;
  }

  /**
   * Resolve a case identifier (incident GUID or ticket number) to the incident GUID.
   * Mirrors `_resolve_case` in the reference Python server.
   */
  async resolveCase(caseIdOrTicket: string): Promise<string> {
    if (isGuid(caseIdOrTicket)) {
      return caseIdOrTicket;
    }
    const res = await this.get<{ value?: Array<{ incidentid: string; ticketnumber: string }> }>(
      'incidents',
      {
        $select: 'incidentid,ticketnumber',
        $filter: `ticketnumber eq '${escapeOData(caseIdOrTicket)}'`,
        $top: 1,
      }
    );
    const items = res.value ?? [];
    if (items.length === 0) {
      throw new Error(`Case with ticket number '${caseIdOrTicket}' not found`);
    }
    return items[0].incidentid;
  }
}
