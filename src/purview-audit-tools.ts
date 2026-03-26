import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import GraphClient from './graph-client.js';
import logger from './logger.js';

const POLL_INTERVAL_MS = 10_000;
const MAX_POLLS = 60; // 10 minutes max

const BETA = { apiVersion: 'beta' } as const;

type AuditLogQueryStatus = 'notStarted' | 'running' | 'succeeded' | 'failed' | 'cancelled' | 'unknownFutureValue';

interface AuditLogQuery {
  id: string;
  status: AuditLogQueryStatus;
  displayName?: string;
  filterStartDateTime?: string;
  filterEndDateTime?: string;
  [key: string]: unknown;
}

interface AuditLogRecordsPage {
  value?: unknown[];
  '@odata.nextLink'?: string;
  [key: string]: unknown;
}

type McpToolResult = {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
};

function errorResult(message: string, extra?: Record<string, unknown>): McpToolResult {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify({ error: message, ...extra }) }],
    isError: true,
  };
}

// Extract path + query string from a beta nextLink URL so it can be passed directly to makeRequest
function extractPathAndQuery(nextLink: string): string {
  const url = new URL(nextLink);
  return url.pathname.replace('/beta', '') + url.search;
}

async function fetchRecordsPage(
  graphClient: GraphClient,
  path: string
): Promise<{ page: AuditLogRecordsPage; error?: never } | { page?: never; error: McpToolResult }> {
  try {
    const page = (await graphClient.makeRequest(path, {
      method: 'GET',
      ...BETA,
    })) as AuditLogRecordsPage;
    return { page };
  } catch (error) {
    return { error: errorResult(`Failed to fetch audit log records: ${(error as Error).message}`) };
  }
}

export function registerPurviewAuditTools(server: McpServer, graphClient: GraphClient): void {
  server.tool(
    'search-purview-audit-logs',
    `Search Microsoft Purview audit logs.

This tool operates in two modes depending on the parameters provided:

**Mode 1 — New search** (provide filterStartDateTime + filterEndDateTime):
  1. Creates an audit log search query via the Microsoft Graph beta API
  2. Polls every 10 seconds until the query completes (up to 10 minutes)
  3. Returns the first page of records plus a queryId and nextLink

**Mode 2 — Fetch existing query** (provide queryId):
  - Skips create and polling; directly fetches records for an already-completed query
  - Pass nextLink from a previous response to retrieve subsequent pages
  - Use this mode to paginate or to re-access records from a prior query

The response always includes queryId, records, hasMore, and nextLink (when more pages exist).
Pass the nextLink back in a subsequent call to fetch the next page.

Requires AuditLogsQuery.Read.All permission and org-mode (--org-mode flag).
Uses the /beta API endpoint as this feature is not available in v1.0.`,
    {
      // ── Mode 1: new search ──────────────────────────────────────────────
      filterStartDateTime: z
        .string()
        .optional()
        .describe('(Mode 1) Start of the search time range (ISO 8601, e.g. 2024-01-01T00:00:00Z). Required when queryId is not provided.'),
      filterEndDateTime: z
        .string()
        .optional()
        .describe('(Mode 1) End of the search time range (ISO 8601, e.g. 2024-01-02T00:00:00Z). Required when queryId is not provided.'),
      displayName: z
        .string()
        .optional()
        .describe('(Mode 1) Optional display name for this query'),
      recordTypeFilters: z
        .array(z.string())
        .optional()
        .describe(
          '(Mode 1) Filter by audit record types, e.g. ["sharePoint", "azureActiveDirectory", "microsoftTeams"]. ' +
          'See Microsoft docs for the full list of supported values.'
        ),
      keywordFilter: z
        .string()
        .optional()
        .describe('(Mode 1) Free-text keyword search across non-indexed audit properties'),
      serviceFilter: z
        .string()
        .optional()
        .describe('(Mode 1) Filter by Microsoft service workload name (e.g. "Exchange", "SharePoint")'),
      operationFilters: z
        .array(z.string())
        .optional()
        .describe('(Mode 1) Filter by operation names (e.g. ["FileAccessed", "UserLoggedIn"])'),
      userPrincipalNameFilters: z
        .array(z.string())
        .optional()
        .describe('(Mode 1) Filter by user principal names (e.g. ["user@contoso.com"])'),
      ipAddressFilters: z
        .array(z.string())
        .optional()
        .describe('(Mode 1) Filter by client IP addresses'),
      objectIdFilters: z
        .array(z.string())
        .optional()
        .describe('(Mode 1) Filter by object IDs such as file or folder paths'),
      administrativeUnitIdFilters: z
        .array(z.string())
        .optional()
        .describe('(Mode 1) Filter by administrative unit IDs'),
      // ── Mode 2: fetch existing query ────────────────────────────────────
      queryId: z
        .string()
        .optional()
        .describe('(Mode 2) ID of a previously completed audit log query. When provided, skips create and polling.'),
      nextLink: z
        .string()
        .optional()
        .describe('(Mode 2) Pagination cursor from a previous response. When provided with queryId, fetches the next page of results.'),
    },
    async (params) => {
      // ── Mode 2: fetch records for an existing queryId ────────────────────
      if (params.queryId) {
        const { queryId, nextLink } = params;
        const path = nextLink
          ? extractPathAndQuery(nextLink)
          : `/security/auditLog/queries/${queryId}/records`;

        logger.info(`[Purview] Mode 2 — fetching records for queryId=${queryId}, hasNextLink=${nextLink != null}`);

        const result = await fetchRecordsPage(graphClient, path);
        if (result.error) {
          return result.error;
        }

        const { page } = result;
        const records = page.value ?? [];
        const responseNextLink = page['@odata.nextLink'] ?? null;

        logger.info(`[Purview] Page returned ${records.length} record(s). hasMore=${responseNextLink !== null}`);

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(
                {
                  queryId,
                  records,
                  hasMore: responseNextLink !== null,
                  nextLink: responseNextLink,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      // ── Mode 1: create a new query ───────────────────────────────────────
      if (!params.filterStartDateTime || !params.filterEndDateTime) {
        return errorResult(
          'Either queryId (to fetch an existing query) or both filterStartDateTime and filterEndDateTime (to start a new search) must be provided.'
        );
      }

      const body: Record<string, unknown> = {
        '@odata.type': '#microsoft.graph.security.auditLogQuery',
        filterStartDateTime: params.filterStartDateTime,
        filterEndDateTime: params.filterEndDateTime,
      };

      if (params.displayName) body.displayName = params.displayName;
      if (params.recordTypeFilters?.length) body.recordTypeFilters = params.recordTypeFilters;
      if (params.keywordFilter) body.keywordFilter = params.keywordFilter;
      if (params.serviceFilter) body.serviceFilter = params.serviceFilter;
      if (params.operationFilters?.length) body.operationFilters = params.operationFilters;
      if (params.userPrincipalNameFilters?.length) body.userPrincipalNameFilters = params.userPrincipalNameFilters;
      if (params.ipAddressFilters?.length) body.ipAddressFilters = params.ipAddressFilters;
      if (params.objectIdFilters?.length) body.objectIdFilters = params.objectIdFilters;
      if (params.administrativeUnitIdFilters?.length) body.administrativeUnitIdFilters = params.administrativeUnitIdFilters;

      logger.info('[Purview] Mode 1 — creating audit log query...');

      let query: AuditLogQuery;
      try {
        query = (await graphClient.makeRequest('/security/auditLog/queries', {
          method: 'POST',
          body: JSON.stringify(body),
          ...BETA,
        })) as AuditLogQuery;
      } catch (error) {
        logger.error(`[Purview] Failed to create audit log query: ${(error as Error).message}`);
        return errorResult(`Failed to create audit log query: ${(error as Error).message}`);
      }

      const queryId = query.id;
      if (!queryId) {
        return errorResult('No query ID returned from create call', { details: query });
      }

      logger.info(`[Purview] Query created: id=${queryId}, initial status=${query.status}`);

      // ── Poll until terminal status ───────────────────────────────────────
      let status: AuditLogQueryStatus = query.status;
      let polls = 0;

      while (status === 'notStarted' || status === 'running') {
        if (polls >= MAX_POLLS) {
          return errorResult('Timed out waiting for audit log query to complete', {
            queryId,
            status,
            elapsedSeconds: polls * (POLL_INTERVAL_MS / 1000),
          });
        }

        await new Promise<void>((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        polls++;

        logger.info(`[Purview] Polling status (attempt ${polls})...`);

        try {
          const statusData = (await graphClient.makeRequest(
            `/security/auditLog/queries/${queryId}`,
            { method: 'GET', ...BETA }
          )) as AuditLogQuery;
          status = statusData.status;
        } catch (error) {
          logger.error(`[Purview] Failed to poll query status: ${(error as Error).message}`);
          return errorResult(`Failed to poll audit log query status: ${(error as Error).message}`, { queryId });
        }

        logger.info(`[Purview] Query status: ${status}`);
      }

      if (status === 'failed' || status === 'cancelled') {
        return errorResult(`Audit log query ${status}`, { queryId, status });
      }

      // ── Fetch first page of records ──────────────────────────────────────
      logger.info(`[Purview] Query succeeded. Fetching first page of records...`);

      const result = await fetchRecordsPage(
        graphClient,
        `/security/auditLog/queries/${queryId}/records`
      );
      if (result.error) {
        return result.error;
      }

      const { page } = result;
      const records = page.value ?? [];
      const nextLink = page['@odata.nextLink'] ?? null;

      logger.info(`[Purview] First page: ${records.length} record(s). hasMore=${nextLink !== null}`);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                queryId,
                status,
                records,
                hasMore: nextLink !== null,
                nextLink,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );
}
