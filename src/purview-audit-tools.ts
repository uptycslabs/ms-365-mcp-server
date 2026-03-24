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

function extractPathAndQuery(nextLink: string): string {
  const url = new URL(nextLink);
  return url.pathname.replace('/beta', '') + url.search;
}

export function registerPurviewAuditTools(server: McpServer, graphClient: GraphClient): void {
  server.tool(
    'search-purview-audit-logs',
    `Search Microsoft Purview audit logs. This tool handles the full async workflow in a single call:
1. Creates an audit log search query via the Microsoft Graph beta API
2. Polls every 10 seconds until the query completes (up to 10 minutes)
3. Fetches and returns all result records (auto-paginated)

Requires AuditLogsQuery.Read.All permission and org-mode (--org-mode flag).
Uses the /beta API endpoint as this feature is not available in v1.0.`,
    {
      filterStartDateTime: z
        .string()
        .describe('Start of the search time range (ISO 8601, e.g. 2024-01-01T00:00:00Z)'),
      filterEndDateTime: z
        .string()
        .describe('End of the search time range (ISO 8601, e.g. 2024-01-02T00:00:00Z)'),
      displayName: z
        .string()
        .optional()
        .describe('Optional display name for this query'),
      recordTypeFilters: z
        .array(z.string())
        .optional()
        .describe(
          'Filter by audit record types, e.g. ["sharePoint", "azureActiveDirectory", "microsoftTeams"]. ' +
          'See Microsoft docs for the full list of supported values.'
        ),
      keywordFilter: z
        .string()
        .optional()
        .describe('Free-text keyword search across non-indexed audit properties'),
      serviceFilter: z
        .string()
        .optional()
        .describe('Filter by Microsoft service workload name (e.g. "Exchange", "SharePoint")'),
      operationFilters: z
        .array(z.string())
        .optional()
        .describe('Filter by operation names (e.g. ["FileAccessed", "UserLoggedIn"])'),
      userPrincipalNameFilters: z
        .array(z.string())
        .optional()
        .describe('Filter by user principal names (e.g. ["user@contoso.com"])'),
      ipAddressFilters: z
        .array(z.string())
        .optional()
        .describe('Filter by client IP addresses'),
      objectIdFilters: z
        .array(z.string())
        .optional()
        .describe('Filter by object IDs such as file or folder paths'),
      administrativeUnitIdFilters: z
        .array(z.string())
        .optional()
        .describe('Filter by administrative unit IDs'),
    },
    async (params) => {
      // ── Step 1: Create the audit log query ──────────────────────────────
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

      logger.info('[Purview] Creating audit log query...');

      const createResponse = await graphClient.graphRequest('/security/auditLog/queries', {
        method: 'POST',
        body: JSON.stringify(body),
        ...BETA,
      });

      if (createResponse.isError) {
        return createResponse;
      }

      let query: AuditLogQuery;
      try {
        query = JSON.parse(createResponse.content[0].text) as AuditLogQuery;
      } catch {
        return {
          content: [{ type: 'text' as const, text: createResponse.content[0].text }],
          isError: true,
        };
      }

      const queryId = query.id;
      if (!queryId) {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ error: 'No query ID returned from create call', details: query }),
            },
          ],
          isError: true,
        };
      }

      logger.info(`[Purview] Query created: id=${queryId}, initial status=${query.status}`);

      // ── Step 2: Poll until terminal status ──────────────────────────────
      let status: AuditLogQueryStatus = query.status;
      let polls = 0;

      while (status === 'notStarted' || status === 'running') {
        if (polls >= MAX_POLLS) {
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify({
                  error: 'Timed out waiting for audit log query to complete',
                  queryId,
                  status,
                  elapsedSeconds: polls * (POLL_INTERVAL_MS / 1000),
                }),
              },
            ],
            isError: true,
          };
        }

        await new Promise<void>((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        polls++;

        logger.info(`[Purview] Polling status (attempt ${polls})...`);

        const statusResponse = await graphClient.graphRequest(
          `/security/auditLog/queries/${queryId}`,
          { method: 'GET', ...BETA }
        );

        if (statusResponse.isError) {
          return statusResponse;
        }

        try {
          const statusData = JSON.parse(statusResponse.content[0].text) as AuditLogQuery;
          status = statusData.status;
        } catch {
          return {
            content: [{ type: 'text' as const, text: statusResponse.content[0].text }],
            isError: true,
          };
        }

        logger.info(`[Purview] Query status: ${status}`);
      }

      if (status === 'failed' || status === 'cancelled') {
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({
                error: `Audit log query ${status}`,
                queryId,
                status,
              }),
            },
          ],
          isError: true,
        };
      }

      // ── Step 3: Fetch all records (auto-paginate) ────────────────────────
      logger.info(`[Purview] Query succeeded. Fetching records...`);

      const allRecords: unknown[] = [];
      let nextPath: string | null = `/security/auditLog/queries/${queryId}/records`;
      let pageCount = 0;

      while (nextPath) {
        const recordsResponse = await graphClient.graphRequest(nextPath, {
          method: 'GET',
          ...BETA,
        });

        if (recordsResponse.isError) {
          return recordsResponse;
        }

        let page: AuditLogRecordsPage;
        try {
          page = JSON.parse(recordsResponse.content[0].text) as AuditLogRecordsPage;
        } catch {
          return {
            content: [{ type: 'text' as const, text: recordsResponse.content[0].text }],
            isError: true,
          };
        }

        const records = page.value ?? [];
        allRecords.push(...records);
        pageCount++;

        logger.info(`[Purview] Fetched page ${pageCount} (${records.length} records)`);

        const nextLink = page['@odata.nextLink'];
        nextPath = nextLink ? extractPathAndQuery(nextLink) : null;
      }

      logger.info(`[Purview] Done. Total records: ${allRecords.length} across ${pageCount} page(s).`);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                queryId,
                status,
                totalRecords: allRecords.length,
                records: allRecords,
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
