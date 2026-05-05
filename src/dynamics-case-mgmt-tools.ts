import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import logger from './logger.js';
import { DataverseClient } from './dataverse-client.js';

type McpToolResult = {
  content: { type: 'text'; text: string }[];
  isError?: boolean;
};

function ok(payload: unknown): McpToolResult {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }],
  };
}

function fail(message: string, extra?: Record<string, unknown>): McpToolResult {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify({ error: message, ...extra }) }],
    isError: true,
  };
}

async function safe(label: string, fn: () => Promise<McpToolResult>): Promise<McpToolResult> {
  try {
    return await fn();
  } catch (error) {
    const message = (error as Error).message;
    logger.error(`[D365 case-mgmt] ${label} failed: ${message}`);
    return fail(message);
  }
}

/**
 * Register the 8 Dynamics 365 Customer Service case-management tools.
 *
 * Read-only tools (always registered):
 *   - dynamics-case-mgmt-whoami
 *   - dynamics-case-mgmt-list-queue-cases
 *   - dynamics-case-mgmt-get-case
 *   - dynamics-case-mgmt-search-cases
 *
 * Mutating tools (skipped when readOnly=true):
 *   - dynamics-case-mgmt-pick-from-queue
 *   - dynamics-case-mgmt-add-note
 *   - dynamics-case-mgmt-update-case
 *   - dynamics-case-mgmt-resolve-case
 */
export function registerDynamicsCaseMgmtTools(
  server: McpServer,
  dv: DataverseClient,
  readOnly: boolean
): void {
  // ── Read-only tools ────────────────────────────────────────────────────

  server.tool(
    'dynamics-case-mgmt-whoami',
    'Return the signed-in Dataverse user identity (user_id, business_unit_id, organization_id). ' +
      'Useful as a sanity check that auth and the org URL are wired correctly.',
    {},
    async () =>
      safe('whoami', async () => {
        const res = (await dv.get('WhoAmI')) as Record<string, unknown>;
        return ok({
          user_id: res.UserId,
          business_unit_id: res.BusinessUnitId,
          organization_id: res.OrganizationId,
          org_url: dv.getOrgUrl(),
        });
      })
  );

  server.tool(
    'dynamics-case-mgmt-list-queue-cases',
    'List cases (incidents) currently in a Dynamics 365 queue. Returns one entry per ' +
      'queue item with the case fields embedded. Note: queueitem GUID is distinct from ' +
      'the incident GUID — pass queueitem_id (not case.incidentid) into pick-from-queue.',
    {
      queue_id_or_name: z.string().describe('Queue GUID or display name (e.g. "Tier 1 Support").'),
      top: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .optional()
        .describe('Max number of items to return (default 25, max 5000).'),
      only_unworked: z
        .boolean()
        .optional()
        .describe(
          'If true (default), only items not currently being worked on (workerid is null).'
        ),
    },
    async (params) =>
      safe('list-queue-cases', async () => {
        const top = params.top ?? 25;
        const onlyUnworked = params.only_unworked ?? true;
        const queueId = await dv.resolveQueue(params.queue_id_or_name);

        const filters = [`_queueid_value eq ${queueId}`, "objecttypecode eq 'incident'"];
        if (onlyUnworked) filters.push('_workerid_value eq null');

        const res = (await dv.get('queueitems', {
          $filter: filters.join(' and '),
          $top: Math.min(top, 5000),
          $select: 'queueitemid,enteredon,_workerid_value',
          $expand:
            'objectid_incident($select=incidentid,ticketnumber,title,description,prioritycode,statecode,statuscode,createdon,modifiedon)',
          $orderby: 'enteredon desc',
        })) as { value?: Record<string, unknown>[] };

        const items = (res.value ?? []).map((qi) => ({
          queueitem_id: qi.queueitemid,
          entered_on: qi.enteredon,
          currently_worked_by: qi._workerid_value,
          case: qi.objectid_incident ?? {},
        }));
        return ok(items);
      })
  );

  server.tool(
    'dynamics-case-mgmt-get-case',
    'Get a case (incident) by GUID or ticket number, with optional related notes ' +
      '(annotations) and email activities.',
    {
      case_id_or_ticket: z
        .string()
        .describe('Incident GUID or ticket number (e.g. "CAS-01234-XXXXXX").'),
      include_notes: z
        .boolean()
        .optional()
        .describe('Include annotations (notes) on the case (default true).'),
      include_emails: z
        .boolean()
        .optional()
        .describe('Include email activities on the case (default false).'),
    },
    async (params) =>
      safe('get-case', async () => {
        const includeNotes = params.include_notes ?? true;
        const includeEmails = params.include_emails ?? false;
        const caseId = await dv.resolveCase(params.case_id_or_ticket);

        const select = [
          'incidentid',
          'ticketnumber',
          'title',
          'description',
          'prioritycode',
          'statecode',
          'statuscode',
          'createdon',
          'modifiedon',
          '_customerid_value',
          '_ownerid_value',
        ].join(',');
        const caseRow = await dv.get(`incidents(${caseId})`, { $select: select });

        const result: Record<string, unknown> = { case: caseRow };

        if (includeNotes) {
          const notes = (await dv.get('annotations', {
            $filter: `_objectid_value eq ${caseId}`,
            $select: 'annotationid,subject,notetext,createdon,_createdby_value',
            $orderby: 'createdon desc',
          })) as { value?: unknown[] };
          result.notes = notes.value ?? [];
        }

        if (includeEmails) {
          const emails = (await dv.get('emails', {
            $filter: `_regardingobjectid_value eq ${caseId}`,
            $select: 'activityid,subject,description,directioncode,createdon',
            $orderby: 'createdon desc',
          })) as { value?: unknown[] };
          result.emails = emails.value ?? [];
        }

        return ok(result);
      })
  );

  server.tool(
    'dynamics-case-mgmt-search-cases',
    'Search cases by customer name, keyword, and/or state. customer_name does an ' +
      'exact match on either account.name or contact.fullname (customerid is polymorphic).',
    {
      customer_name: z
        .string()
        .optional()
        .describe('Exact-match account.name or contact.fullname on the case customer lookup.'),
      keyword: z.string().optional().describe('Substring-match against case title or description.'),
      state: z
        .enum(['active', 'resolved', 'cancelled'])
        .optional()
        .describe('Filter by state. Default: any.'),
      top: z.number().int().min(1).max(5000).optional().describe('Max results (default 25).'),
    },
    async (params) =>
      safe('search-cases', async () => {
        const top = params.top ?? 25;
        const filters: string[] = [];

        if (params.state) {
          const stateMap: Record<string, number> = { active: 0, resolved: 1, cancelled: 2 };
          filters.push(`statecode eq ${stateMap[params.state]}`);
        }
        if (params.keyword) {
          const kw = params.keyword.replace(/'/g, "''");
          filters.push(`(contains(title,'${kw}') or contains(description,'${kw}'))`);
        }
        if (params.customer_name) {
          const cn = params.customer_name.replace(/'/g, "''");
          filters.push(
            `(customerid_account/name eq '${cn}' or customerid_contact/fullname eq '${cn}')`
          );
        }

        const query: Record<string, string | number> = {
          $select:
            'incidentid,ticketnumber,title,prioritycode,statecode,statuscode,createdon,modifiedon',
          $top: top,
          $orderby: 'modifiedon desc',
        };
        if (filters.length > 0) query.$filter = filters.join(' and ');

        const res = (await dv.get('incidents', query)) as { value?: unknown[] };
        return ok(res.value ?? []);
      })
  );

  if (readOnly) {
    logger.info('[D365 case-mgmt] read-only mode — skipping mutating tools');
    return;
  }

  // ── Mutating tools ─────────────────────────────────────────────────────

  server.tool(
    'dynamics-case-mgmt-pick-from-queue',
    'Assign a queue item to a CSR (PickFromQueue action). Pass the **queueitem GUID** ' +
      '(from list-queue-cases), NOT the incident GUID. Because auth is delegated, an ' +
      'explicit assignee_user_id (systemuser GUID) is required.',
    {
      queueitem_id: z
        .string()
        .describe('Queueitem GUID (from list-queue-cases). NOT the incident GUID.'),
      assignee_user_id: z.string().describe('systemuser GUID of the CSR to assign the case to.'),
      remove_from_queue: z
        .boolean()
        .optional()
        .describe(
          'If true, removes the item from the queue after assignment (full takeover; default false).'
        ),
    },
    async (params) =>
      safe('pick-from-queue', async () => {
        const removeFromQueue = params.remove_from_queue ?? false;
        const body = {
          SystemUser: {
            '@odata.type': 'Microsoft.Dynamics.CRM.systemuser',
            systemuserid: params.assignee_user_id,
          },
          RemoveQueueItem: removeFromQueue,
        };
        await dv.post(
          `queueitems(${params.queueitem_id})/Microsoft.Dynamics.CRM.PickFromQueue`,
          body
        );
        return ok({
          status: 'ok',
          queueitem_id: params.queueitem_id,
          assigned_to: params.assignee_user_id,
          removed_from_queue: removeFromQueue,
        });
      })
  );

  server.tool(
    'dynamics-case-mgmt-add-note',
    'Add a note (annotation) to a case.',
    {
      case_id_or_ticket: z.string().describe('Incident GUID or ticket number.'),
      subject: z.string().describe('Short note title.'),
      note_text: z.string().describe('Body of the note (plain text or simple HTML).'),
    },
    async (params) =>
      safe('add-note', async () => {
        const caseId = await dv.resolveCase(params.case_id_or_ticket);
        const res = (await dv.post(
          'annotations',
          {
            subject: params.subject,
            notetext: params.note_text,
            'objectid_incident@odata.bind': `/incidents(${caseId})`,
          },
          'return=representation'
        )) as Record<string, unknown> | null;
        return ok({
          annotation_id: res?.annotationid ?? null,
          case_id: caseId,
        });
      })
  );

  server.tool(
    'dynamics-case-mgmt-update-case',
    'Patch fields on a case. Common fields: title, description, prioritycode ' +
      '(1=High, 2=Normal, 3=Low). Set lookups via "<navprop>@odata.bind" with value ' +
      '"/<entityset>(<guid>)" — e.g. {"customerid_account@odata.bind": "/accounts(<guid>)"}. ' +
      'Refuses statecode — use resolve-case to close.',
    {
      case_id_or_ticket: z.string().describe('Incident GUID or ticket number.'),
      fields: z
        .record(z.string(), z.unknown())
        .describe('Field map to PATCH onto the incident. Must not include statecode.'),
    },
    async (params) =>
      safe('update-case', async () => {
        if ('statecode' in params.fields) {
          return fail(
            'Refusing to set statecode via update-case; use dynamics-case-mgmt-resolve-case to close.'
          );
        }
        const caseId = await dv.resolveCase(params.case_id_or_ticket);
        await dv.patch(`incidents(${caseId})`, params.fields);
        return ok({
          status: 'ok',
          case_id: caseId,
          updated_fields: Object.keys(params.fields),
        });
      })
  );

  server.tool(
    'dynamics-case-mgmt-resolve-case',
    'Resolve (close) a case via the CloseIncident action. Always use this rather than ' +
      'PATCHing statecode directly — Dataverse rejects direct closes and requires ' +
      'CloseIncident so an incidentresolution activity is created. status_code defaults ' +
      'to 5 (Problem Solved, OOB); orgs that have customized the option set should pass ' +
      'their own value.',
    {
      case_id_or_ticket: z.string().describe('Incident GUID or ticket number.'),
      resolution_subject: z.string().describe('Short title for the resolution.'),
      resolution_description: z
        .string()
        .optional()
        .describe('Detailed resolution notes (default empty).'),
      billable_minutes: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe('timespent in minutes (default 0).'),
      status_code: z
        .number()
        .int()
        .optional()
        .describe(
          'incident statuscode at close. Default 5 = Problem Solved (OOB). Other OOB: 1000 = Information Provided.'
        ),
    },
    async (params) =>
      safe('resolve-case', async () => {
        const caseId = await dv.resolveCase(params.case_id_or_ticket);
        const statusCode = params.status_code ?? 5;
        const body = {
          IncidentResolution: {
            '@odata.type': 'Microsoft.Dynamics.CRM.incidentresolution',
            subject: params.resolution_subject,
            description: params.resolution_description ?? '',
            timespent: params.billable_minutes ?? 0,
            'incidentid@odata.bind': `/incidents(${caseId})`,
          },
          Status: statusCode,
        };
        await dv.post('CloseIncident', body);
        return ok({
          status: 'ok',
          case_id: caseId,
          resolution_subject: params.resolution_subject,
          status_code: statusCode,
        });
      })
  );
}
