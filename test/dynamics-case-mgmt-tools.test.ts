import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerDynamicsCaseMgmtTools } from '../src/dynamics-case-mgmt-tools.js';
import type { DataverseClient } from '../src/dataverse-client.js';

vi.mock('../src/logger.js', () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

type ToolHandler = (params: unknown) => Promise<{
  content: { type: string; text: string }[];
  isError?: boolean;
}>;

interface MockServer {
  tool: ReturnType<typeof vi.fn>;
  handlers: Map<string, ToolHandler>;
}

function makeServer(): MockServer {
  const handlers = new Map<string, ToolHandler>();
  const tool = vi.fn(
    (name: string, _description: string, _schema: unknown, handler: ToolHandler) => {
      handlers.set(name, handler);
    }
  );
  return { tool, handlers };
}

function makeDv(overrides: Partial<DataverseClient> = {}): DataverseClient {
  return {
    getOrgUrl: () => 'https://contoso.crm.dynamics.com',
    get: vi.fn().mockResolvedValue({ value: [] }),
    post: vi.fn().mockResolvedValue(null),
    patch: vi.fn().mockResolvedValue(undefined),
    resolveQueue: vi.fn().mockResolvedValue('00000000-0000-0000-0000-000000000001'),
    resolveCase: vi.fn().mockResolvedValue('00000000-0000-0000-0000-000000000002'),
    ...overrides,
  } as unknown as DataverseClient;
}

const ALL_TOOLS = [
  'dynamics-case-mgmt-whoami',
  'dynamics-case-mgmt-list-queue-cases',
  'dynamics-case-mgmt-get-case',
  'dynamics-case-mgmt-search-cases',
  'dynamics-case-mgmt-pick-from-queue',
  'dynamics-case-mgmt-add-note',
  'dynamics-case-mgmt-update-case',
  'dynamics-case-mgmt-resolve-case',
];

const READ_ONLY_TOOLS = [
  'dynamics-case-mgmt-whoami',
  'dynamics-case-mgmt-list-queue-cases',
  'dynamics-case-mgmt-get-case',
  'dynamics-case-mgmt-search-cases',
];

describe('Dynamics 365 case-mgmt tools', () => {
  let server: MockServer;

  beforeEach(() => {
    server = makeServer();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('tool registration', () => {
    it('registers all 8 tools when readOnly=false', () => {
      registerDynamicsCaseMgmtTools(server as never, makeDv(), false);
      const names = Array.from(server.handlers.keys()).sort();
      expect(names).toEqual([...ALL_TOOLS].sort());
    });

    it('registers only the 4 read-only tools when readOnly=true', () => {
      registerDynamicsCaseMgmtTools(server as never, makeDv(), true);
      const names = Array.from(server.handlers.keys()).sort();
      expect(names).toEqual([...READ_ONLY_TOOLS].sort());
    });
  });

  describe('whoami', () => {
    it('returns identity from the WhoAmI Dataverse function', async () => {
      const dv = makeDv({
        get: vi.fn().mockResolvedValue({
          UserId: 'u1',
          BusinessUnitId: 'bu1',
          OrganizationId: 'org1',
        }),
      } as Partial<DataverseClient>);
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-whoami')!;
      const result = await handler({});

      expect(dv.get).toHaveBeenCalledWith('WhoAmI');
      const payload = JSON.parse(result.content[0].text);
      expect(payload).toEqual({
        user_id: 'u1',
        business_unit_id: 'bu1',
        organization_id: 'org1',
        org_url: 'https://contoso.crm.dynamics.com',
      });
    });
  });

  describe('update-case', () => {
    it('refuses statecode in fields and does NOT call patch', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-update-case')!;
      const result = await handler({
        case_id_or_ticket: 'CAS-00001-AB',
        fields: { statecode: 1, title: 'should-be-ignored' },
      });

      expect(result.isError).toBe(true);
      const payload = JSON.parse(result.content[0].text);
      expect(payload.error).toContain('statecode');
      expect(dv.patch).not.toHaveBeenCalled();
      expect(dv.resolveCase).not.toHaveBeenCalled();
    });

    it('PATCHes incidents(<id>) when fields are valid', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-update-case')!;
      const result = await handler({
        case_id_or_ticket: 'CAS-00001-AB',
        fields: { title: 'Updated', prioritycode: 1 },
      });

      expect(dv.patch).toHaveBeenCalledWith('incidents(00000000-0000-0000-0000-000000000002)', {
        title: 'Updated',
        prioritycode: 1,
      });
      const payload = JSON.parse(result.content[0].text);
      expect(payload.status).toBe('ok');
      expect(payload.updated_fields).toEqual(['title', 'prioritycode']);
    });
  });

  describe('resolve-case', () => {
    it('POSTs to /CloseIncident with IncidentResolution + Status (default 5)', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-resolve-case')!;
      await handler({
        case_id_or_ticket: 'CAS-00001-AB',
        resolution_subject: 'Fixed',
      });

      expect(dv.post).toHaveBeenCalledTimes(1);
      const [path, body] = (dv.post as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(path).toBe('CloseIncident');
      expect(body).toMatchObject({
        Status: 5,
        IncidentResolution: {
          '@odata.type': 'Microsoft.Dynamics.CRM.incidentresolution',
          subject: 'Fixed',
          'incidentid@odata.bind': '/incidents(00000000-0000-0000-0000-000000000002)',
        },
      });
    });

    it('honours an explicit status_code override', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-resolve-case')!;
      await handler({
        case_id_or_ticket: 'CAS-00001-AB',
        resolution_subject: 'Info given',
        status_code: 1000,
      });

      const [, body] = (dv.post as ReturnType<typeof vi.fn>).mock.calls[0];
      expect((body as { Status: number }).Status).toBe(1000);
    });
  });

  describe('pick-from-queue', () => {
    it('posts the PickFromQueue action with SystemUser body', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-pick-from-queue')!;
      await handler({
        queueitem_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        assignee_user_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        remove_from_queue: true,
      });

      expect(dv.post).toHaveBeenCalledWith(
        'queueitems(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa)/Microsoft.Dynamics.CRM.PickFromQueue',
        {
          SystemUser: {
            '@odata.type': 'Microsoft.Dynamics.CRM.systemuser',
            systemuserid: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
          },
          RemoveQueueItem: true,
        }
      );
    });
  });

  describe('search-cases', () => {
    it('builds the polymorphic customer filter ORing account.name and contact.fullname', async () => {
      const dv = makeDv();
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-search-cases')!;
      await handler({ customer_name: "O'Brien Co", state: 'active' });

      const [path, query] = (dv.get as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(path).toBe('incidents');
      const filter = (query as { $filter: string }).$filter;
      expect(filter).toContain('statecode eq 0');
      expect(filter).toContain("customerid_account/name eq 'O''Brien Co'");
      expect(filter).toContain("customerid_contact/fullname eq 'O''Brien Co'");
    });
  });

  describe('error handling', () => {
    it('surfaces Dataverse errors as isError responses', async () => {
      const dv = makeDv({
        get: vi.fn().mockRejectedValue(new Error('401 Unauthorized: token expired')),
      } as Partial<DataverseClient>);
      registerDynamicsCaseMgmtTools(server as never, dv, false);

      const handler = server.handlers.get('dynamics-case-mgmt-whoami')!;
      const result = await handler({});

      expect(result.isError).toBe(true);
      const payload = JSON.parse(result.content[0].text);
      expect(payload.error).toContain('401');
    });
  });
});
