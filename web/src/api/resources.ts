import { api, requestEnvelope } from "./client";
import type {
  Assignment,
  AuditEntry,
  DenyRule,
  ExplainResult,
  FeatureFlags,
  Group,
  GroupMember,
  LoginResponse,
  Permission,
  Policy,
  ResourceGrant,
  Role,
  Scope,
  ServiceRegistryEntry,
  Session,
} from "./types";

/* --------------------------------- Auth --------------------------------- */

export const authApi = {
  login: (email: string, password: string) =>
    requestEnvelope<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: { email, password },
    }),
  logout: () => requestEnvelope("/api/auth/logout", { method: "POST" }),
  logoutAll: () => requestEnvelope("/api/auth/logout-all", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    requestEnvelope("/api/auth/change-password", {
      method: "POST",
      body: { currentPassword, newPassword },
    }),
  sessions: () => api.get<Session[]>("/api/auth/sessions"),
  revokeSession: (id: string) => api.del(`/api/auth/sessions/${id}`),
};

/* --------------------------------- Authz -------------------------------- */

export type ScopeSummary = { id: string; name: string; path?: string; type?: string };

export const authzApi = {
  myScopes: () => api.get<ScopeSummary[]>("/api/authz/me/scopes"),
  myPermissions: (scopeId: string) =>
    api.get<string[]>("/api/authz/me/permissions", { scopeId }),
  explain: (input: unknown) => api.post<ExplainResult>("/api/v1/authorize/explain", input),
};

/* --------------------------------- Meta --------------------------------- */

export const metaApi = {
  features: () => api.get<FeatureFlags>("/api/v1/meta/features"),
};

/* --------------------------------- Scopes ------------------------------- */

export const scopesApi = {
  list: () => api.get<Scope[]>("/api/v1/scopes"),
  create: (input: {
    type: string;
    name: string;
    code: string;
    parentId?: string | null;
  }) => api.post<Scope>("/api/v1/scopes", input),
  move: (id: string, newParentId: string) =>
    api.post(`/api/v1/scopes/${id}/move`, { newParentId }),
};

/* --------------------------------- Roles -------------------------------- */

export const rolesApi = {
  list: () => api.get<Role[]>("/api/v1/roles"),
  create: (input: {
    name: string;
    displayName?: string;
    description?: string;
    ownerScopeId?: string | null;
    permissionIds: string[];
  }) => api.post<Role>("/api/v1/roles", input),
  updatePermissions: (id: string, permissionIds: string[]) =>
    api.put(`/api/v1/roles/${id}/permissions`, permissionIds),
};

/* ------------------------------ Assignments ----------------------------- */

export const assignmentsApi = {
  list: (params?: { subjectId?: string }) =>
    api.get<Assignment[]>("/api/v1/assignments", params),
  create: (input: {
    subjectId: string;
    subjectType: string;
    roleId: string;
    scopeId?: string | null;
    expiresAt?: string | null;
    conditions?: unknown;
  }) => api.post<Assignment>("/api/v1/assignments", input),
  revoke: (id: string, reason: string) =>
    api.del(`/api/v1/assignments/${id}`, { reason }),
};

/* ------------------------------ Deny Rules ------------------------------ */

export const denyRulesApi = {
  list: () => api.get<DenyRule[]>("/api/v1/deny-rules"),
  create: (input: {
    subjectId: string;
    subjectType: string;
    permissionKey: string;
    scopeId?: string | null;
    reason: string;
    referenceId?: string | null;
    expiresAt?: string | null;
  }) => api.post<DenyRule>("/api/v1/deny-rules", input),
  del: (id: string) => api.del(`/api/v1/deny-rules/${id}`),
};

/* -------------------------------- Policies ------------------------------ */

export const policiesApi = {
  list: () => api.get<Policy[]>("/api/v1/policies"),
  create: (input: Partial<Policy>) => api.post<Policy>("/api/v1/policies", input),
  update: (id: string, input: Partial<Policy>) =>
    api.put<Policy>(`/api/v1/policies/${id}`, input),
  del: (id: string) => api.del(`/api/v1/policies/${id}`),
};

/* ----------------------------- Resource Grants -------------------------- */

export const resourceGrantsApi = {
  list: (params?: {
    subjectId?: string;
    resourceType?: string;
    resourceId?: string;
  }) => api.get<ResourceGrant[]>("/api/v1/resource-grants", params),
  create: (input: Partial<ResourceGrant>) =>
    api.post<ResourceGrant>("/api/v1/resource-grants", input),
  del: (id: string) => api.del(`/api/v1/resource-grants/${id}`),
};

/* -------------------------------- Groups -------------------------------- */

export const groupsApi = {
  list: () => api.get<Group[]>("/api/v1/groups"),
  members: (id: string) => api.get<GroupMember[]>(`/api/v1/groups/${id}/members`),
  addMember: (id: string, input: { subjectId: string; subjectType: string }) =>
    api.post(`/api/v1/groups/${id}/members`, input),
  removeMember: (id: string, memberId: string) =>
    api.del(`/api/v1/groups/${id}/members/${memberId}`),
};

/* -------------------------------- Services ------------------------------ */

export const servicesApi = {
  list: () => api.get<ServiceRegistryEntry[]>("/api/v1/services"),
  create: (input: { name: string; displayName?: string; ownedDomains: string[] }) =>
    api.post<ServiceRegistryEntry & { apiKey: string }>("/api/v1/services", input),
};

/* ----------------------------- Permissions ------------------------------ */

export const permissionsApi = {
  list: () => api.get<Permission[]>("/api/v1/permissions"),
};

/* --------------------------------- Audit -------------------------------- */

export const auditApi = {
  bySubject: (subjectId: string) =>
    api.get<AuditEntry[]>(`/api/v1/audit/subject/${subjectId}`),
  recent: () => api.get<AuditEntry[]>("/api/v1/audit/recent"),
};