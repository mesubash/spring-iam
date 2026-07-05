import { api, requestEnvelope } from "./client";
import type {
  AccessListEntry,
  AdminPasswordSet,
  Assignment,
  AuditEntry,
  AuditStatistics,
  AuthorizeResult,
  ContextAttribute,
  CreatedIdentity,
  DenyRule,
  EffectivePermissions,
  ExplainResult,
  FeatureFlags,
  GroupMember,
  IdentityAdmin,
  LoginResponse,
  ManifestSyncResult,
  Permission,
  PermissionGroup,
  Policy,
  RegisteredService,
  ResourceGrant,
  Role,
  Scope,
  ScopeSummary,
  ServiceClient,
  Session,
  SubjectGroup,
} from "./types";

/* --------------------------------- Auth --------------------------------- */

export const authApi = {
  register: (email: string, password: string) =>
    requestEnvelope("/api/auth/register", { method: "POST", body: { email, password } }),
  login: (email: string, password: string) =>
    requestEnvelope<LoginResponse>("/api/auth/login", { method: "POST", body: { email, password } }),
  logout: () => requestEnvelope("/api/auth/logout", { method: "POST" }),
  logoutAll: () => requestEnvelope("/api/auth/logout-all", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    requestEnvelope("/api/auth/change-password", {
      method: "POST",
      body: { currentPassword, newPassword, confirmPassword: newPassword },
    }),
  changeEmail: (newEmail: string, currentPassword: string) =>
    requestEnvelope("/api/auth/change-email", { method: "POST", body: { newEmail, currentPassword } }),
  forgotPassword: (email: string) =>
    requestEnvelope("/api/auth/forgot-password", { method: "POST", query: { email } }),
  resetPassword: (token: string, newPassword: string) =>
    requestEnvelope("/api/auth/reset-password", { method: "POST", query: { token, newPassword } }),
  resendVerification: (email: string) =>
    requestEnvelope("/api/auth/resend-verification", { method: "POST", query: { email } }),
  sessions: () => api.get<Session[]>("/api/auth/sessions"),
  revokeSession: (id: string) => api.del(`/api/auth/sessions/${id}`),
};

/* --------------------------------- Authz -------------------------------- */

export const authzApi = {
  myScopes: () => api.get<ScopeSummary[]>("/api/authz/me/scopes"),
  myPermissions: (scopeId: string) =>
    api.get<string[]>("/api/authz/me/permissions", { scopeId }),
};

export type AuthorizeInput = {
  subject: string;
  permission: string;
  resource: { type?: string; id?: string; scopeId: string };
  context?: Record<string, unknown>;
};

export const pdpApi = {
  authorize: (input: AuthorizeInput) => api.post<AuthorizeResult>("/api/v1/authorize", input),
  explain: (input: AuthorizeInput) => api.post<ExplainResult>("/api/v1/authorize/explain", input),
  simulate: (input: {
    request: AuthorizeInput;
    addAssignments?: { roleId: string; scopeId: string }[];
    removeAssignmentIds?: string[];
  }) => api.post<ExplainResult>("/api/v1/authorize/simulate", input),
  effectivePermissions: (subject: string, scopeId: string, asOf?: string) =>
    api.post<EffectivePermissions>("/api/v1/effective-permissions", { subject, scopeId }, asOf ? { asOf } : undefined),
  filterResources: (input: {
    subjectId: string;
    permission: string;
    resourceType: string;
    resourceIds: string[];
    scopeId: string;
  }) => api.post<{ allowed: string[] }>("/api/v1/filter-resources", input),
  accessList: (permission: string, scopeId: string) =>
    api.get<AccessListEntry[]>("/api/v1/access-list", { permission, scopeId }),
};

/* --------------------------------- Meta --------------------------------- */

export const metaApi = {
  features: () => api.get<FeatureFlags>("/api/v1/meta/features"),
};

/* ------------------------------ Identities ------------------------------ */

export const identitiesApi = {
  list: (params?: { query?: string; status?: string; limit?: number }) =>
    api.get<IdentityAdmin[]>("/api/v1/identities", params),
  get: (id: string) => api.get<IdentityAdmin>(`/api/v1/identities/${id}`),
  create: (input: { email: string; password?: string; emailVerified?: boolean }) =>
    api.post<CreatedIdentity>("/api/v1/identities", input),
  setPassword: (id: string, input: { newPassword?: string; revokeSessions?: boolean }) =>
    api.put<AdminPasswordSet>(`/api/v1/identities/${id}/password`, input),
  setStatus: (id: string, status: string, reason?: string) =>
    api.put<IdentityAdmin>(`/api/v1/identities/${id}/status`, { status, reason }),
};

/* -------------------------------- Scopes -------------------------------- */

export const scopesApi = {
  list: (type?: string) => api.get<Scope[]>("/api/v1/scopes", type ? { type } : undefined),
  get: (id: string) => api.get<Scope>(`/api/v1/scopes/${id}`),
  root: () => api.get<Scope>("/api/v1/scopes/root"),
  descendants: (id: string) => api.get<Scope[]>(`/api/v1/scopes/${id}/descendants`),
  create: (input: {
    type: string;
    name: string;
    code: string;
    parentId: string;
    metadata?: Record<string, unknown>;
  }) => api.post<Scope>("/api/v1/scopes", input),
  move: (id: string, newParentId: string) =>
    api.post<Scope>(`/api/v1/scopes/${id}/move`, { newParentId }),
};

/* --------------------------------- Roles -------------------------------- */

export const rolesApi = {
  list: (orgType?: string) => api.get<Role[]>("/api/v1/roles", orgType ? { orgType } : undefined),
  get: (id: string) => api.get<Role>(`/api/v1/roles/${id}`),
  permissions: (id: string) => api.get<Permission[]>(`/api/v1/roles/${id}/permissions`),
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

export const roleHierarchyApi = {
  parents: (roleId: string) => api.get<string[]>(`/api/v1/role-hierarchy/parents/${roleId}`),
  children: (roleId: string) => api.get<string[]>(`/api/v1/role-hierarchy/children/${roleId}`),
  add: (parentRoleId: string, childRoleId: string) =>
    api.post("/api/v1/role-hierarchy", { parentRoleId, childRoleId }),
  remove: (parentRoleId: string, childRoleId: string) =>
    api.del("/api/v1/role-hierarchy", { parentRoleId, childRoleId }),
};

/* ------------------------------ Assignments ----------------------------- */

export const assignmentsApi = {
  list: (params?: { subjectId?: string }) => api.get<Assignment[]>("/api/v1/assignments", params),
  create: (input: {
    subjectId: string;
    subjectType: string;
    roleId: string;
    scopeId: string;
    expiresAt?: string | null;
    conditions?: Record<string, unknown>;
  }) => api.post<Assignment>("/api/v1/assignments", input),
  revoke: (id: string, reason: string) => api.del(`/api/v1/assignments/${id}`, { reason }),
};

/* ------------------------------ Deny Rules ------------------------------ */

export const denyRulesApi = {
  // Backend returns [] unless subjectId is provided.
  list: (subjectId: string) => api.get<DenyRule[]>("/api/v1/deny-rules", { subjectId }),
  create: (input: {
    subjectId: string;
    subjectType?: string;
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
  get: (id: string) => api.get<Policy>(`/api/v1/policies/${id}`),
  create: (input: Partial<Policy>) => api.post<Policy>("/api/v1/policies", input),
  update: (id: string, input: Partial<Policy>) => api.put<Policy>(`/api/v1/policies/${id}`, input),
  del: (id: string) => api.del(`/api/v1/policies/${id}`),
};

/* ---------------------------- Context Attributes ------------------------ */

export const contextAttributesApi = {
  list: () => api.get<ContextAttribute[]>("/api/v1/context-attributes"),
  create: (input: { name: string; valueType: string; description?: string }) =>
    api.post<ContextAttribute>("/api/v1/context-attributes", input),
  del: (id: string) => api.del(`/api/v1/context-attributes/${id}`),
};

/* ----------------------------- Resource Grants -------------------------- */

export const resourceGrantsApi = {
  list: (params: { subjectId?: string; resourceType?: string; resourceId?: string }) =>
    api.get<ResourceGrant[]>("/api/v1/resource-grants", params),
  create: (input: {
    subjectId: string;
    subjectType?: string;
    permissionKey: string;
    resourceType: string;
    resourceId: string;
    scopeId?: string | null;
    expiresAt?: string | null;
  }) => api.post<ResourceGrant>("/api/v1/resource-grants", input),
  del: (id: string) => api.del(`/api/v1/resource-grants/${id}`),
};

/* -------------------------------- Groups -------------------------------- */

export const groupsApi = {
  list: () => api.get<SubjectGroup[]>("/api/v1/groups"),
  create: (input: { name: string; description?: string }) =>
    api.post<SubjectGroup>("/api/v1/groups", input),
  members: (id: string) => api.get<GroupMember[]>(`/api/v1/groups/${id}/members`),
  addMember: (id: string, subjectId: string) =>
    api.post(`/api/v1/groups/${id}/members`, { subjectId }),
  removeMember: (id: string, subjectId: string) =>
    api.del(`/api/v1/groups/${id}/members/${encodeURIComponent(subjectId)}`),
};

/* -------------------------------- Services ------------------------------ */

export const servicesApi = {
  list: () => api.get<ServiceClient[]>("/api/v1/services"),
  create: (input: { name: string; displayName?: string; ownedDomains: string[] }) =>
    api.post<RegisteredService>("/api/v1/services", input),
  syncPermissions: (
    name: string,
    permissions: { key: string; description?: string }[],
    deprecateMissing = true,
  ) => api.put<ManifestSyncResult>(`/api/v1/services/${name}/permissions`, { permissions, deprecateMissing }),
};

/* ----------------------------- Permissions ------------------------------ */

export const permissionsApi = {
  list: (domain?: string) => api.get<Permission[]>("/api/v1/permissions", domain ? { domain } : undefined),
  get: (id: string) => api.get<Permission>(`/api/v1/permissions/${id}`),
  create: (input: {
    key: string;
    domain: string;
    resource: string;
    action: string;
    description?: string;
  }) => api.post<Permission[]>("/api/v1/permissions", [input]),
};

export const permissionGroupsApi = {
  list: () => api.get<PermissionGroup[]>("/api/v1/permission-groups"),
};

/* --------------------------------- Audit -------------------------------- */

export const auditApi = {
  bySubject: (subjectId: string, limit = 50) =>
    api.get<AuditEntry[]>(`/api/v1/audit/subject/${encodeURIComponent(subjectId)}`, { limit }),
  byResource: (resourceType: string, resourceId: string, limit = 50) =>
    api.get<AuditEntry[]>(`/api/v1/audit/resource/${resourceType}/${resourceId}`, { limit }),
  statistics: (subjectId: string, sinceDaysAgo = 7) =>
    api.get<AuditStatistics>(`/api/v1/audit/statistics/${encodeURIComponent(subjectId)}`, { sinceDaysAgo }),
};

/* ------------------------------ Break-glass ----------------------------- */

export const breakGlassApi = {
  grant: (input: {
    subjectId: string;
    roleId: string;
    scopeId: string;
    durationMinutes: number;
    reason: string;
    referenceId?: string;
  }) => api.post<Assignment>("/api/v1/break-glass", input),
};

/* --------------------------------- Keys --------------------------------- */

export const keysApi = {
  rotate: () => api.post<{ kid: string }>("/api/v1/keys/rotate"),
};
