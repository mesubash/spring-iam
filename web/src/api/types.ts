// Types mirror the Spring IAM REST contract exactly. Admin /api/v1/* endpoints
// return raw JSON entities; /api/auth/* return an { status, message, data } envelope.

export type Identity = {
  id: string;
  email: string;
  emailVerified?: boolean;
  displayName?: string | null;
  [k: string]: unknown;
};

export type LoginResponse = {
  accessToken: string;
  expiresIn: number;
  tokenType?: string;
  identity: Identity;
};

export type Scope = {
  id: string;
  type: string;
  name: string;
  code: string;
  parentId: string | null;
  path: string;
  depth: number;
  metadata?: Record<string, unknown>;
  active: boolean;
  createdBy?: string;
};

/** Slim scope from /api/authz/me/scopes */
export type ScopeSummary = {
  id: string;
  type?: string;
  name: string;
  code?: string;
  path?: string;
};

export type Permission = {
  id: string;
  key: string;
  domain: string;
  resource: string;
  action: string;
  description?: string | null;
  isDeprecated?: boolean;
};

export type Role = {
  id: string;
  name: string;
  displayName?: string | null;
  description?: string | null;
  isSystemRole: boolean;
  orgType?: string | null;
  ownerScopeId: string | null;
  active: boolean;
  createdBy?: string;
};

export type Assignment = {
  id: string;
  subjectId: string;
  subjectType: string;
  roleId: string;
  scopeId: string;
  origin?: string;
  grantedBy?: string;
  grantedAt?: string;
  expiresAt?: string | null;
  conditions?: Record<string, unknown>;
  active: boolean;
  revokedAt?: string | null;
  revokeReason?: string | null;
};

export type DenyRule = {
  id: string;
  subjectId: string;
  subjectType?: string;
  permissionKey: string;
  scopeId?: string | null;
  reason: string;
  referenceId?: string | null;
  expiresAt?: string | null;
  active?: boolean;
  createdAt?: string;
  createdBy?: string;
};

export type Policy = {
  id: string;
  name: string;
  description?: string | null;
  permissionKey?: string | null;
  resourceType?: string | null;
  scopeId?: string | null;
  effect: "ALLOW" | "DENY";
  enforcementMode: "ENFORCE" | "SHADOW";
  priority: number;
  conditions?: Record<string, unknown>;
  active: boolean;
};

export type ResourceGrant = {
  id: string;
  subjectId: string;
  subjectType?: string;
  permissionKey: string;
  resourceType: string;
  resourceId: string;
  scopeId?: string | null;
  grantedBy?: string;
  grantedAt?: string;
  expiresAt?: string | null;
  revokedAt?: string | null;
};

export type SubjectGroup = {
  id: string;
  name: string;
  description?: string | null;
  active?: boolean;
};

export type GroupMember = {
  groupId: string;
  subjectId: string;
  addedAt?: string;
  addedBy?: string;
};

export type ServiceClient = {
  id: string;
  name: string;
  displayName?: string;
  ownedDomains: string[];
  active?: boolean;
  lastSeenAt?: string | null;
};

export type ContextAttribute = {
  id: string;
  name: string;
  valueType: "STRING" | "NUMBER" | "BOOLEAN" | "TIMESTAMP";
  description?: string | null;
};

export type PermissionGroup = {
  id: string;
  name: string;
  description?: string | null;
  parentGroupId?: string | null;
};

export type AuditEntry = {
  id: string;
  timestamp: string;
  subjectId: string;
  permissionKey: string;
  resourceType?: string | null;
  resourceId?: string | null;
  scopeId?: string | null;
  decision: boolean;
  reason: string;
  context?: Record<string, unknown>;
  requestId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
};

export type AuditStatistics = {
  total: number;
  allowed: number;
  denied: number;
  allowRate: number;
  byPermission?: Record<string, number>;
};

export type Session = {
  id: string;
  deviceLabel?: string | null;
  createdIp?: string | null;
  createdAt: string;
  lastUsedAt?: string;
};

export type FeatureFlags = {
  "resource-grants": boolean;
  groups: boolean;
  "service-registry": boolean;
  oauth2: boolean;
  "break-glass": boolean;
  introspection: boolean;
  "revocation-feed": boolean;
};

// Decision trace from /authorize/explain and /authorize/simulate
export type ExplainStep = {
  name: string; // scope_validity | deny_rules | rbac_scope | conditions | resource_grants | policies
  outcome: "PASS" | "FAIL" | "SKIP" | "ALLOW" | "DENY";
  detail: string;
};

export type ExplainResult = {
  allowed: boolean;
  reason: string;
  steps: ExplainStep[];
};

export type AuthorizeResult = {
  authorized: boolean;
  reason: string;
  policyVersion?: number;
  effectivePermissions?: string[];
  auditId?: string;
};

export type EffectivePermissions = {
  subject: string;
  scopeId: string;
  permissions: string[];
};

export type AccessListEntry = {
  subjectId: string;
  conditional: boolean;
};

export type ManifestSyncResult = {
  created: number;
  unchanged: number;
  deprecated: number;
};

export type RegisteredService = ServiceClient & { apiKey: string };
