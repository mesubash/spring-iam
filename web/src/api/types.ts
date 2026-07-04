export type Identity = {
  id: string;
  email: string;
  displayName?: string;
  [k: string]: unknown;
};

export type LoginResponse = {
  accessToken: string;
  expiresIn: number;
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
  active: boolean;
};

export type Permission = {
  id: string;
  key: string;
  domain?: string;
  resource?: string;
  action?: string;
  description?: string;
  deprecated?: boolean;
};

export type Role = {
  id: string;
  name: string;
  displayName?: string;
  description?: string;
  ownerScopeId: string | null;
  systemRole?: boolean;
  permissionIds?: string[];
};

export type Assignment = {
  id: string;
  subjectId: string;
  subjectType: string;
  roleId: string;
  roleName?: string;
  scopeId: string | null;
  scopePath?: string | null;
  expiresAt?: string | null;
  origin?: string;
  conditions?: unknown;
};

export type DenyRule = {
  id: string;
  subjectId: string;
  subjectType: string;
  permissionKey: string;
  scopeId?: string | null;
  reason: string;
  referenceId?: string | null;
  expiresAt?: string | null;
  createdAt?: string;
};

export type Policy = {
  id: string;
  name: string;
  effect: "ALLOW" | "DENY";
  enforcementMode: "ENFORCE" | "SHADOW";
  priority: number;
  permissionKey: string;
  resourceType?: string;
  conditions?: unknown;
  description?: string;
};

export type ResourceGrant = {
  id: string;
  subjectId: string;
  permissionKey: string;
  resourceType: string;
  resourceId: string;
  scopeId?: string | null;
  expiresAt?: string | null;
};

export type Group = {
  id: string;
  name: string;
  displayName?: string;
  description?: string;
};

export type GroupMember = {
  id: string;
  subjectId: string;
  subjectType: string;
  addedAt?: string;
};

export type ServiceRegistryEntry = {
  id: string;
  name: string;
  displayName?: string;
  ownedDomains: string[];
  lastSeenAt?: string | null;
};

export type AuditEntry = {
  id: string;
  timestamp: string;
  subjectId: string;
  permissionKey: string;
  decision: "ALLOW" | "DENY";
  reason?: string;
  scopeId?: string | null;
  context?: unknown;
};

export type Session = {
  id: string;
  deviceLabel?: string;
  createdIp?: string;
  createdAt: string;
  lastUsedAt?: string;
};

export type FeatureFlags = {
  "resource-grants": boolean;
  groups: boolean;
  "service-registry": boolean;
  oauth2: boolean;
};

export type ExplainStep = {
  stage: string;
  passed: boolean;
  decision?: "ALLOW" | "DENY" | "SKIP" | "NEUTRAL";
  rule?: string;
  detail?: string;
  data?: unknown;
};

export type ExplainResult = {
  decision: "ALLOW" | "DENY";
  steps: ExplainStep[];
};