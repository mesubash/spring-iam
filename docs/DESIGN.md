# 🔐 Enterprise Authorization System - Complete Documentation

> **Version:** 1.0  
> **Last Updated:** January 2026  
> **Status:** Production-Ready Design

---

## 📑 Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Core Principles](#2-core-principles)
3. [System Architecture](#3-system-architecture)
4. [Authorization Model](#4-authorization-model)
5. [Database Schema](#5-database-schema)
6. [Authorization Algorithm](#6-authorization-algorithm)
7. [Permission Catalog](#7-permission-catalog)
8. [Role Definitions](#8-role-definitions)
9. [API Specifications](#9-api-specifications)
10. [Integration Guide](#10-integration-guide)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Performance & Security](#12-performance--security)

---

## 1. Executive Summary

### 1.1 Purpose

This document defines a **centralized authorization system** that serves as the single source of truth for access control across all services, products, and platforms in the organization.

### 1.2 Key Capabilities

✅ **Multi-tenant isolation** - Complete data separation between organizations  
✅ **Hierarchical scopes** - Global → Region → Country → Organization → Department → Team  
✅ **Fine-grained permissions** - Domain.Resource.Action pattern  
✅ **Role-based access** - Reusable role templates  
✅ **Attribute-based policies** - Context-aware decisions  
✅ **Audit trail** - Every decision logged immutably  
✅ **Performance optimized** - Closure tables + caching  
✅ **Future-proof** - Extensible without redesign

### 1.3 Business Domains Supported

- **Travel & Tourism** - Orders, tourists, guides, devices
- **Rescue Operations** - SOS handling, rescue missions
- **Insurance** - Policies, claims, underwriting
- **Finance** - Payments, invoices, commissions
- **Organization Management** - Companies, employees, roles
- **Platform Administration** - Countries, regions, analytics
- **Future domains** - Hospitals, logistics (plug-in ready)

---

## 2. Core Principles

### 2.1 Non-Negotiable Rules

```
1. Authorization is centralized (no service-local auth logic)
2. Permissions are immutable contracts (never rename)
3. Explicit DENY always overrides ALLOW
4. Scope defines authority boundaries (hierarchical)
5. Every decision is auditable (immutable logs)
6. Services contain ZERO permission logic
7. Roles never contain scope (scope is assigned separately)
8. Policy logic is externalized (not in database)
```

**Violation of any principle = guaranteed redesign required.**

### 2.2 Authorization Question

Every authorization request answers:

> **Can subject S perform action A on resource R under context C?**

Where:
- **S** = User or service account
- **A** = Permission (e.g., `order.order.approve`)
- **R** = Business object (Order, Tourist, Invoice)
- **C** = Context (time, IP, ownership, assignment)

---

## 3. System Architecture

### 3.1 Component Overview

```
┌─────────────────────────────────────────────────────────┐
│              CLIENT APPLICATIONS LAYER                   │
│  Web App  |  Mobile App  |  Admin Portal  |  Partners   │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP/REST
                     ↓
┌─────────────────────────────────────────────────────────┐
│                   API GATEWAY                            │
│         (Authentication, Rate Limiting, Routing)         │
└────────────────────┬────────────────────────────────────┘
                     │
          ┌──────────┼──────────┬──────────────────┐
          │          │          │                  │
          ↓          ↓          ↓                  ↓
┌─────────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────┐
│   Order     │ │ Rescue   │ │ Tourist │ │   Finance    │
│  Service    │ │ Service  │ │ Service │ │   Service    │
└──────┬──────┘ └────┬─────┘ └────┬────┘ └──────┬───────┘
       │             │             │             │
       └─────────────┼─────────────┼─────────────┘
                     │ gRPC/HTTP
                     ↓
       ┌─────────────────────────────────────┐
       │      IAM SERVICE (Authorization)     │
       │  ┌─────────────────────────────┐   │
       │  │  Authorization Engine        │   │
       │  │  - RBAC Evaluator           │   │
       │  │  - Scope Resolver           │   │
       │  │  - Policy Engine            │   │
       │  │  - DENY Rule Processor      │   │
       │  └─────────────────────────────┘   │
       │  ┌─────────────────────────────┐   │
       │  │  Cache Layer (Redis)         │   │
       │  └─────────────────────────────┘   │
       └──────────────┬──────────────────────┘
                      │
                      ↓
       ┌─────────────────────────────────────┐
       │    AUTHORIZATION DATABASE            │
       │         (PostgreSQL)                 │
       └──────────────────────────────────────┘
```

### 3.2 Request Flow Sequence

```
1. User clicks "Approve Order" in Web App

2. Web App → Order Service: POST /orders/123/approve

3. Order Service → IAM Service: 
   POST /authorize {
     subject: "user_ram",
     permission: "order.order.approve",
     resource: {scopeId: "ORG:EVEREST_TRAVELS"}
   }

4. IAM Service:
   a. Check Redis cache
   b. If miss, query database
   c. Evaluate: DENY rules → Permissions → Scope → Conditions
   d. Return decision + reason
   e. Log to audit_log

5. Order Service:
   if (authorized) {
     execute business logic
   } else {
     throw 403 Forbidden
   }

6. Response → User
```

---

## 4. Authorization Model

### 4.1 Hybrid Model Components

The system uses a **hybrid authorization model**:

| Component | Purpose | Example |
|-----------|---------|---------|
| **RBAC** | Defines "what you can do" | TravelAgencyAdmin role grants order.order.approve |
| **Scope Hierarchy** | Defines "where you can do it" | Admin at Company A cannot see Company B |
| **ABAC** | Defines "when/how you can do it" | Only during business hours, only from office IP |
| **ReBAC** | Defines ownership & assignment | Only assigned rescuer can update rescue status |
| **DENY Rules** | Safety & compliance overrides | Suspend user during investigation |

### 4.2 Scope Hierarchy Structure

```
GLOBAL
 │
 └── REGION (Asia, Africa, Europe)
      │
      └── COUNTRY (Nepal, Thailand, India)
           │
           └── ORGANIZATION (Travel Agency, Rescue Company, Hospital)
                │
                └── DEPARTMENT (Sales, Operations, Medical)
                     │
                     └── TEAM / FACILITY (Team Alpha, Hospital Branch 3)
                          │
                          └── PROJECT (Optional)
```

**Key Properties:**
- **Hierarchical** - Parent contains all children
- **Inheritable** - Permissions flow downward
- **Flexible** - Support any depth
- **Isolating** - Siblings cannot see each other

**Example:**
```
User: Hari (Regional Admin for Asia)
Scope: REGION:ASIA

Can access:
✅ All organizations in Asia
✅ Everest Travels (inside Nepal)
✅ Mountain Rescue (inside Nepal)

Cannot access:
❌ Organizations in Africa (different region)
❌ Global data (higher level)
```

### 4.3 Permission Structure

**Format:**
```
<domain>.<resource>.<action>

Components:
- domain: Business capability (tourist, order, rescue, finance)
- resource: Entity being acted upon (profile, order, claim)
- action: Operation verb (create, read, update, delete, approve, assign)
```

**Examples:**
```
tourist.profile.create
order.order.approve
rescue.sos.handle
insurance.claim.review
finance.payment.execute
org.employee.create
platform.analytics.view
```

### 4.4 How Authorization Combines

```
AUTHORIZATION = ROLE × SCOPE × CONTEXT

Example:
User: Ram
Role: TravelAgencyAdmin
  → Grants: order.order.approve
  
Scope: ORG:EVEREST_TRAVELS
  → Limits: Only Everest Travels data
  
Context: Cannot approve own orders
  → Condition: owner_id ≠ approver_id

Result: 
✅ Can approve Everest Travels orders created by others
❌ Cannot approve own orders
❌ Cannot approve other companies' orders
```

---

## 5. Database Schema

### 5.1 Schema Overview

The authorization database consists of 8 core tables:

1. **permissions** - Immutable permission registry
2. **scopes** - Hierarchical organization structure
3. **scope_closure** - Pre-computed hierarchy (performance)
4. **roles** - Permission bundles
5. **role_permissions** - Role-to-permission mapping
6. **assignments** - User-to-role at scope
7. **deny_rules** - Explicit denial overrides
8. **authorization_audit** - Immutable decision log

---

### 5.2 Table Definitions

#### 5.2.1 permissions (Immutable Registry)

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(50) NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT chk_key_format 
    CHECK (key ~ '^[a-z]+\.[a-z]+\.[a-z]+$')
);

CREATE INDEX idx_permissions_domain ON permissions(domain);
CREATE INDEX idx_permissions_key ON permissions(key);
```

**Purpose:** Central registry of all permissions

**Key Points:**
- Permissions are **never deleted**, only deprecated
- `key` is unique identifier used everywhere
- Format: `domain.resource.action`

**Sample Data:**
```sql
INSERT INTO permissions (key, domain, resource, action, description) 
VALUES
('tourist.profile.create', 'tourist', 'profile', 'create', 
 'Create new tourist profile'),
('order.order.approve', 'order', 'order', 'approve', 
 'Approve travel order'),
('rescue.sos.handle', 'rescue', 'sos', 'handle', 
 'Respond to SOS alert');
```

---

#### 5.2.2 scopes (Hierarchy Nodes)

```sql
CREATE TABLE scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    parent_id UUID REFERENCES scopes(id),
    path LTREE NOT NULL,
    metadata JSONB DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT chk_type CHECK (type IN (
        'GLOBAL', 'COUNTRY', 'REGION', 'ORG', 
        'DEPT', 'TEAM', 'PROJECT'
    ))
);

CREATE INDEX idx_scopes_path ON scopes USING GIST(path);
CREATE INDEX idx_scopes_parent ON scopes(parent_id);
CREATE INDEX idx_scopes_type ON scopes(type);
```

**Purpose:** Organizational hierarchy representation

**Key Points:**
- Uses PostgreSQL `ltree` extension for hierarchy
- `path` format: `GLOBAL.ASIA.NEPAL.EVEREST_TRAVELS`
- `metadata` stores type-specific data (country_code, org_type)

**Sample Data:**
```sql
INSERT INTO scopes (id, type, name, parent_id, path, metadata) 
VALUES
('00000001', 'GLOBAL', 'Global', NULL, 
 'GLOBAL', '{}'),
('00000002', 'REGION', 'Asia', '00000001', 
 'GLOBAL.ASIA', '{"region_code": "ASIA"}'),
('00000003', 'COUNTRY', 'Nepal', '00000002', 
 'GLOBAL.ASIA.NEPAL', '{"country_code": "NP"}'),
('00000004', 'ORG', 'Everest Travels', '00000003', 
 'GLOBAL.ASIA.NEPAL.EVEREST_TRAVELS', 
 '{"org_type": "TRAVEL_AGENCY"}');
```

---

#### 5.2.3 scope_closure (Performance Accelerator)

```sql
CREATE TABLE scope_closure (
    ancestor_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    descendant_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    depth INT NOT NULL,
    
    PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE INDEX idx_closure_ancestor ON scope_closure(ancestor_id);
CREATE INDEX idx_closure_descendant ON scope_closure(descendant_id);
```

**Purpose:** Pre-computed transitive closure for instant "contains" checks

**How It Works:**
```
If hierarchy is: GLOBAL → ASIA → NEPAL → EVEREST_TRAVELS

Table contains:
(GLOBAL, GLOBAL, 0)              -- self-reference
(GLOBAL, ASIA, 1)                -- direct child
(GLOBAL, NEPAL, 2)               -- grandchild
(GLOBAL, EVEREST_TRAVELS, 3)     -- great-grandchild
(ASIA, ASIA, 0)
(ASIA, NEPAL, 1)
(ASIA, EVEREST_TRAVELS, 2)
(NEPAL, NEPAL, 0)
(NEPAL, EVEREST_TRAVELS, 1)
(EVEREST_TRAVELS, EVEREST_TRAVELS, 0)
```

**Query Example:**
```sql
-- Does NEPAL contain EVEREST_TRAVELS?
SELECT EXISTS (
    SELECT 1 FROM scope_closure
    WHERE ancestor_id = 'NEPAL'
    AND descendant_id = 'EVEREST_TRAVELS'
);
-- Result: TRUE (O(1) lookup!)
```

**Maintenance Trigger:**
```sql
CREATE OR REPLACE FUNCTION maintain_scope_closure()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Add self-reference
        INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
        VALUES (NEW.id, NEW.id, 0);
        
        -- Add paths from all ancestors
        INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
        SELECT ancestor_id, NEW.id, depth + 1
        FROM scope_closure
        WHERE descendant_id = NEW.parent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scope_closure_insert
AFTER INSERT ON scopes
FOR EACH ROW EXECUTE FUNCTION maintain_scope_closure();
```

---

#### 5.2.4 roles (Permission Bundles)

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT false,
    org_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT chk_org_type CHECK (org_type IN (
        'TRAVEL_AGENCY', 'RESCUE_COMPANY', 
        'INSURANCE', 'HOSPITAL', NULL
    ))
);

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_org_type ON roles(org_type);
```

**Purpose:** Reusable templates of permissions

**Key Points:**
- `is_system_role = true` prevents deletion
- `org_type` filters relevant roles per organization
- Roles are scope-agnostic (scope assigned in assignments table)

**Sample Data:**
```sql
INSERT INTO roles (name, description, is_system_role, org_type) 
VALUES
('SuperAdmin', 'Platform super administrator', true, NULL),
('CountryAdmin', 'Country-level administrator', true, NULL),
('RegionalAdmin', 'Regional administrator', true, NULL),
('TravelAgencyAdmin', 'Travel agency administrator', 
 false, 'TRAVEL_AGENCY'),
('TravelAgencyStaff', 'Travel agency staff', 
 false, 'TRAVEL_AGENCY');
```

---

#### 5.2.5 role_permissions (Role-Permission Mapping)

```sql
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT NOW(),
    
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
```

**Purpose:** Defines which permissions each role grants

**Sample Data:**
```sql
-- TravelAgencyStaff permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    (SELECT id FROM roles WHERE name = 'TravelAgencyStaff'),
    id
FROM permissions
WHERE key IN (
    'tourist.profile.create',
    'tourist.profile.read',
    'tourist.profile.update',
    'order.order.create',
    'order.order.read',
    'order.guide.assign',
    'order.device.bind'
);
```

---

#### 5.2.6 assignments (User → Role × Scope)

```sql
CREATE TABLE assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id VARCHAR(100) NOT NULL,
    subject_type VARCHAR(20) DEFAULT 'USER',
    role_id UUID NOT NULL REFERENCES roles(id),
    scope_id UUID NOT NULL REFERENCES scopes(id),
    effect VARCHAR(10) DEFAULT 'ALLOW',
    granted_by VARCHAR(100),
    granted_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    conditions JSONB DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    
    CONSTRAINT chk_effect CHECK (effect IN ('ALLOW', 'DENY')),
    CONSTRAINT chk_subject_type CHECK (subject_type IN ('USER', 'SERVICE'))
);

CREATE INDEX idx_assignments_subject ON assignments(subject_id, active);
CREATE INDEX idx_assignments_role ON assignments(role_id);
CREATE INDEX idx_assignments_scope ON assignments(scope_id);
```

**Purpose:** Connects users to roles at specific scopes

**Key Points:**
- One user can have multiple assignments
- `expires_at` enables temporary grants
- `conditions` stores JSONB for time windows, IP restrictions, etc.

**Sample Data:**
```sql
-- Ram is admin at Everest Travels
INSERT INTO assignments (subject_id, role_id, scope_id, granted_by)
VALUES (
    'user_ram',
    (SELECT id FROM roles WHERE name = 'TravelAgencyAdmin'),
    (SELECT id FROM scopes WHERE name = 'Everest Travels'),
    'system'
);

-- Hari is regional admin for Asia
INSERT INTO assignments (subject_id, role_id, scope_id, granted_by)
VALUES (
    'user_hari',
    (SELECT id FROM roles WHERE name = 'RegionalAdmin'),
    (SELECT id FROM scopes WHERE name = 'Asia'),
    'user_rajesh'
);
```

---

#### 5.2.7 deny_rules (Override Layer)

```sql
CREATE TABLE deny_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id VARCHAR(100) NOT NULL,
    permission_key VARCHAR(100) NOT NULL,
    scope_id UUID REFERENCES scopes(id),
    reason TEXT NOT NULL,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT true,
    
    FOREIGN KEY (permission_key) REFERENCES permissions(key)
);

CREATE INDEX idx_deny_rules_subject ON deny_rules(subject_id, active);
CREATE INDEX idx_deny_rules_permission ON deny_rules(permission_key);
```

**Purpose:** Explicit denials that override all ALLOW rules

**Key Points:**
- DENY always wins, regardless of role assignments
- Can be scoped (deny in specific org) or global (deny everywhere)
- Used for compliance, security incidents, suspensions

**Sample Data:**
```sql
-- Suspend user from approving orders globally
INSERT INTO deny_rules (subject_id, permission_key, scope_id, reason, created_by)
VALUES (
    'user_ram',
    'order.order.approve',
    NULL,  -- NULL = applies everywhere
    'Under investigation for policy violation',
    'user_krishna'
);
```

---

#### 5.2.8 authorization_audit (Immutable Log)

```sql
CREATE TABLE authorization_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id VARCHAR(100) NOT NULL,
    permission_key VARCHAR(100),
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),
    scope_id UUID,
    decision BOOLEAN NOT NULL,
    reason TEXT,
    context JSONB DEFAULT '{}',
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_subject ON authorization_audit(subject_id, timestamp DESC);
CREATE INDEX idx_audit_timestamp ON authorization_audit(timestamp DESC);

-- Make table immutable
CREATE RULE no_update_audit AS ON UPDATE TO authorization_audit DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO authorization_audit DO INSTEAD NOTHING;
```

**Purpose:** Complete audit trail of all authorization decisions

**Key Points:**
- Every `/authorize` call creates log entry
- Immutable (no updates or deletes)
- Partition by month for performance

**Sample Data:**
```sql
INSERT INTO authorization_audit 
(subject_id, permission_key, resource_type, resource_id, scope_id, decision, reason, context)
VALUES (
    'user_ram',
    'order.order.approve',
    'ORDER',
    'ORD_123',
    (SELECT id FROM scopes WHERE name = 'Everest Travels'),
    true,
    'ALLOW via role:TravelAgencyAdmin at scope:ORG:EVEREST_TRAVELS',
    '{"ip": "103.1.2.3", "session_id": "sess_abc"}'
);
```

---

### 5.3 Complete Schema ERD

```
permissions          role_permissions         roles
┌─────────┐         ┌──────────────┐         ┌──────────┐
│ id (PK) │◄────────┤ permission_id│         │ id (PK)  │
│ key (UK)│         │ role_id      ├────────►│ name (UK)│
│ domain  │         └──────────────┘         │ org_type │
│ resource│                                  └────┬─────┘
│ action  │                                       │
└─────────┘                                       │
                                                  │
scopes                                            │
┌──────────────┐         assignments             │
│ id (PK)      │         ┌─────────────┐         │
│ type         │◄────────┤ scope_id    │         │
│ name         │         │ subject_id  │         │
│ parent_id(FK)├─┐       │ role_id     ├─────────┘
│ path (ltree) │ │       │ effect      │
└──────┬───────┘ │       │ expires_at  │
       │         │       └─────────────┘
       │         │
       ▼         │       deny_rules
scope_closure    │       ┌──────────────┐
┌──────────────┐ │       │ id (PK)      │
│ ancestor_id  ├─┘       │ subject_id   │
│ descendant_id│◄────────┤ scope_id (FK)│
│ depth        │         │ permission   │
└──────────────┘         │ reason       │
                         └──────────────┘

authorization_audit
┌─────────────────┐
│ id (PK)         │
│ subject_id      │
│ permission_key  │
│ decision        │
│ reason          │
│ context (JSONB) │
│ timestamp       │
└─────────────────┘
```

---

## 6. Authorization Algorithm

### 6.1 Decision Flow Diagram

```
┌─────────────────────────────────────────┐
│     AUTHORIZATION REQUEST               │
│  {subject, permission, resource_scope}  │
└────────────────┬────────────────────────┘
                 │
                 ↓
┌─────────────────────────────────────────┐
│  STEP 1: CHECK DENY RULES               │
│  Any explicit DENY for this user?       │
└────────────────┬────────────────────────┘
                 │
         ┌───────┴───────┐
         │ DENY found?   │
         └───┬───────┬───┘
         YES │       │ NO
             ↓       ↓
        ┌────────┐  │
        │ RETURN │  │
        │ DENY ❌│  │
        └────────┘  │
                    ↓
        ┌────────────────────────────────┐
        │ STEP 2: FETCH USER ASSIGNMENTS │
        │ Get all active role assignments │
        └────────────┬───────────────────┘
                     │
             ┌───────┴───────┐
             │ Found any?    │
             └───┬───────┬───┘
             NO  │       │ YES
                 ↓       ↓
            ┌────────┐  │
            │ RETURN │  │
            │ DENY ❌│  │
            └────────┘  │
                        ↓
            ┌─────────────────────────────┐
            │ STEP 3: EXPAND TO PERMISSIONS│
            │ Get all permissions from roles│
            └────────────┬────────────────┘
                         │
                 ┌───────┴───────┐
                 │ Has permission?│
                 └───┬───────┬───┘
                 NO  │       │ YES
                     ↓       ↓
                ┌────────┐  │
                │ RETURN │  │
                │ DENY ❌│  │
                └────────┘  │
                            ↓
                ┌──────────────────────────┐
                │ STEP 4: CHECK SCOPE      │
                │ Does user scope contain  │
                │ resource scope?          │
                └────────────┬─────────────┘
                             │
                     ┌───────┴───────┐
                     │ Scope matches?│
                     └───┬───────┬───┘
                     NO  │       │ YES
                         ↓       ↓
                    ┌────────┐  │
                    │ RETURN │  │
                    │ DENY ❌│  │
                    └────────┘  │
                                ↓
                    ┌────────────────────────┐
                    │ STEP 5: CHECK CONDITIONS│
                    │ Time window, IP, etc.  │
                    └────────────┬───────────┘
                                 │
                         ┌───────┴───────┐
                         │ Conditions OK?│
                         └───┬───────┬───┘
                         NO  │       │ YES
                             ↓       ↓
                        ┌────────┐  │
                        │ RETURN │  │
                        │ DENY ❌│  │
                        └────────┘  │
                                    ↓
                        ┌──────────────────┐
                        │ RETURN ALLOW ✅  │
                        │ + Audit log      │
                        └──────────────────┘
```

### 6.2 Pseudocode Implementation

```python
def authorize(subject_id, permission_key, resource_scope_id, context):
    """
    Main authorization decision function
    Returns: (allowed: bool, reason: str)
    """
    
    # STEP 1: Check explicit DENY rules (highest priority)
    deny_rule = check_deny_rules(subject_id, permission_key, resource_scope_id)
    if deny_rule:
        audit_log(subject_id, permission_key, resource_scope_id, False, 
                  f"DENY via explicit rule: {deny_rule.reason}")
        return (False, deny_rule.reason)
    
    # STEP 2: Fetch active assignments
    assignments = get_active_assignments(subject_id)
    if not assignments:
        audit_log(subject_id, permission_key, resource_scope_id, False,
                  "DENY: No active assignments")
        return (False, "No permissions assigned")
    
    # STEP 3: Expand roles to permissions
    permissions = expand_roles_to_permissions(assignments)
    if permission_key not in permissions:
        audit_log(subject_id, permission_key, resource_scope_id, False,
                  "DENY: Permission not granted by any role")
        return (False, "Insufficient permissions")
    
    # STEP 4: Check scope containment
    valid_scopes = filter_assignments_by_scope(assignments, resource_scope_id)
    if not valid_scopes:
        audit_log(subject_id, permission_key, resource_scope_id, False,
                  "DENY: Scope mismatch")
        return (False, "Access denied: scope mismatch")
    
    # STEP 5: Evaluate conditions (ABAC)
    for assignment in valid_scopes:
        if evaluate_conditions(assignment.conditions, context):
            reason = f"ALLOW via role:{assignment.role_name} at scope:{assignment.scope_id}"
            audit_log(subject_id, permission_key, resource_scope_id, True, reason)
            return (True, reason)
    
    audit_log(subject_id, permission_key, resource_scope_id, False,
              "DENY: Conditions not met")
    return (False, "Conditional access denied")
```

### 6.3 SQL Query Example

```sql
-- Single query authorization check
WITH user_assignments AS (
    SELECT a.role_id, a.scope_id, r.name as role_name
    FROM assignments a
    JOIN roles r ON r.id = a.role_id
    WHERE a.subject_id = :subject_id
    AND a.active = true
    AND (a.expires_at IS NULL OR a.expires_at > NOW())
),
user_permissions AS (
    SELECT DISTINCT p.key
    FROM user_assignments ua
    JOIN role_permissions rp ON rp.role_id = ua.role_id
    JOIN permissions p ON p.id = rp.permission_id
),
scope_check AS (
    SELECT EXISTS (
        SELECT 1
        FROM user_assignments ua
        JOIN scope_closure sc ON sc.ancestor_id = ua.scope_id
        WHERE sc.descendant_id = :resource_scope_id
    ) AS has_scope
),
deny_check AS (
    SELECT EXISTS (
        SELECT 1
        FROM deny_rules dr
        WHERE dr.subject_id = :subject_id
        AND dr.permission_key = :permission_key
        AND dr.active = true
        AND (dr.scope_id IS NULL OR dr.scope_id IN (
            SELECT ancestor_id FROM scope_closure 
            WHERE descendant_id = :resource_scope_id
        ))
    ) AS is_denied
)
SELECT 
    (SELECT COUNT(*) FROM user_permissions WHERE key = :permission_key) > 0 AS has_permission,
    (SELECT has_scope FROM scope_check) AS has_scope,
    (SELECT is_denied FROM deny_check) AS is_denied;
```

---

## 7. Permission Catalog

### 7.1 Tourist Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `tourist.profile.create` | Create new tourist profile | TravelAgencyStaff, SalesAgencyStaff |
| `tourist.profile.read` | View tourist details | All staff, All admins |
| `tourist.profile.update` | Edit tourist information | TravelAgencyStaff, SalesAgencyStaff |
| `tourist.profile.delete` | Remove tourist profile | OrgAdmin, RegionalAdmin+ |
| `tourist.profile.export` | Export tourist data | OrgAdmin, RegionalAdmin+ |

### 7.2 Order Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `order.order.create` | Create new order | TravelAgencyStaff, SalesAgencyStaff |
| `order.order.read` | View order details | All staff, All admins |
| `order.order.update` | Modify order | TravelAgencyStaff |
| `order.order.approve` | Approve order | OrgAdmin (Travel Agency) |
| `order.order.cancel` | Cancel order | OrgAdmin, Customer (owner) |
| `order.order.delete` | Delete order | RegionalAdmin+ |
| `order.guide.assign` | Assign guide to order | TravelAgencyStaff |
| `order.guide.reassign` | Change assigned guide | OrgAdmin |
| `order.device.bind` | Bind device to order | TravelAgencyStaff |
| `order.device.unbind` | Remove device | OrgAdmin |
| `order.statistics.view` | View order analytics | OrgAdmin, RegionalAdmin+ |

### 7.3 Rescue Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `rescue.sos.create` | Trigger SOS alert | Tourist, Anyone (emergency) |
| `rescue.sos.view` | View SOS alerts | RescueCenterDispatcher, RegionalAdmin+ |
| `rescue.sos.handle` | Respond to SOS | RescueCenterDispatcher |
| `rescue.order.create` | Create rescue mission | RescueCenterDispatcher |
| `rescue.order.assign` | Assign rescue company | RescueCenterDispatcher |
| `rescue.order.accept` | Accept rescue mission | RescueCompanyOperator |
| `rescue.order.reject` | Decline rescue mission | RescueCompanyOperator |
| `rescue.status.update` | Update rescue status | RescueCompanyOperator (if assigned) |
| `rescue.progress.update` | Add progress notes | RescueCompanyOperator (if assigned) |
| `rescue.progress.view` | View rescue progress | All admins, Tourist (own) |

### 7.4 Insurance Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `insurance.policy.create` | Create insurance policy | InsuranceOperator |
| `insurance.policy.read` | View policy details | InsuranceOperator, Tourist (own) |
| `insurance.policy.approve` | Approve policy | InsuranceReviewer |
| `insurance.claim.create` | File insurance claim | Tourist (own), InsuranceOperator |
| `insurance.claim.review` | Review claim | InsuranceReviewer |
| `insurance.claim.approve` | Approve claim payment | InsuranceReviewer |
| `insurance.claim.reject` | Deny claim | InsuranceReviewer |
| `insurance.compensation.view` | View compensation stats | OrgAdmin, RegionalAdmin+ |

### 7.5 Finance Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `finance.invoice.create` | Generate invoice | OrgAdmin, FinanceOfficer |
| `finance.invoice.read` | View invoices | OrgAdmin, FinanceOfficer, RegionalAdmin+ |
| `finance.invoice.approve` | Approve invoice | FinanceOfficer |
| `finance.payment.execute` | Process payment | FinanceOfficer |
| `finance.payment.view` | View payment history | OrgAdmin, RegionalAdmin+ |
| `finance.income.view` | View revenue reports | OrgAdmin, RegionalAdmin+ |
| `finance.commission.calculate` | Calculate commissions | FinanceOfficer, CountryAdmin+ |

### 7.6 Organization Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `org.company.create` | Register new company | RegionalAdmin+ |
| `org.company.read` | View company details | All admins |
| `org.company.update` | Update company info | OrgAdmin (own), RegionalAdmin+ |
| `org.company.approve` | Approve company registration | RegionalAdmin+ |
| `org.company.suspend` | Suspend company | CountryAdmin+ |
| `org.employee.create` | Add employee | OrgAdmin |
| `org.employee.update` | Edit employee details | OrgAdmin |
| `org.employee.delete` | Remove employee | OrgAdmin |
| `org.role.assign` | Assign roles to users | OrgAdmin (limited), RegionalAdmin+ |

### 7.7 Platform Domain

| Permission | Description | Required By |
|------------|-------------|-------------|
| `platform.country.create` | Add new country | SuperAdmin |
| `platform.region.create` | Add new region | CountryAdmin+ |
| `platform.analytics.global.view` | View global dashboards | SuperAdmin |
| `platform.analytics.country.view` | View country analytics | CountryAdmin+ |
| `platform.analytics.region.view` | View regional analytics | RegionalAdmin+ |
| `platform.audit.view` | View audit logs | SuperAdmin, CountryAdmin+ |
| `platform.config.update` | Update platform settings | SuperAdmin |

---

## 8. Role Definitions

### 8.1 System Roles

#### SuperAdmin

```yaml
name: SuperAdmin
description: Platform super administrator
is_system_role: true
scope_assignment: GLOBAL

permissions:
  - platform.*.* (all platform operations)
  - org.*.* (all organization management)
  - All domain permissions for oversight
```

#### CountryAdmin

```yaml
name: CountryAdmin
description: Country-level administrator
is_system_role: true
scope_assignment: COUNTRY:{country_id}

permissions:
  - org.company.create
  - org.company.approve
  - org.company.read
  - org.employee.read
  - platform.region.create
  - platform.analytics.country.view
  - platform.audit.view
  - All read permissions for country data
```

#### RegionalAdmin

```yaml
name: RegionalAdmin
description: Regional administrator
is_system_role: true
scope_assignment: REGION:{region_id}

permissions:
  - org.company.create
  - org.company.approve
  - org.company.update
  - org.role.assign (org-level only)
  - platform.analytics.region.view
  - All read permissions for regional data
```

---

### 8.2 Organization-Specific Roles

#### TravelAgencyAdmin

```yaml
name: TravelAgencyAdmin
description: Travel agency administrator
org_type: TRAVEL_AGENCY
scope_assignment: ORG:{travel_agency_id}

permissions:
  # Tourist management (full)
  - tourist.profile.create
  - tourist.profile.read
  - tourist.profile.update
  - tourist.profile.delete
  
  # Order management (full)
  - order.order.create
  - order.order.read
  - order.order.update
  - order.order.approve
  - order.order.cancel
  - order.guide.assign
  - order.guide.reassign
  - order.device.bind
  - order.device.unbind
  - order.statistics.view
  
  # Employee management
  - org.employee.create
  - org.employee.update
  - org.employee.delete
  - org.role.assign
  
  # Finance (read + limited write)
  - finance.invoice.create
  - finance.invoice.read
  - finance.payment.view
  - finance.income.view
```

#### TravelAgencyStaff

```yaml
name: TravelAgencyStaff
description: Travel agency staff member
org_type: TRAVEL_AGENCY
scope_assignment: ORG:{travel_agency_id}

permissions:
  # Tourist management (limited)
  - tourist.profile.create
  - tourist.profile.read
  - tourist.profile.update
  
  # Order management (basic)
  - order.order.create
  - order.order.read
  - order.order.update
  - order.guide.assign
  - order.device.bind
  
  # Finance (read-only)
  - finance.invoice.read
```

#### RescueCenterDispatcher

```yaml
name: RescueCenterDispatcher
description: Rescue center dispatcher
org_type: RESCUE_COMPANY
scope_assignment: REGION:{region_id}

permissions:
  # SOS handling
  - rescue.sos.view
  - rescue.sos.handle
  
  # Rescue order management
  - rescue.order.create
  - rescue.order.assign
  - rescue.order.read
  
  # Progress tracking
  - rescue.progress.view
```

#### RescueOperator

```yaml
name: RescueOperator
description: Rescue company field operator
org_type: RESCUE_COMPANY
scope_assignment: ORG:{rescue_company_id}

permissions:
  # Rescue order handling (only assigned)
  - rescue.order.read
  - rescue.order.accept
  - rescue.order.reject
  - rescue.status.update
  - rescue.progress.update
```

---

## 9. API Specifications

### 9.1 Authorization Endpoint

**POST** `/api/v1/authorize`

Checks if a subject can perform an action on a resource.

**Request:**
```json
{
  "subject": "user_ram",
  "permission": "order.order.approve",
  "resource": {
    "type": "ORDER",
    "id": "ORD_123",
    "scopeId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "metadata": {
      "ownerId": "user_sita",
      "status": "PENDING"
    }
  },
  "context": {
    "timestamp": "2026-01-22T14:30:00Z",
    "ipAddress": "103.1.2.3",
    "userAgent": "Mozilla/5.0",
    "sessionId": "sess_abc123"
  }
}
```

**Response (Success):**
```json
{
  "authorized": true,
  "reason": "ALLOW via role:TravelAgencyAdmin at scope:ORG:EVEREST_TRAVELS",
  "effectivePermissions": [
    "order.order.approve",
    "order.order.cancel",
    "order.order.update"
  ],
  "auditId": "aud_9876543210",
  "timestamp": "2026-01-22T14:30:00.123Z"
}
```

**Response (Denied):**
```json
{
  "authorized": false,
  "reason": "DENY: No assignment scope contains resource scope",
  "auditId": "aud_9876543211",
  "timestamp": "2026-01-22T14:30:00.456Z"
}
```

---

### 9.2 Permission Management

**GET** `/api/v1/permissions`

List all permissions (filterable by domain).

**Query Parameters:**
- `domain` (optional): Filter by domain (e.g., "order", "rescue")
- `page` (optional): Page number
- `size` (optional): Page size

**Response:**
```json
{
  "permissions": [
    {
      "id": "perm_uuid",
      "key": "order.order.approve",
      "domain": "order",
      "resource": "order",
      "action": "approve",
      "description": "Approve travel order",
      "createdAt": "2026-01-01T00:00:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "size": 50
}
```

---

**POST** `/api/v1/permissions`

Create new permission (SuperAdmin only).

**Request:**
```json
{
  "key": "medical.record.create",
  "domain": "medical",
  "resource": "record",
  "action": "create",
  "description": "Create medical record"
}
```

**Response:**
```json
{
  "id": "perm_new_uuid",
  "key": "medical.record.create",
  "domain": "medical",
  "resource": "record",
  "action": "create",
  "description": "Create medical record",
  "createdAt": "2026-01-22T14:30:00Z"
}
```

---

### 9.3 Role Management

**GET** `/api/v1/roles`

List all roles.

**GET** `/api/v1/roles/{roleId}`

Get role details including permissions.

**Response:**
```json
{
  "id": "role_uuid",
  "name": "TravelAgencyAdmin",
  "description": "Travel agency administrator",
  "orgType": "TRAVEL_AGENCY",
  "isSystemRole": false,
  "permissions": [
    "tourist.profile.create",
    "order.order.approve",
    "org.employee.create"
  ],
  "createdAt": "2026-01-01T00:00:00Z"
}
```

---

**POST** `/api/v1/roles`

Create new role.

**Request:**
```json
{
  "name": "HospitalDoctor",
  "description": "Doctor at hospital",
  "orgType": "HOSPITAL",
  "permissions": [
    "medical.record.create",
    "medical.record.update",
    "medical.prescription.issue"
  ]
}
```

---

**PUT** `/api/v1/roles/{roleId}/permissions`

Update role permissions.

**Request:**
```json
{
  "permissions": [
    "medical.record.create",
    "medical.record.update",
    "medical.prescription.issue",
    "medical.diagnosis.create"
  ]
}
```

---

### 9.4 Assignment Management

**POST** `/api/v1/assignments`

Assign role to user at scope.

**Request:**
```json
{
  "subjectId": "user_ram",
  "subjectType": "USER",
  "roleId": "role_uuid",
  "scopeId": "scope_uuid",
  "expiresAt": "2027-01-22T00:00:00Z",
  "conditions": {
    "timeWindow": "09:00-17:00",
    "ipRanges": ["103.0.0.0/8"]
  }
}
```

**Response:**
```json
{
  "id": "assignment_uuid",
  "subjectId": "user_ram",
  "roleId": "role_uuid",
  "scopeId": "scope_uuid",
  "effect": "ALLOW",
  "grantedBy": "user_admin",
  "grantedAt": "2026-01-22T14:30:00Z",
  "expiresAt": "2027-01-22T00:00:00Z",
  "active": true
}
```

---

**GET** `/api/v1/assignments?subjectId=user_ram`

List user's assignments.

**DELETE** `/api/v1/assignments/{assignmentId}`

Revoke assignment.

---

### 9.5 Scope Management

**POST** `/api/v1/scopes`

Create new scope.

**Request:**
```json
{
  "type": "ORG",
  "name": "New Hospital",
  "parentId": "region_uuid",
  "metadata": {
    "orgType": "HOSPITAL",
    "licenseNumber": "HOSP-2026-001",
    "address": "Kathmandu, Nepal"
  }
}
```

**Response:**
```json
{
  "id": "scope_new_uuid",
  "type": "ORG",
  "name": "New Hospital",
  "parentId": "region_uuid",
  "path": "GLOBAL.ASIA.NEPAL.NEW_HOSPITAL",
  "metadata": {
    "orgType": "HOSPITAL",
    "licenseNumber": "HOSP-2026-001"
  },
  "active": true,
  "createdAt": "2026-01-22T14:30:00Z"
}
```

---

**GET** `/api/v1/scopes/{scopeId}/descendants`

Get all descendants of a scope.

**Response:**
```json
{
  "scope": {
    "id": "asia_uuid",
    "name": "Asia",
    "type": "REGION"
  },
  "descendants": [
    {
      "id": "everest_uuid",
      "name": "Everest Travels",
      "type": "ORG",
      "depth": 1
    },
    {
      "id": "mountain_uuid",
      "name": "Mountain Rescue",
      "type": "ORG",
      "depth": 1
    }
  ]
}
```

---

## 10. Integration Guide

### 10.1 Service Integration Pattern

**Every microservice MUST check authorization before business logic.**

#### Java/Spring Boot Example

```java
@Service
public class OrderService {
    
    @Autowired
    private AuthorizationClient authClient;
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Transactional
    public Order approveOrder(String orderId, User currentUser) {
        // 1. Fetch order
        Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NotFoundException("Order not found"));
        
        // 2. AUTHORIZATION CHECK (MANDATORY)
        AuthorizationRequest authReq = AuthorizationRequest.builder()
            .subject(currentUser.getId())
            .permission("order.order.approve")
            .resource(AuthResource.builder()
                .type("ORDER")
                .id(orderId)
                .scopeId(order.getOrganizationId())
                .metadata(Map.of(
                    "ownerId", order.getCreatedBy(),
                    "status", order.getStatus()
                ))
                .build())
            .context(AuthContext.builder()
                .timestamp(Instant.now())
                .ipAddress(getCurrentIpAddress())
                .sessionId(currentUser.getSessionId())
                .build())
            .build();
        
        AuthorizationResponse authResp = authClient.authorize(authReq);
        
        if (!authResp.isAuthorized()) {
            throw new ForbiddenException(authResp.getReason());
        }
        
        // 3. BUSINESS LOGIC (only after authorization passes)
        order.setStatus(OrderStatus.APPROVED);
        order.setApprovedBy(currentUser.getId());
        order.setApprovedAt(Instant.now());
        
        return orderRepository.save(order);
    }
}
```

---

#### Node.js/Express Example

```javascript
const authClient = require('./lib/authClient');

async function approveOrder(req, res) {
    const { orderId } = req.params;
    const currentUser = req.user;
    
    try {
        // 1. Fetch order
        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        // 2. AUTHORIZATION CHECK (MANDATORY)
        const authResult = await authClient.authorize({
            subject: currentUser.id,
            permission: 'order.order.approve',
            resource: {
                type: 'ORDER',
                id: orderId,
                scopeId: order.organizationId,
                metadata: {
                    ownerId: order.createdBy,
                    status: order.status
                }
            },
            context: {
                timestamp: new Date().toISOString(),
                ipAddress: req.ip,
                sessionId: req.sessionID
            }
        });
        
        if (!authResult.authorized) {
            return res.status(403).json({ 
                error: 'Access denied',
                reason: authResult.reason 
            });
        }
        
        // 3. BUSINESS LOGIC (only after authorization)
        order.status = 'APPROVED';
        order.approvedBy = currentUser.id;
        order.approvedAt = new Date();
        
        await order.save();
        
        return res.json({ 
            success: true, 
            order,
            auditId: authResult.auditId
        });
        
    } catch (error) {
        console.error('Error approving order:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}

module.exports = { approveOrder };
```

---

### 10.2 Frontend Integration

**React Example:**

```jsx
import { useAuth } from './hooks/useAuth';
import { hasPermission } from './utils/permissions';

function OrderDetailsPage({ orderId }) {
    const { user, permissions, scopes } = useAuth();
    const [order, setOrder] = useState(null);
    const [loading, setLoading] = useState(false);
    
    useEffect(() => {
        fetchOrder(orderId).then(setOrder);
    }, [orderId]);
    
    // Check permission (UI only - backend still enforces)
    const canApprove = hasPermission(
        permissions,
        'order.order.approve',
        order?.organizationId,
        scopes
    );
    
    const canCancel = hasPermission(
        permissions,
        'order.order.cancel',
        order?.organizationId,
        scopes
    );
    
    const handleApprove = async () => {
        setLoading(true);
        try {
            await api.post(`/orders/${orderId}/approve`);
            toast.success('Order approved successfully');
            // Refresh order
            const updated = await fetchOrder(orderId);
            setOrder(updated);
        } catch (error) {
            if (error.status === 403) {
                toast.error('You do not have permission to approve this order');
            } else {
                toast.error('Failed to approve order');
            }
        } finally {
            setLoading(false);
        }
    };
    
    return (
        <div className="order-details">
            <h1>Order #{order?.id}</h1>
            <div className="order-info">
                <p>Status: {order?.status}</p>
                <p>Created by: {order?.createdBy}</p>
                <p>Amount: ${order?.amount}</p>
            </div>
            
            <div className="actions">
                {/* Conditional UI rendering based on permissions */}
                {canApprove && order?.status === 'PENDING' && (
                    <button 
                        onClick={handleApprove}
                        disabled={loading}
                        className="btn-primary"
                    >
                        {loading ? 'Approving...' : 'Approve Order'}
                    </button>
                )}
                
                {canCancel && order?.status !== 'CANCELLED' && (
                    <button 
                        onClick={handleCancel}
                        className="btn-danger"
                    >
                        Cancel Order
                    </button>
                )}
            </div>
        </div>
    );
}
```

**Important:** Frontend checks are for **UX only**. Backend MUST always enforce authorization.

---

## 11. Implementation Roadmap

### Sprint 0: Foundation (2 weeks)

**Goal:** Core infrastructure operational

**Deliverables:**
- ✅ PostgreSQL database created
- ✅ All tables and indexes
- ✅ IAM service skeleton
- ✅ `/authorize` endpoint (basic RBAC)
- ✅ Unit tests

**Tasks:**
1. Setup PostgreSQL 14+ with ltree extension
2. Execute schema DDL scripts
3. Create scope closure triggers
4. Implement authorization algorithm
5. Seed sample permissions/roles/scopes
6. Write unit tests (80% coverage target)

---

### Sprint 1: Organization Hierarchy (1 week)

**Goal:** Multi-level scope support

**Deliverables:**
- ✅ Scope management APIs
- ✅ Hierarchy queries working
- ✅ System roles created
- ✅ Integration tests

**Tasks:**
1. Implement scope CRUD APIs
2. Test ltree path queries
3. Create default scope tree (Global → Asia → Nepal)
4. Assign SuperAdmin, CountryAdmin, RegionalAdmin roles
5. Test scope containment queries

---

### Sprint 2: Travel & Order Domain (1.5 weeks)

**Goal:** Core business domain operational

**Deliverables:**
- ✅ Tourist & Order permissions
- ✅ Travel agency roles
- ✅ Order service integration
- ✅ End-to-end tests

**Tasks:**
1. Create tourist/order domain permissions
2. Create TravelAgencyAdmin and TravelAgencyStaff roles
3. Integrate order-service with IAM
4. Test: Admin at Company A cannot see Company B data
5. Performance test: 1000 req/sec authorization checks

---

### Sprint 3: Rescue Domain (2 weeks)

**Goal:** Critical rescue operations

**Deliverables:**
- ✅ Rescue permissions
- ✅ Rescue roles
- ✅ Assignment-based access (ReBAC)
- ✅ Rescue service integration

**Tasks:**
1. Create rescue domain permissions
2. Create RescueCenterDispatcher and RescueOperator roles
3. Implement policy: "only assigned operator can update status"
4. Integrate rescue-service with IAM
5. Test rescue workflows end-to-end

---

### Sprint 4: Insurance & Finance (1.5 weeks)

**Goal:** Financial operations support

**Deliverables:**
- ✅ Insurance & Finance permissions
- ✅ Insurance & Finance roles
- ✅ Service integrations

**Tasks:**
1. Create insurance/finance permissions
2. Create InsuranceReviewer, FinanceOfficer roles
3. Implement dual-approval for large payments
4. Integrate services with IAM

---

### Sprint 5: DENY Rules & Policies (1 week)

**Goal:** Advanced security features

**Deliverables:**
- ✅ DENY rules engine
- ✅ Condition evaluation (time, IP)
- ✅ Admin UI for DENY rules

**Tasks:**
1. Implement DENY rule evaluation
2. Implement time window conditions
3. Implement IP range conditions
4. Test: DENY always overrides ALLOW
5. Create admin interface for managing DENY rules

---

### Sprint 6: Performance & Caching (1 week)

**Goal:** Production-ready performance

**Deliverables:**
- ✅ Redis caching layer
- ✅ JWT optimization
- ✅ Performance benchmarks met

**Tasks:**
1. Setup Redis cluster
2. Cache user permission sets (TTL: 5 min)
3. Cache scope hierarchy (TTL: 1 hour)
4. Implement JWT with embedded scopes
5. Load test: 10,000 req/sec target

---

### Sprint 7+: Future Platforms

**Goal:** Demonstrate extensibility

**Example: Hospital Platform**
- Create medical domain permissions
- Create HospitalDoctor, HospitalNurse roles
- **No schema changes required** ✅
- Plug-and-play with existing system

---

## 12. Performance & Security

### 12.1 Caching Strategy

| Data Type | TTL | Cache Key | Invalidation |
|-----------|-----|-----------|--------------|
| User permissions | 5 min | `perms:user:{id}` | Assignment change |
| Scope hierarchy | 1 hour | `scope:closure:{id}` | Scope creation/deletion |
| Role permissions | 1 hour | `role:perms:{id}` | Role update |
| DENY rules | 1 min | `deny:user:{id}` | DENY rule change |

---

### 12.2 Database Indexes

```sql
-- Critical for performance
CREATE INDEX idx_assignments_subject_active 
ON assignments(subject_id, active) WHERE active = true;

CREATE INDEX idx_closure_lookup 
ON scope_closure(ancestor_id, descendant_id);

CREATE INDEX idx_audit_subject_time 
ON authorization_audit(subject_id, timestamp DESC);

CREATE INDEX idx_deny_active 
ON deny_rules(subject_id, active) WHERE active = true;
```

---

### 12.3 Performance Targets

| Metric | Target | Measured At |
|--------|--------|-------------|
| Authorization latency (cached) | < 10ms | p95 |
| Authorization latency (uncached) | < 50ms | p95 |
| Throughput | 10,000 req/sec | Sustained |
| Cache hit rate | > 95% | Average |
| Database connections | < 100 | Per instance |

---

### 12.4 Security Best Practices

**DENY Rules:**
- Use for emergency access revocation
- Always provide clear reason
- Set expiration where appropriate
- Monitor DENY rule usage

**Audit Logs:**
- Retain for minimum 7 years
- Partition by month
- Never delete (immutable)
- Regular compliance reviews

**JWT Tokens:**
- Short expiry (max 1 hour)
- Include permissions hash
- Re-validate critical actions
- Revoke on assignment changes

**Rate Limiting:**
- 1000 req/min per user
- 100 failed authz/min per user
- 10,000 req/min per service

---

## 13. Conclusion

This authorization system provides:

✅ **Centralized control** - Single source of truth  
✅ **Multi-tenant isolation** - Complete data separation  
✅ **Hierarchical scopes** - Unlimited organizational depth  
✅ **Fine-grained permissions** - Precise access control  
✅ **Performance optimized** - 10,000+ req/sec capability  
✅ **Future-proof** - Add new platforms without redesign  
✅ **Audit compliant** - Complete decision trail  
✅ **Battle-tested patterns** - Industry best practices

**Key Principle:** Build this exact system, and you will never redesign authorization again.

---

**Document Version:** 1.0  
**Last Updated:** January 22, 2
