# iam-console

Standalone web console for the Spring IAM service — a single React app that
serves **both** audiences from one build:

- **Administrators** manage scopes, roles, assignments, deny rules, policies,
  grants, groups, services, and audit.
- **Regular users** see their own access, sessions, and security settings.

There is no separate admin build. What a user can see is decided entirely by
their **permissions** (bootstrapped from the API), never by role-name branching.

---

## Hard boundary: this app is a black-box REST consumer

- It talks to IAM **only** over the public HTTP API (`VITE_API_BASE_URL`).
- It never imports Java code, never touches the database, and holds no secrets.
- It is **not** part of the Spring Boot / Maven build and is **not** served from
  the jar. It builds and deploys on its own (see below). The root
  `.dockerignore` keeps it out of the Java image.

---

## Stack

React 19 + TypeScript · Vite · TanStack Query/Router/Table · Tailwind + shadcn/ui ·
react-hook-form + zod · Playwright (e2e). See [`../docs/UI_PLAN.md`](../docs/UI_PLAN.md).

---

## Develop

```bash
cp .env.example .env        # set VITE_API_BASE_URL (default http://localhost:8080)
npm install
npm run dev                 # Vite dev server on http://localhost:5173
```

The Java service must be running (see the repo README). CORS on the API already
allows `http://localhost:3000` and `:8080`; add your dev origin
(`http://localhost:5173`) to `CORS_ALLOWED_ORIGINS` if needed.

## Build & run standalone (separate from the Java stack)

```bash
# Static build
npm run build               # → dist/

# Or containerized (nginx serving the static build), on its own:
docker build -t iam-console web/
docker run -p 3000:80 -e API_BASE_URL=http://localhost:8080 iam-console

# Or via the dedicated compose file (does NOT start Postgres/Redis/IAM):
docker compose -f web/docker-compose.web.yml up
```

The main `docker-compose.yml` at the repo root intentionally does **not**
include this app — the backend and frontend deploy independently.

---

## Generating the app

The initial app is scaffolded from the prompt in the project chat (Lovable /
any React generator). Drop the generated Vite project into this directory,
keeping `package.json`, `src/`, and `index.html` here. Then wire the API client
to `import.meta.env.VITE_API_BASE_URL`.
