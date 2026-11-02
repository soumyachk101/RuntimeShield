# RuntimeShield web console — static build + nginx fronting the control plane.
#
# web/package.json declares plain npm scripts ("build": "tsc -b && vite build")
# and there is no lockfile or packageManager field (no pnpm-lock.yaml, no
# yarn.lock, no package-lock.json in the repo today), so this is an npm build.
# All build steps happen at image build time; the final stage is a static
# nginx with NO client-side build at container runtime.
#
# Build from the product root (compose build context):
#   docker build -f web/Dockerfile .
#
# NOTE: web/index.html references /src/main.tsx, but src/main.tsx does not
# exist yet (screens/components/styles are still empty in this checkout).
# Until the web console is finished, `npm run build` will fail on the missing
# entry point. See deploy/NOTES-AND-GAPS.md (gap: web-console-incomplete).

# --- stage 1: static build ----------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app
# Install then build; the lock file is committed alongside by the repo.
COPY web/package.json ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- stage 2: nginx fronting the control plane --------------------------------
FROM nginx:1.27-alpine
# Copy the console build (vite outputs to web/dist -> /app/dist).
COPY --from=build /app/dist /usr/share/nginx/html
# nginx.conf ships at deploy/nginx.conf (product root); it reverse-proxies
# /v1/ to the control-plane service (web client's API base is /v1, see
# web/src/lib/api.ts — NOT /api/; see deploy/NOTES-AND-GAPS.md).
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
