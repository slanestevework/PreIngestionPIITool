# Deploy FastAPI to OpenShift (First-Time Guide)

This project now includes a production container file (`Dockerfile`) for the FastAPI app in `api.py`.

## Option A (Recommended): OpenShift Web Console from Git

1. Push this repository to GitHub, GitLab, or your enterprise Git server.
2. In OpenShift, switch to **Developer** view.
3. Select **+Add** then **Import from Git**.
4. Paste your repository URL.
5. Build strategy:
   - Choose **Dockerfile** (OpenShift detects the `Dockerfile` in this repo).
6. App settings:
   - Name: `pii-scanner-api`
   - Target port: `8000`
   - Create route: enabled
7. Environment variable:
   - Add `PII_SCANNER_API_KEY` with your key value (or leave unset to disable API key auth).
8. Click **Create**.

OpenShift will build the image, deploy a pod, expose a route, and keep it running.

## Option B: CLI Flow (oc)

Prereq:
- Install `oc` CLI.
- Log in using your OpenShift cluster URL and token from the web console.

```powershell
oc login --token=<your-token> --server=<your-api-server>
oc project <your-project>
```

Create a secret for API key protection:

```powershell
oc create secret generic pii-scanner-secret --from-literal=api-key="change-me"
```

Start an app from Git and Dockerfile:

```powershell
oc new-app <your-git-repo-url> --name=pii-scanner-api --strategy=docker
oc expose service pii-scanner-api
```

Set container port and env var if needed:

```powershell
oc set env deployment/pii-scanner-api PII_SCANNER_API_KEY=change-me
oc set probe deployment/pii-scanner-api --readiness --get-url=http://:8000/health --initial-delay-seconds=10
oc set probe deployment/pii-scanner-api --liveness --get-url=http://:8000/health --initial-delay-seconds=30
```

Get public URL:

```powershell
oc get route pii-scanner-api
```

## Verify Deployment

Health check:

```powershell
curl https://<your-route>/health
```

If API key is enabled, include header `x-api-key` in client requests.

## Notes

- Use at least 1 Gi memory request for pandas + Presidio workloads.
- Scale replicas after initial validation:

```powershell
oc scale deployment/pii-scanner-api --replicas=2
```

- Trigger rebuild after code changes by pushing to your Git repo, then:

```powershell
oc start-build pii-scanner-api
```