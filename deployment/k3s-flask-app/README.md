# k3s Kubernetes Flask App Deployment

Deploy a Flask application on k3s (Lightweight Kubernetes) with Envoy proxy sidecar.

## Overview

This is a **separate project** demonstrating a simple Flask web application running on k3s with:
- **Flask App**: Running on port 8080
- **Envoy Proxy**: Sidecar proxy on port 10000
- **Kubernetes**: Full manifest with deployment, service, and configmap

## Architecture

```
Internet → NodePort 30080
            ↓
        k3s Service (packitty-svc)
            ↓
    Kubernetes Pod (packitty-demo namespace)
        ├── Container: app (port 8080)
        └── Container: envoy (port 10000)
            ↓
        Envoy forwards traffic to Flask app
```

## Files

- **app/Dockerfile** - Flask application container image
- **app/main.py** - Flask application source code
- **app/requirements.txt** - Python dependencies
- **envoy/envoy.yaml** - Envoy proxy configuration
- **k8s/manifest.yaml** - Complete Kubernetes manifest

## Prerequisites

- k3s installed on Ubuntu/Linux (or local k3s cluster)
- `kubectl` configured
- Docker (for building app image)
- Sufficient disk space

## Quick Start

### 1. Build Docker Image

```bash
cd deployment/k3s-flask-app
docker build -t packitty/app:v1 app/
```

### 2. Load Image into k3s

```bash
# If using local k3s
docker run -d --name k3s-server \
  -p 6443:6443 \
  -p 80:80 \
  -p 8080:8080 \
  -p 10000:10000 \
  rancher/k3s:latest server

# Load image
docker load < packitty-app-v1.tar
```

### 3. Deploy to Kubernetes

```bash
# Apply manifest
kubectl apply -f k8s/manifest.yaml

# Check deployment status
kubectl -n packitty-demo get pods
kubectl -n packitty-demo get svc

# Wait for pods to be ready
kubectl -n packitty-demo wait --for=condition=ready pod -l app=packitty --timeout=300s
```

### 4. Access Application

**Internal (from k3s):**
```bash
curl http://127.0.0.1:10000/
```

**External (NodePort):**
```bash
curl http://<cluster-ip>:30080/
```

**Expected Response:**
```json
{
  "client": "127.0.0.1",
  "msg": "Hello from App via Envoy!"
}
```

## Configuration

### Flask App Configuration
Edit `app/main.py` to modify:
- Port (default: 8080)
- Response message
- Routes and endpoints

### Envoy Proxy Configuration
Edit `envoy/envoy.yaml` to modify:
- Listener port (default: 10000)
- Route configuration
- Upstream cluster settings
- Admin port (default: 9901)

### Kubernetes Configuration
Edit `k8s/manifest.yaml` to modify:
- Replica count
- Container images
- Resource limits
- Service type and ports
- Namespace

## Deployment Management

### Check Status
```bash
# List pods
kubectl -n packitty-demo get pods -o wide

# Check pod logs
kubectl -n packitty-demo logs <pod-name> -c app
kubectl -n packitty-demo logs <pod-name> -c envoy

# Describe pod
kubectl -n packitty-demo describe pod <pod-name>

# Check service
kubectl -n packitty-demo get svc
kubectl -n packitty-demo describe svc packitty-svc
```

### Scale Deployment
```bash
# Scale to N replicas
kubectl -n packitty-demo scale deployment app-with-envoy --replicas=3

# Watch rollout
kubectl -n packitty-demo rollout status deployment/app-with-envoy
```

### Update Image
```bash
# Build new image
docker build -t packitty/app:v2 app/

# Update deployment
kubectl -n packitty-demo set image \
  deployment/app-with-envoy \
  app=packitty/app:v2

# Watch rollout
kubectl -n packitty-demo rollout status deployment/app-with-envoy
```

### Rollback Deployment
```bash
# View history
kubectl -n packitty-demo rollout history deployment/app-with-envoy

# Rollback to previous version
kubectl -n packitty-demo rollout undo deployment/app-with-envoy

# Rollback to specific revision
kubectl -n packitty-demo rollout undo deployment/app-with-envoy --to-revision=1
```

## Cleanup

### Remove Deployment
```bash
# Delete manifest
kubectl delete -f k8s/manifest.yaml

# Verify removal
kubectl -n packitty-demo get pods
```

### Remove Namespace
```bash
# Delete entire namespace
kubectl delete namespace packitty-demo
```

## Troubleshooting

### Pods Won't Start
```bash
# Check pod events
kubectl -n packitty-demo describe pod <pod-name>

# View logs
kubectl -n packitty-demo logs <pod-name> --previous
```

### ImagePullBackOff
```bash
# Ensure image is loaded into k3s
docker images | grep packitty

# If missing, rebuild and load
docker build -t packitty/app:v1 app/
```

### Can't Connect to Service
```bash
# Check service endpoints
kubectl -n packitty-demo get endpoints

# Check port forwarding
kubectl -n packitty-demo port-forward svc/packitty-svc 10000:10000

# Test connection
curl http://127.0.0.1:10000/
```

### Envoy Not Forwarding Traffic
```bash
# Check envoy logs
kubectl -n packitty-demo logs <pod-name> -c envoy

# Check envoy config
kubectl -n packitty-demo get configmap envoy-config -o yaml

# Access admin interface
kubectl -n packitty-demo port-forward <pod-name> 9901:9901
curl http://127.0.0.1:9901/stats
```

## Performance Tuning

### Resource Limits
Edit `k8s/manifest.yaml` to set:
```yaml
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi
```

### Horizontal Pod Autoscaling
```bash
kubectl -n packitty-demo autoscale deployment app-with-envoy \
  --min=1 --max=10 --cpu-percent=80
```

## Security Considerations

1. **Network Policies**: Restrict pod-to-pod communication
2. **RBAC**: Use role-based access control
3. **Image Registry**: Use private image registry
4. **Secrets**: Store sensitive data as secrets
5. **TLS**: Enable TLS for ingress traffic

## Production Deployment

For production, consider:
- Use container registry (Docker Hub, ECR, GCR)
- Enable health checks (liveness/readiness probes)
- Setup persistent storage for logs
- Configure monitoring and alerting
- Use dedicated ingress controller
- Enable rate limiting
- Setup backup and disaster recovery

## Documentation

- **Main Deployment**: `../README.md`
- **Packitty DDoS Detection**: `../packitty/README.md`
- **Main README**: `../../README.md`

## Note

This is a **separate demonstration project** and does NOT depend on Packitty DDoS Detection.
Both projects can run independently in the same repository.

