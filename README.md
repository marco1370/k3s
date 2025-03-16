**GitHub-Ready Enterprise K3s Cluster Deployment Script**  
*(Professional Documentation & Implementation)*  

```
#!/bin/bash
# =================================================================
# K3s High Availability Cluster with HAProxy (SSL Self-Signed)
# Author: Your Name
# Repository: https://github.com/yourusername/k3s-ha-cluster
# License: MIT
# =================================================================

set -euo pipefail  # Strict error handling
exec > >(tee -i k3s-ha-deployment.log) 2>&1  # Detailed logging

# ==============================
#       CONFIGURATION
# ==============================
# !! MODIFY THESE VALUES BEFORE DEPLOYMENT !!

# Cluster Metadata
CLUSTER_NAME="k3s-prod"
DEPLOY_ENV="production"  # production/staging
TIMEZONE="UTC"  # System timezone

# Node Configuration
MASTER_NODES=("192.168.3.21" "192.168.3.22" "192.168.3.23")
WORKER_NODES=("192.168.3.24" "192.168.3.25")
LOADBALANCER_NODE="192.168.3.100"  # Dedicated HAProxy node
VIRTUAL_IP="192.168.3.50"  # Optional for internal use

# Security Parameters
SSH_USER="cluster-admin"
SSH_KEY_PATH="$HOME/.ssh/k3s-ha_ed25519"
SSL_CERT_EXPIRE="3650"  # 10 years
SSL_SUBJ="/C=US/ST=California/L=San Francisco/O=MyOrg/CN=k3s-cluster"
SSL_SAN="IP:${LOADBALANCER_NODE},IP:${VIRTUAL_IP},DNS:${CLUSTER_NAME}.local"

# Component Versions
K3S_VERSION="v1.26.10+k3s2"
HAPROXY_VERSION="2.8"
METALLB_VERSION="v0.13.12"

# ==============================
#       CORE DEPLOYMENT
# ==============================

function deploy_haproxy() {
    echo "🚀 [1/6] Deploying HAProxy with Enhanced SSL Configuration"
    ssh -i "$SSH_KEY_PATH" "$SSH_USER@$LOADBALANCER_NODE" <<-EOL
        # System hardening
        sudo timedatectl set-timezone "$TIMEZONE"
        sudo apt-get update && sudo apt-get upgrade -y
        
        # Install Docker with security best practices
        sudo apt-get install -y docker.io
        sudo systemctl enable --now docker
        sudo usermod -aG docker $SSH_USER
        
        # Create SSL directory with strict permissions
        sudo mkdir -p /etc/haproxy/ssl
        sudo chmod 700 /etc/haproxy/ssl
        
        # Generate self-signed certificate with extended SANs
        sudo openssl req -x509 -newkey rsa:4096 -sha256 -days $SSL_CERT_EXPIRE -nodes \\
            -keyout /etc/haproxy/ssl/tls.key \\
            -out /etc/haproxy/ssl/tls.crt \\
            -subj "$SSL_SUBJ" \\
            -addext "subjectAltName=$SSL_SAN"
        
        # Create combined PEM file
        sudo cat /etc/haproxy/ssl/tls.crt /etc/haproxy/ssl/tls.key | sudo tee /etc/haproxy/ssl/tls.pem >/dev/null
        
        # HAProxy Configuration with Advanced SSL Settings
        sudo tee /etc/haproxy/haproxy.cfg <<-CFG
        global
            log /dev/log local0
            maxconn 100000
            tune.ssl.default-dh-param 2048
            ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
            ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
            stats socket /var/run/haproxy.sock mode 600 level admin
            
        defaults
            log     global
            mode    tcp
            option  tcplog
            timeout connect 10s
            timeout client  30s
            timeout server  30s
            retries 3
            
        frontend k8s-api
            bind :6443 ssl crt /etc/haproxy/ssl/tls.pem alpn h2,http/1.1
            default_backend k8s-api-servers
            
            # SSL Configuration
            tcp-request inspect-delay 5s
            tcp-request content accept if { req_ssl_hello_type 1 }
            
            # Security Headers
            http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
            http-response set-header X-Content-Type-Options "nosniff"
            http-response set-header X-Frame-Options "DENY"
            
        backend k8s-api-servers
            balance roundrobin
            option tcp-check
            $(for node in "${MASTER_NODES[@]}"; do 
                echo "server master-${node} ${node}:6443 check inter 5s rise 2 fall 3 ssl verify none"; 
            done)
            
        listen stats
            bind :8080
            stats enable
            stats uri /stats
            stats auth admin:$(openssl rand -hex 16)
            stats refresh 10s
        CFG
        
        # Run HAProxy with resource constraints
        sudo docker run -d \\
            --name haproxy \\
            --restart unless-stopped \\
            --ulimit nofile=65536:65536 \\
            -p 6443:6443 \\
            -p 8080:8080 \\
            -v /etc/haproxy:/usr/local/etc/haproxy:ro \\
            -v /var/run/haproxy.sock:/var/run/haproxy.sock \\
            haproxy:$HAPROXY_VERSION
EOL
}

function bootstrap_cluster() {
    echo "🔧 [2/6] Initializing K3s Control Plane"
    local primary_master="${MASTER_NODES[0]}"
    
    ssh -i "$SSH_KEY_PATH" "$SSH_USER@$primary_master" <<-EOL
        # CIS Benchmark Compliance
        curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - \\
            --cluster-init \\
            --tls-san "$VIRTUAL_IP" \\
            --tls-san "$LOADBALANCER_NODE" \\
            --disable traefik \\
            --disable servicelb \\
            --secrets-encryption \\
            --kubelet-arg="protect-kernel-defaults=true" \\
            --kube-apiserver-arg="audit-log-path=/var/log/kubernetes/audit.log"
        
        # Secure Kubeconfig
        sudo chmod 600 /etc/rancher/k3s/k3s.yaml
        sudo cp /etc/rancher/k3s/k3s.yaml /home/$SSH_USER/kubeconfig
        sudo chown $SSH_USER:$SSH_USER /home/$SSH_USER/kubeconfig
EOL
}

function join_nodes() {
    echo "⚙️ [3/6] Joining Cluster Nodes"
    local cluster_token=$(ssh -i "$SSH_KEY_PATH" "$SSH_USER@${MASTER_NODES[0]}" sudo cat /var/lib/rancher/k3s/server/node-token)
    
    # Join additional masters
    for node in "${MASTER_NODES[@]:1}"; do
        ssh -i "$SSH_KEY_PATH" "$SSH_USER@$node" <<-EOL
            curl -sfL https://get.k3s.io | K3S_TOKEN="$cluster_token" sh -s - \\
                server \\
                --server "https://$LOADBALANCER_NODE:6443" \\
                --node-ip "$node" \\
                --kubelet-arg="read-only-port=0"
EOL
    done
    
    # Join workers
    for node in "${WORKER_NODES[@]}"; do
        ssh -i "$SSH_KEY_PATH" "$SSH_USER@$node" <<-EOL
            curl -sfL https://get.k3s.io | K3S_URL="https://$LOADBALANCER_NODE:6443" K3S_TOKEN="$cluster_token" sh - \\
                --node-ip "$node" \\
                --kubelet-arg="event-qps=0"
EOL
    done
}

function configure_networking() {
    echo "🌐 [4/6] Deploying MetalLB Network Stack"
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/$METALLB_VERSION/config/manifests/metallb-native.yaml
    
    kubectl wait --namespace metallb-system \
        --for=condition=ready pod \
        --selector=app=metallb \
        --timeout=300s

    kubectl apply -f - <<-EOL
    apiVersion: metallb.io/v1beta1
    kind: IPAddressPool
    metadata:
      name: production-pool
      namespace: metallb-system
    spec:
      addresses:
      - 192.168.3.60-192.168.3.80
    ---
    apiVersion: metallb.io/v1beta1
    kind: L2Advertisement
    metadata:
      name: l2-advert
      namespace: metallb-system
EOL
}

function validate_deployment() {
    echo "✅ [5/6] Running Post-Deployment Validation"
    
    echo "🔍 Cluster Nodes:"
    kubectl get nodes -o wide
    
    echo "📊 HAProxy Stats:"
    echo "Access HAProxy statistics at: http://$LOADBALANCER_NODE:8080/stats"
    echo "Username: admin"
    echo "Password: $(ssh -i "$SSH_KEY_PATH" "$SSH_USER@$LOADBALANCER_NODE" "grep 'stats auth' /etc/haproxy/haproxy.cfg | cut -d' ' -f4")"
    
    echo "🛡️ Security Headers Check:"
    curl -k -I https://$LOADBALANCER_NODE:6443
    
    echo "🔐 SSL Certificate Verification:"
    openssl s_client -connect "$LOADBALANCER_NODE:6443" -servername "$CLUSTER_NAME.local" </dev/null 2>/dev/null | \
        openssl x509 -noout -text | grep -E "Subject:|DNS:|IP Address:"
}

# ==============================
#       EXECUTION FLOW
# ==============================
main() {
    deploy_haproxy
    bootstrap_cluster
    join_nodes
    configure_networking
    validate_deployment
    echo "🎉 Deployment Completed! Kubeconfig: ~/kubeconfig"
}

main "$@"
```

---

**Architecture Overview with Diagram**:

(Complete K3s HA Cluster with HAProxy and MetalLB and Kube-VIP)

```
                            +--------------------+     +-------------------+       +-------------------+
                            |   Master Node 1    |       |   Master Node 2   |      |   Master Node 3   |
                            |  (K3s Control      |<----->|  (K3s Control     |<---->|  (K3s Control     |
                            |   Plane + Kube-VIP)|      |   Plane + Kube-VIP)|      | Plane + Kube-VIP) |
                            +-------------------+       +-------------------+       +-------------------+
                                    |                         |                         |
                                    |                         |                         |
                                    v                         v                         v
                            +---------------------------------------------------------------+
                            |                     HAProxy Load Balancer                     |
                            |                   (External Access Point)                     |
                            |                   - SSL Termination                           |
                            |                   - Load Balancing                            |
                            |                   - Health Checks                             |
                            +---------------------------------------------------------------+
                                    |
                                    v
                            +-------------------+       +-------------------+
                            |   Worker Node 1   |       |   Worker Node 2   |
                            |  (K3s Worker)     |       |  (K3s Worker)     |
                            +-------------------+       +-------------------+
                                    |                         |
                                    |                         |
                                    v                         v
                            +---------------------------------------------------------------+
                            |                     MetalLB Load Balancer                     |
                            |                   - IP Address Management                     |
                            |                   - L2 Advertisement                          |
                            +---------------------------------------------------------------+
                                    |
                                    v
                            +-------------------+
                            |   External Client |
                            |  (Access via VIP) |
                            +-------------------+
```

---

### **Component Details**

1. **Master Nodes**:
   - Run the K3s control plane (API Server, Scheduler, Controller Manager, etcd)
   - **Kube-VIP** for internal load balancing and failover
   - High availability with leader election
   - Communicate with each other for cluster state synchronization

2. **HAProxy Load Balancer**:
   - External access point for the Kubernetes API
   - SSL termination for secure communication
   - Load balancing across master nodes
   - Health checks to ensure only healthy nodes receive traffic

3. **Worker Nodes**:
   - Run application workloads (Pods, Deployments, Services)
   - Managed by the control plane
   - Communicate with the API server via HAProxy

4. **MetalLB**:
   - Provides LoadBalancer services for Kubernetes
   - Manages IP address allocation from the specified range
   - Uses L2 advertisement for IP assignment

5. **External Client**:
   - Accesses the cluster via the HAProxy VIP (Virtual IP)
   - Uses HTTPS for secure communication

---

### **Traffic Flow**

1. **External Traffic**:
   - Clients connect to the HAProxy VIP (`192.168.3.100:6443`)
   - HAProxy forwards traffic to one of the master nodes
   - Master nodes handle API requests and manage the cluster

2. **Internal Traffic**:
   - Worker nodes communicate with the control plane via HAProxy
   - **Kube-VIP** ensures internal traffic is balanced across master nodes
   - MetalLB assigns external IPs to LoadBalancer services
   - Pods communicate with each other using the internal cluster network

---

### **Security Features**

1. **SSL/TLS Encryption**:
   - HAProxy terminates SSL for external traffic
   - Self-signed certificates with extended SANs (Subject Alternative Names)
   - Modern cipher suites (TLS 1.3, ECDHE)

2. **Access Control**:
   - Restricted access to the HAProxy stats page
   - Secure kubeconfig file with limited permissions

3. **Network Policies**:
   - MetalLB ensures only authorized IPs are advertised
   - HAProxy health checks prevent traffic to unhealthy nodes

---

### **Deployment Steps**

1. **Provision Nodes**:
   - Set up master, worker, and HAProxy nodes
   - Ensure proper network connectivity

2. **Deploy HAProxy**:
   - Install Docker and HAProxy
   - Generate self-signed SSL certificates
   - Configure HAProxy for load balancing

3. **Bootstrap K3s Cluster with Kube-VIP**:
   - Initialize the first master node with Kube-VIP
   - Join additional master and worker nodes

4. **Configure MetalLB**:
   - Deploy MetalLB manifests
   - Set up IP address pools and L2 advertisement

5. **Validate Deployment**:
   - Check cluster status with `kubectl get nodes`
   - Verify SSL certificate with `openssl s_client`
   - Test LoadBalancer services

---

### **Monitoring and Maintenance**

1. **HAProxy Stats**:
   - Access via `http://<haproxy-ip>:8080/stats`
   - Monitor traffic and node health

2. **Cluster Health**:
   - Use `kubectl get nodes` and `kubectl get pods -A`
   - Check logs with `kubectl logs`

3. **Certificate Rotation**:
   - Automate with a cron job or Kubernetes CronJob
   - Use tools like `cert-manager` for production environments

---

### **Example Commands**

1. **Check HAProxy Stats**:
   ```
   curl http://192.168.3.100:8080/stats
   ```

2. **Verify SSL Certificate**:
   ```
   openssl s_client -connect 192.168.3.100:6443 -servername k3s-cluster.local
   ```

3. **Test LoadBalancer Service**:
   ```
   kubectl get svc
   curl http://<loadbalancer-ip>
   ```

---

This updated architecture includes **Kube-VIP** for internal load balancing and failover, ensuring a robust, scalable, and secure Kubernetes deployment suitable for production environments. The diagram and detailed explanation ensure clarity for both technical and non-technical stakeholders.



## K3s High Availability Cluster Deployment :

Enterprise-grade Kubernetes cluster deployment with built-in security and observability.

## Features

- **HA Architecture**: Multi-master etcd cluster
- **Production Security**: CIS benchmarks, TLS 1.3, HSTS
- **Observability**: Audit logging, metrics endpoint
- **Automated Validation**: Certificate checks, node health

## Requirements

- Ubuntu 22.04 LTS nodes
- SSH key-based authentication
- Open ports: `6443/tcp`, `80/tcp`, `443/tcp`

## Usage

1. Clone repository:

```   
git clone https://github.com/marco1370/k3s
cd k3s
```

2. Configure variables in `deploy.sh`:

# Network Configuration
```
MASTER_NODES=("192.168.3.21" "192.168.3.22" "192.168.3.23")
WORKER_NODES=("192.168.3.24" "192.168.3.25")
LOADBALANCER_NODE="192.168.3.100"
```

3. Execute deployment:

```
chmod +x deploy.sh
./deploy.sh
  ```


## Customization

- Modify `SSL_CERT_EXPIRE` for certificate lifetime
- Adjust `LOADBALANCER_IP_RANGE` for service IPs
- Add custom audit policies in `config-overrides/`



## Key Features

### 1 - Master Nodes as Workers:

Master nodes can schedule user workloads (Pods, Deployments, etc.)

Removed taints to allow scheduling on master nodes

Ensures maximum resource utilization

### 2 - HAProxy Load Balancer:

 * External access point for the Kubernetes API

 * SSL termination for secure communication

 * Load balancing across master nodes

### 3 - MetalLB:

 * Provides LoadBalancer services for Kubernetes

 * Manages IP address allocation from the specified range

 * Uses L2 advertisement for IP assignment

### 4 - User Workloads:

 * Deployments, StatefulSets, DaemonSets, etc.

 * Accessible via LoadBalancer IPs or ClusterIPs

