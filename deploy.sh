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
