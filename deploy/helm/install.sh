#!/bin/bash

# S3 Encryption Proxy Helm Chart Installation Script
# This script provides examples of how to install the chart in different environments

set -e

CHART_PATH="./deploy/helm/s3-encryption-proxy"
NAMESPACE="s3-encryption-proxy"
RELEASE_NAME="s3-proxy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [ENVIRONMENT] [OPTIONS]"
    echo ""
    echo "Environments:"
    echo "  dev         - Install development configuration"
    echo "  staging     - Install staging configuration" 
    echo "  prod        - Install production configuration"
    echo ""
    echo "Options:"
    echo "  --dry-run   - Show what would be installed without actually installing"
    echo "  --upgrade   - Upgrade existing installation"
    echo "  --help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 dev"
    echo "  $0 prod --upgrade"
    echo "  $0 staging --dry-run"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v helm &> /dev/null; then
        log_error "Helm is not installed. Please install Helm 3.0+."
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl."
        exit 1
    fi
    
    # Check if we can connect to Kubernetes
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    log_info "Prerequisites check passed."
}

create_namespace() {
    log_info "Creating namespace '$NAMESPACE' if it doesn't exist..."
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
}

install_cert_manager() {
    local env=$1
    
    if [[ "$env" == "prod" || "$env" == "staging" ]]; then
        log_info "Checking for cert-manager..."
        
        if ! kubectl get crd certificates.cert-manager.io &> /dev/null; then
            log_warn "cert-manager is not installed. Installing cert-manager..."
            
            # Add cert-manager repository
            helm repo add jetstack https://charts.jetstack.io
            helm repo update
            
            # Install cert-manager
            helm install cert-manager jetstack/cert-manager \
                --namespace cert-manager \
                --create-namespace \
                --version v1.13.0 \
                --set installCRDs=true
            
            log_info "Waiting for cert-manager to be ready..."
            kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=300s
        else
            log_info "cert-manager is already installed."
        fi
    fi
}

get_values_file() {
    local env=$1
    case $env in
        dev)
            echo "$CHART_PATH/values-development.yaml"
            ;;
        staging)
            echo "$CHART_PATH/values-production.yaml"
            ;;
        prod)
            echo "$CHART_PATH/values-production.yaml"
            ;;
        *)
            echo "$CHART_PATH/values.yaml"
            ;;
    esac
}

install_chart() {
    local env=$1
    local dry_run=$2
    local upgrade=$3
    
    local values_file=$(get_values_file "$env")
    local cmd="helm"
    
    if [[ "$upgrade" == "true" ]]; then
        cmd="$cmd upgrade"
    else
        cmd="$cmd install"
    fi
    
    cmd="$cmd $RELEASE_NAME $CHART_PATH"
    cmd="$cmd --namespace $NAMESPACE"
    cmd="$cmd --values $values_file"
    
    if [[ "$dry_run" == "true" ]]; then
        cmd="$cmd --dry-run"
    fi
    
    # Environment-specific configurations
    case $env in
        dev)
            log_info "Installing development configuration..."
            # Add any dev-specific overrides here
            ;;
        staging)
            log_info "Installing staging configuration..."
            cmd="$cmd --set image.tag=staging"
            cmd="$cmd --set certificate.dnsNames[0]=s3-proxy-staging.yourdomain.com"
            cmd="$cmd --set ingress.hosts[0].host=s3-proxy-staging.yourdomain.com"
            ;;
        prod)
            log_info "Installing production configuration..."
            cmd="$cmd --set image.tag=v1.0.0"
            cmd="$cmd --set certificate.dnsNames[0]=s3-proxy.yourdomain.com"
            cmd="$cmd --set ingress.hosts[0].host=s3-proxy.yourdomain.com"
            ;;
    esac
    
    # Prompt for secrets in production
    if [[ "$env" == "prod" && "$dry_run" != "true" ]]; then
        read -p "S3 Access Key ID: " -s s3_access_key
        echo
        read -p "S3 Secret Key: " -s s3_secret_key
        echo
        
        cmd="$cmd --set secrets.s3.accessKeyId=$s3_access_key"
        cmd="$cmd --set secrets.s3.secretKey=$s3_secret_key"
    fi
    
    log_info "Executing: $cmd"
    eval $cmd
    
    if [[ "$dry_run" != "true" ]]; then
        log_info "Waiting for deployment to be ready..."
        kubectl wait --for=condition=available deployment/$RELEASE_NAME -n $NAMESPACE --timeout=300s
        
        log_info "Installation completed successfully!"
        
        # Show some helpful information
        echo ""
        log_info "Useful commands:"
        echo "  kubectl get pods -n $NAMESPACE"
        echo "  kubectl logs -f deployment/$RELEASE_NAME -n $NAMESPACE"
        echo "  helm status $RELEASE_NAME -n $NAMESPACE"
        echo "  helm uninstall $RELEASE_NAME -n $NAMESPACE"
    fi
}

main() {
    local environment=""
    local dry_run="false"
    local upgrade="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            dev|staging|prod)
                environment="$1"
                shift
                ;;
            --dry-run)
                dry_run="true"
                shift
                ;;
            --upgrade)
                upgrade="true"
                shift
                ;;
            --help|-h)
                print_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$environment" ]]; then
        log_error "Environment is required."
        print_usage
        exit 1
    fi
    
    check_prerequisites
    create_namespace
    install_cert_manager "$environment"
    install_chart "$environment" "$dry_run" "$upgrade"
}

main "$@"
