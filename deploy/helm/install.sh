#!/bin/bash

# S3 Encryption Proxy Helm Chart Installation Script
# Installs the chart into the current Kubernetes context

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
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --dry-run   - Show what would be installed without actually installing"
    echo "  --upgrade   - Upgrade existing installation"
    echo "  --help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 --upgrade"
    echo "  $0 --dry-run"
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

get_version() {
    local version=""

    # Try to get version from git tag
    if command -v git &> /dev/null && git rev-parse --git-dir > /dev/null 2>&1; then
        # Get the latest git tag
        version=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

        # If no tag found, try to get from Chart.yaml appVersion
        if [[ -z "$version" ]] && [[ -f "$CHART_PATH/Chart.yaml" ]]; then
            version=$(grep "appVersion:" "$CHART_PATH/Chart.yaml" | awk '{print $2}' | tr -d '"')
        fi

        # If still no version, use commit hash
        if [[ -z "$version" ]]; then
            version=$(git rev-parse --short HEAD 2>/dev/null || echo "latest")
        fi
    else
        # Fallback to Chart.yaml appVersion
        if [[ -f "$CHART_PATH/Chart.yaml" ]]; then
            version=$(grep "appVersion:" "$CHART_PATH/Chart.yaml" | awk '{print $2}' | tr -d '"')
        else
            version="latest"
        fi
    fi

    echo "$version"
}

install_chart() {
    local dry_run=$1
    local upgrade=$2

    local values_file="$CHART_PATH/values.yaml"
    local license_file="./config/license.jwt"
    local version=$(get_version)
    local cmd="helm"

    log_info "Using version: $version"

    if [[ "$upgrade" == "true" ]]; then
        cmd="$cmd upgrade"
    else
        cmd="$cmd install"
    fi

    cmd="$cmd $RELEASE_NAME $CHART_PATH"
    cmd="$cmd --namespace $NAMESPACE"
    cmd="$cmd --values $values_file"
    cmd="$cmd --set image.tag=$version"

    # Add license from file if it exists
    if [[ -f "$license_file" ]]; then
        log_info "Loading license from $license_file..."
        local license_content=$(cat "$license_file")
        cmd="$cmd --set-string license.jwt=\"$license_content\""
    else
        log_warn "License file not found at $license_file"
    fi

    if [[ "$dry_run" == "true" ]]; then
        cmd="$cmd --dry-run"
    fi

    log_info "Installing into current Kubernetes context..."
    log_info "Executing: $cmd"
    eval $cmd

    if [[ "$dry_run" != "true" ]]; then
        log_info "Waiting for deployment to be ready..."

        # Get the actual deployment name from the release
        local deployment_name=$(kubectl get deployments -n $NAMESPACE -l app.kubernetes.io/instance=$RELEASE_NAME -o jsonpath='{.items[0].metadata.name}')

        if [[ -n "$deployment_name" ]]; then
            kubectl wait --for=condition=available deployment/$deployment_name -n $NAMESPACE --timeout=300s
        else
            log_warn "Could not find deployment for release $RELEASE_NAME"
        fi

        log_info "Installation completed successfully!"

        # Show some helpful information
        echo ""
        log_info "Useful commands:"
        echo "  kubectl get pods -n $NAMESPACE"
        echo "  kubectl logs -f -l app.kubernetes.io/instance=$RELEASE_NAME -n $NAMESPACE"
        echo "  helm status $RELEASE_NAME -n $NAMESPACE"
        echo "  helm uninstall $RELEASE_NAME -n $NAMESPACE"
    fi
}

main() {
    local dry_run="false"
    local upgrade="false"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
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

    check_prerequisites
    create_namespace
    install_chart "$dry_run" "$upgrade"
}

main "$@"
