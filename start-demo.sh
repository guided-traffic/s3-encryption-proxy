#!/bin/bash

# S3 Encryption Proxy - Demo Starter Script
# This script intelligently starts or restarts the demo environment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.demo.yml"
PROXY_SERVICE="s3-encryption-proxy"
PROXY_CONTAINER="demo-s3-encryption-proxy"

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ SUCCESS:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠️  WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}❌ ERROR:${NC} $1"
}

# Check if Docker and Docker Compose are available
check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
        log_error "Docker Compose is not available"
        exit 1
    fi

    # Determine which docker-compose command to use
    if docker compose version &> /dev/null 2>&1; then
        DOCKER_COMPOSE="docker compose"
    else
        DOCKER_COMPOSE="docker-compose"
    fi

    log_success "Dependencies check passed"
}

# Check if demo environment is running
is_demo_running() {
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" ps -q | wc -l | grep -q -v "^0$"
}

# Check if proxy container is running
is_proxy_running() {
    docker ps -q --filter "name=$PROXY_CONTAINER" | wc -l | grep -q -v "^0$"
}

# Get current Git commit for build args
get_git_info() {
    local git_commit
    local build_time

    git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    build_time=$(date -u '+%Y-%m-%d_%H:%M:%S_UTC')

    echo "$git_commit $build_time"
}

# Build and restart proxy service
rebuild_proxy() {
    log_info "Rebuilding S3 Encryption Proxy..."

    # Get Git info for build args
    read -r git_commit build_time <<< "$(get_git_info)"

    # Stop the proxy service
    log_info "Stopping proxy service..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" stop "$PROXY_SERVICE" 2>/dev/null || true

    # Remove the proxy container
    log_info "Removing proxy container..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" rm -f "$PROXY_SERVICE" 2>/dev/null || true

    # Build the new image with build args
    log_info "Building new proxy image (commit: $git_commit)..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" build \
        --build-arg "BUILD_NUMBER=demo-dev" \
        --build-arg "GIT_COMMIT=$git_commit" \
        --build-arg "BUILD_TIME=$build_time" \
        "$PROXY_SERVICE"

    # Start the proxy service
    log_info "Starting proxy service..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d "$PROXY_SERVICE"

    log_success "Proxy rebuild completed"
}

# Start the complete demo environment
start_demo() {
    log_info "Starting complete demo environment..."

    # Get Git info for build args
    read -r git_commit build_time <<< "$(get_git_info)"

    # Start all services
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d \
        --build \
        --build-arg "BUILD_NUMBER=demo-dev" \
        --build-arg "GIT_COMMIT=$git_commit" \
        --build-arg "BUILD_TIME=$build_time"

    log_success "Demo environment started"
}

# Show service status and endpoints
show_status() {
    log_info "Service Status:"
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" ps

    echo
    log_info "Available Endpoints:"
    echo "  🔐 S3 Encryption Proxy:     http://localhost:8080"
    echo "  📦 MinIO S3 API:            https://localhost:9000 (self-signed cert)"
    echo "  🎛️  MinIO Console:           https://localhost:9001 (admin/minioadmin123)"
    echo "  🔒 S3 Explorer (Encrypted): http://localhost:8081"
    echo "  🔓 S3 Explorer (Direct):    http://localhost:8082"
    echo
    echo
    echo "  � Debug Commands:"
    echo "     View proxy logs:        docker logs -f proxy"
    echo
    echo "  �💡 Note: S3 Explorers may take a moment to fully start on Apple Silicon Macs"
}

# Show logs for proxy service
show_logs() {
    log_info "Showing S3 Encryption Proxy logs (Ctrl+C to exit)..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" logs -f "$PROXY_SERVICE"
}

# Clean up demo environment
cleanup() {
    log_info "Stopping and cleaning up demo environment..."
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" down -v

    # Remove dangling images
    if docker images -f "dangling=true" -q | grep -q .; then
        log_info "Cleaning up dangling Docker images..."
        docker rmi $(docker images -f "dangling=true" -q) 2>/dev/null || true
    fi

    log_success "Cleanup completed"
}

# Wait for services to be healthy
wait_for_health() {
    log_info "Waiting for services to become healthy..."

    local max_attempts=30
    local attempt=1

    # First check MinIO
    log_info "Checking MinIO health..."
    while [ $attempt -le $max_attempts ]; do
        if curl -sf -k https://localhost:9000/minio/health/live >/dev/null 2>&1; then
            log_success "MinIO is healthy"
            break
        fi

        if [ $attempt -eq $max_attempts ]; then
            log_warning "MinIO health check timeout - continuing anyway"
            break
        fi

        echo -n "."
        sleep 2
        ((attempt++))
    done

    # Then check Proxy
    log_info "Checking S3 Encryption Proxy health..."
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
            log_success "S3 Encryption Proxy is healthy"
            return 0
        fi

        echo -n "."
        sleep 2
        ((attempt++))
    done

    log_warning "Services may not be fully healthy yet. Check with 'show-status' command."
    return 1
}

# Main execution logic
main() {
    case "${1:-start}" in
        "start")
            check_dependencies
            if is_demo_running; then
                log_info "Demo environment is already running"
                if is_proxy_running; then
                    log_info "Rebuilding proxy with latest changes..."
                    rebuild_proxy
                else
                    log_info "Starting proxy service..."
                    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d "$PROXY_SERVICE"
                fi
                # Ensure all services are running
                log_info "Ensuring all services are running..."
                $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d
            else
                start_demo
            fi
            wait_for_health
            show_status
            ;;

        "rebuild"|"restart")
            check_dependencies
            if is_demo_running; then
                rebuild_proxy
                wait_for_health
                show_status
            else
                log_warning "Demo environment is not running. Starting complete environment..."
                start_demo
                wait_for_health
                show_status
            fi
            ;;

        "stop")
            check_dependencies
            log_info "Stopping demo environment..."
            $DOCKER_COMPOSE -f "$COMPOSE_FILE" stop
            log_success "Demo environment stopped"
            ;;

        "down"|"cleanup")
            check_dependencies
            cleanup
            ;;

        "status"|"show-status")
            check_dependencies
            show_status
            ;;

        "logs")
            check_dependencies
            show_logs
            ;;

        "health")
            if curl -sf http://localhost:8080/health; then
                log_success "S3 Encryption Proxy is healthy"
                echo "  Version info: http://localhost:8080/version"
            else
                log_error "S3 Encryption Proxy is not healthy"
                exit 1
            fi
            ;;

        "help"|"-h"|"--help")
            echo "S3 Encryption Proxy - Demo Environment Manager"
            echo
            echo "Usage: $0 [command]"
            echo
            echo "Commands:"
            echo "  start              Start demo environment (default)"
            echo "                     - If running: rebuild proxy"
            echo "                     - If not running: start all services"
            echo "  rebuild|restart    Force rebuild and restart proxy service"
            echo "  stop              Stop all services"
            echo "  down|cleanup      Stop and remove all containers and volumes"
            echo "  status|show-status Show service status and endpoints"
            echo "  logs              Show proxy logs (follow mode)"
            echo "  health            Check proxy health"
            echo "  help              Show this help message"
            echo
            echo "Examples:"
            echo "  $0                 # Start or restart demo"
            echo "  $0 rebuild         # Force rebuild proxy"
            echo "  $0 logs            # Watch proxy logs"
            echo "  $0 cleanup         # Clean up everything"
            ;;

        *)
            log_error "Unknown command: $1"
            log_info "Use '$0 help' to see available commands"
            exit 1
            ;;
    esac
}

# Trap cleanup on script exit
trap 'echo' EXIT

# Run main function
main "$@"
