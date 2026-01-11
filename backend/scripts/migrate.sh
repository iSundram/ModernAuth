#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATIONS_DIR="$SCRIPT_DIR/migrations"

# Function to get DATABASE_URL from docker-compose.yml or .env
get_database_url() {
    # Try .env first
    if [ -f "$SCRIPT_DIR/../.env" ]; then
        DATABASE_URL=$(grep "^DATABASE_URL=" "$SCRIPT_DIR/../.env" | cut -d '=' -f2-)
        if [ ! -z "$DATABASE_URL" ]; then
            echo "$DATABASE_URL"
            return
        fi
    fi

    # Fallback to docker-compose.yml
    if [ -f "$SCRIPT_DIR/../docker-compose.yml" ]; then
        DB_USER=$(grep -A 10 "postgres:" "$SCRIPT_DIR/../docker-compose.yml" | grep "POSTGRES_USER:" | awk '{print $2}' | head -1)
        DB_PASS=$(grep -A 10 "postgres:" "$SCRIPT_DIR/../docker-compose.yml" | grep "POSTGRES_PASSWORD:" | awk '{print $2}' | head -1)
        DB_NAME=$(grep -A 10 "postgres:" "$SCRIPT_DIR/../docker-compose.yml" | grep "POSTGRES_DB:" | awk '{print $2}' | head -1)
        
        echo "postgres://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}?sslmode=disable"
        return
    fi

    # Default fallback
    echo "postgres://modernauth:modernauth@localhost:5432/modernauth?sslmode=disable"
}

# Wrapper for psql command to handle cases where it's not installed on host
run_psql() {
    if command -v psql &> /dev/null; then
        psql "$@"
    elif command -v docker &> /dev/null && docker ps --format '{{.Names}}' | grep -q "modernauth-postgres"; then
        # If psql is missing on host, run it inside the docker container
        local args=("$@")
        local file_path=""
        local new_args=()
        
        # Look for -f argument and extract the file path
        for ((i=0; i<${#args[@]}; i++)); do
            if [[ "${args[$i]}" == "-f" ]]; then
                file_path="${args[$((i+1))]}"
                i=$((i+1)) # Skip the next arg which is the file path
            else
                new_args+=("${args[$i]}")
            fi
        done

        if [[ -n "$file_path" ]]; then
            # Pipe file content to psql inside container
            cat "$file_path" | docker exec -i modernauth-postgres psql "${new_args[@]}"
        else
            docker exec -i modernauth-postgres psql "${new_args[@]}"
        fi
    else
        echo -e "${RED}Error: psql not found on host and modernauth-postgres container is not running.${NC}"
        echo -e "${YELLOW}Please install postgresql-client or start the docker containers.${NC}"
        exit 1
    fi
}

# Function to create migrations table
create_migrations_table() {
    run_psql "$DATABASE_URL" -c "
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    "
}

# Function to check if migration is applied
is_migration_applied() {
    local version=$1
    run_psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM schema_migrations WHERE version = '$version';" | xargs
}

# Function to mark migration as applied
mark_migration_applied() {
    local version=$1
    run_psql "$DATABASE_URL" -c "INSERT INTO schema_migrations (version) VALUES ('$version');"
}

# Function to mark migration as reverted
mark_migration_reverted() {
    local version=$1
    run_psql "$DATABASE_URL" -c "DELETE FROM schema_migrations WHERE version = '$version';"
}

# Function to migrate up
migrate_up() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Running Database Migrations       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    create_migrations_table
    
    local applied_count=0
    local skipped_count=0
    
    for file in $(ls "$MIGRATIONS_DIR"/*.up.sql | sort); do
        local filename=$(basename "$file")
        local version="${filename%.up.sql}"
        
        if [ $(is_migration_applied "$version") -eq 0 ]; then
            echo -e "${YELLOW}→ Applying $filename...${NC}"
            
            if run_psql "$DATABASE_URL" -f "$file"; then
                mark_migration_applied "$version"
                echo -e "${GREEN}✓ Applied $filename${NC}"
                applied_count=$((applied_count + 1))
            else
                echo -e "${RED}✗ Failed to apply $filename${NC}"
                exit 1
            fi
        else
            echo -e "${BLUE}• Skipped $filename (already applied)${NC}"
            skipped_count=$((skipped_count + 1))
        fi
    done
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}Migrations complete!${NC}"
    echo -e "  Applied: ${GREEN}$applied_count${NC}"
    echo -e "  Skipped: ${BLUE}$skipped_count${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
}

# Function to migrate down
migrate_down() {
    echo -e "${YELLOW}╔════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║    Rolling Back Last Migration        ║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get the last applied migration
    local last_version=$(run_psql "$DATABASE_URL" -t -c "SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1;" | xargs)
    
    if [ -z "$last_version" ]; then
        echo -e "${YELLOW}No migrations to rollback${NC}"
        exit 0
    fi
    
    local down_file="$MIGRATIONS_DIR/${last_version}.down.sql"
    
    if [ ! -f "$down_file" ]; then
        echo -e "${RED}✗ Rollback file not found: ${down_file}${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}→ Rolling back $last_version...${NC}"
    
    if run_psql "$DATABASE_URL" -f "$down_file" > /dev/null 2>&1; then
        mark_migration_reverted "$last_version"
        echo -e "${GREEN}✓ Rolled back $last_version${NC}"
    else
        echo -e "${RED}✗ Failed to rollback $last_version${NC}"
        exit 1
    fi
}

# Function to reset database
migrate_reset() {
    echo -e "${RED}╔════════════════════════════════════════╗${NC}"
    echo -e "${RED}║      Resetting Database (DANGER!)      ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}WARNING: This will rollback ALL migrations!${NC}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
    
    # Get all applied migrations in reverse order
    local versions=$(run_psql "$DATABASE_URL" -t -c "SELECT version FROM schema_migrations ORDER BY applied_at DESC;")
    
    for version in $versions; do
        local down_file="$MIGRATIONS_DIR/${version}.down.sql"
        
        if [ -f "$down_file" ]; then
            echo -e "${YELLOW}→ Rolling back $version...${NC}"
            run_psql "$DATABASE_URL" -f "$down_file" > /dev/null 2>&1
            mark_migration_reverted "$version"
            echo -e "${GREEN}✓ Rolled back $version${NC}"
        else
            echo -e "${YELLOW}⚠ Skipping $version (no down file)${NC}"
            mark_migration_reverted "$version"
        fi
    done
    
    echo -e "${GREEN}Database reset complete${NC}"
}

# Function to show migration status
migrate_status() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       Migration Status                 ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    create_migrations_table
    
    for file in $(ls "$MIGRATIONS_DIR"/*.up.sql | sort); do
        local filename=$(basename "$file")
        local version="${filename%.up.sql}"
        
        if [ $(is_migration_applied "$version") -eq 1 ]; then
            echo -e "${GREEN}✓${NC} $version"
        else
            echo -e "${RED}✗${NC} $version"
        fi
    done
}

# Main script
DATABASE_URL=$(get_database_url)

echo -e "${BLUE}Database: ${DATABASE_URL}${NC}"
echo ""

case "${1:-up}" in
    up)
        migrate_up
        ;;
    down)
        migrate_down
        ;;
    reset)
        migrate_reset
        ;;
    status)
        migrate_status
        ;;
    *)
        echo "Usage: $0 {up|down|reset|status}"
        echo ""
        echo "Commands:"
        echo "  up     - Apply all pending migrations (default)"
        echo "  down   - Rollback the last migration"
        echo "  reset  - Rollback all migrations (DANGER)"
        echo "  status - Show migration status"
        exit 1
        ;;
esac