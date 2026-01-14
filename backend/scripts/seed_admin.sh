#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

DOCKER_CONTAINER="modernauth-postgres"
DB_USER="modernauth"
DB_NAME="modernauth"

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ModernAuth Admin Account Creator     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if docker container is running
if ! docker ps | grep -q "$DOCKER_CONTAINER"; then
    echo -e "${RED}Error: Docker container '$DOCKER_CONTAINER' is not running${NC}"
    echo -e "${YELLOW}Start it with: docker-compose up -d${NC}"
    exit 1
fi

echo -e "${YELLOW}Using Docker container: ${DOCKER_CONTAINER}${NC}"
echo ""

# Prompt for admin credentials
read -p "Enter admin email [admin@example.com]: " ADMIN_EMAIL
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}

while true; do
    read -sp "Enter admin password (min 8 chars): " ADMIN_PASSWORD
    echo
    if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
        echo -e "${RED}Password must be at least 8 characters${NC}"
        continue
    fi
    read -sp "Confirm admin password: " ADMIN_PASSWORD_CONFIRM
    echo
    if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
        break
    fi
    echo -e "${RED}Passwords do not match. Try again.${NC}"
done

echo ""
echo -e "${YELLOW}Creating admin account...${NC}"

# Create temporary directory for Go program to hash the password
TEMP_DIR=$(mktemp -d)
cat > $TEMP_DIR/hash_password.go << 'EOF'
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "os"
    "golang.org/x/crypto/argon2"
)

func hashPassword(password string) (string, error) {
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    
    hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
    
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)
    
    return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", b64Salt, b64Hash), nil
}

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintf(os.Stderr, "Usage: hash_password <password>\n")
        os.Exit(1)
    }
    
    hash, err := hashPassword(os.Args[1])
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Print(hash)
}
EOF

# Compile and run the password hasher
PUSHED_DIR=$(pwd)
cd $TEMP_DIR
go mod init hash_password
go get golang.org/x/crypto/argon2
go build -o hash_password hash_password.go

HASHED_PASSWORD=$(./hash_password "$ADMIN_PASSWORD")
cd $PUSHED_DIR
rm -rf $TEMP_DIR

# Create SQL script
SQL_SCRIPT=$(cat << EOF
-- Create admin user
DO \$\$
DECLARE
    v_user_id UUID;
BEGIN
    -- Check if user exists
    SELECT id INTO v_user_id FROM users WHERE email = '$ADMIN_EMAIL';
    
    IF v_user_id IS NULL THEN
        -- Insert new user
        INSERT INTO users (id, email, hashed_password, is_email_verified, is_active, created_at, updated_at)
        VALUES (
            gen_random_uuid(),
            '$ADMIN_EMAIL',
            '$HASHED_PASSWORD',
            true,
            true,
            NOW(),
            NOW()
        )
        RETURNING id INTO v_user_id;
    ELSE
        -- Update existing user
        UPDATE users
        SET hashed_password = '$HASHED_PASSWORD',
            is_active = true,
            updated_at = NOW()
        WHERE id = v_user_id;
    END IF;

    -- Assign admin role (00000000-0000-0000-0000-000000000001 is the admin role UUID from migration)
    INSERT INTO user_roles (user_id, role_id, assigned_at)
    VALUES (
        v_user_id,
        '00000000-0000-0000-0000-000000000001',
        NOW()
    )
    ON CONFLICT (user_id, role_id) DO NOTHING;

    -- Create audit log
    INSERT INTO audit_logs (id, user_id, event_type, created_at)
    VALUES (gen_random_uuid(), v_user_id, 'user.admin_seeded', NOW());

    RAISE NOTICE 'Admin user created successfully: %', '$ADMIN_EMAIL';
END \$\$;
EOF
)

# Execute SQL via Docker
echo "$SQL_SCRIPT" | docker exec -i "$DOCKER_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Admin account created successfully!${NC}"
    echo ""
    echo -e "${GREEN}Credentials:${NC}"
    echo -e "  Email:    ${YELLOW}$ADMIN_EMAIL${NC}"
    echo -e "  Password: ${YELLOW}********${NC}"
    echo ""
    echo -e "${YELLOW}You can now login with these credentials.${NC}"
else
    echo -e "${RED}✗ Failed to create admin account${NC}"
    echo -e "${RED}Make sure Docker container is running and migrations are applied.${NC}"
    exit 1
fi
