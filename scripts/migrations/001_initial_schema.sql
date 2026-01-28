-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table with ULID
CREATE TABLE users (
    id CHAR(26) PRIMARY KEY, -- ULID (26 characters)
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for users table
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Create user_roles table
CREATE TABLE user_roles (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for user_roles table
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role);

-- Create refresh_tokens table
CREATE TABLE refresh_tokens (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for refresh_tokens table
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Create password_reset_tokens table
CREATE TABLE password_reset_tokens (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for password_reset_tokens table
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- Create audit_logs table
CREATE TABLE audit_logs (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id CHAR(26),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for audit_logs table
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Create email_verifications table
CREATE TABLE email_verifications (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for email_verifications table
CREATE INDEX idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX idx_email_verifications_token ON email_verifications(token);
CREATE INDEX idx_email_verifications_expires_at ON email_verifications(expires_at);

-- Create sessions table
CREATE TABLE sessions (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    session_token TEXT NOT NULL,
    device_info JSONB,
    ip_address INET,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for sessions table
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Create blacklisted_tokens table
CREATE TABLE blacklisted_tokens (
    id CHAR(26) PRIMARY KEY, -- ULID
    token TEXT NOT NULL,
    user_id CHAR(26) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reason VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for blacklisted_tokens table
CREATE INDEX idx_blacklisted_tokens_token ON blacklisted_tokens(token);
CREATE INDEX idx_blacklisted_tokens_expires_at ON blacklisted_tokens(expires_at);
CREATE INDEX idx_blacklisted_tokens_user_id ON blacklisted_tokens(user_id);

-- Create otp_codes table
CREATE TABLE otp_codes (
    id CHAR(26) PRIMARY KEY, -- ULID
    user_id CHAR(26) NOT NULL,
    code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- 'login', 'verification', 'password_reset'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes for otp_codes table
CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_codes_code ON otp_codes(code);
CREATE INDEX idx_otp_codes_purpose ON otp_codes(purpose);
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for users table
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user (password: Admin@123)
INSERT INTO users (id, email, password_hash, full_name, phone, is_active, is_verified) 
VALUES (
    '01H9ZQ8VQJ5Q1Q1Q1Q1Q1Q1Q1Q', -- ULID example
    'admin@example.com',
    '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- bcrypt hash for 'Admin@123'
    'System Administrator',
    '+62123456789',
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- Insert admin role for admin user
INSERT INTO user_roles (id, user_id, role) 
VALUES (
    '01H9ZQ8VQJ5Q1Q1Q1Q1Q1Q1Q2Q',
    '01H9ZQ8VQJ5Q1Q1Q1Q1Q1Q1Q1Q',
    'admin'
) ON CONFLICT DO NOTHING;

-- Insert user role for admin user
INSERT INTO user_roles (id, user_id, role) 
VALUES (
    '01H9ZQ8VQJ5Q1Q1Q1Q1Q1Q1Q3Q',
    '01H9ZQ8VQJ5Q1Q1Q1Q1Q1Q1Q1Q',
    'user'
) ON CONFLICT DO NOTHING;

-- Create view for user with roles
CREATE VIEW user_with_roles AS
SELECT 
    u.*,
    ARRAY_AGG(ur.role) AS roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
WHERE u.deleted_at IS NULL
GROUP BY u.id;

-- Create function to generate ULID
CREATE OR REPLACE FUNCTION generate_ulid()
RETURNS CHAR(26) AS $$
DECLARE
    timestamp BIGINT;
    random_bytes BYTEA;
    ulid CHAR(26);
BEGIN
    -- Get current timestamp in milliseconds
    timestamp := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
    
    -- Generate random bytes
    random_bytes := gen_random_bytes(10);
    
    -- Encode as Crockford's Base32
    ulid := encode_ulid(timestamp, random_bytes);
    
    RETURN ulid;
END;
$$ LANGUAGE plpgsql;

-- Create function to encode ULID
CREATE OR REPLACE FUNCTION encode_ulid(timestamp BIGINT, randomness BYTEA)
RETURNS CHAR(26) AS $$
DECLARE
    encoding CHAR(32) := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    ulid CHAR(26);
    i INTEGER;
    n BIGINT;
    part BYTEA;
BEGIN
    -- Encode timestamp (10 characters)
    FOR i IN 9 DOWNTO 0 LOOP
        n := (timestamp >> (i * 5)) & 31;
        ulid := ulid || substr(encoding, n + 1, 1);
    END LOOP;
    
    -- Encode randomness (16 characters)
    FOR i IN 0 TO 9 LOOP
        IF i < 8 THEN
            n := (get_byte(randomness, i // 2) >> ((1 - (i % 2)) * 4)) & 15;
        ELSE
            n := get_byte(randomness, i + 2 - 8) & 31;
        END IF;
        ulid := ulid || substr(encoding, n + 1, 1);
    END LOOP;
    
    RETURN ulid;
END;
$$ LANGUAGE plpgsql;