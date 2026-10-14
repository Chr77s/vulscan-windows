-- 💀 VULN : backup SQL accessible publiquement (CWE-530)
-- Visible via http://localhost/WebLab/backup/database_2025.sql

INSERT INTO users (username, email, password, role) VALUES
  ('root_backup', 'root@weblab.lab', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin'),
  ('legacy_admin', 'legacy@weblab.lab', '0192023a7bbd73250516f069df18b500', 'admin');

-- Secrets DB de production
SET @DB_PROD_PASSWORD = 'P@ssw0rd_Pr0d_2024!!';
SET @STRIPE_API_KEY = 'sk_live_4242424242424242';
SET @JWT_SECRET = 'super_secret_jwt_key_changeme';
