-- ============================================================
--  WebLab — Schéma MySQL
--  À importer via phpMyAdmin ou : mysql -u root < schema.sql
-- ============================================================

DROP DATABASE IF EXISTS weblab;
CREATE DATABASE weblab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE weblab;

-- ----------- USERS -----------
CREATE TABLE users (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  username    VARCHAR(64) UNIQUE NOT NULL,
  email       VARCHAR(128),
  password    VARCHAR(64) NOT NULL,   -- ⚠️ md5 sans salt
  role        ENUM('user', 'admin') DEFAULT 'user',
  bio         TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------- PRODUCTS -----------
CREATE TABLE products (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(128) NOT NULL,
  description TEXT,
  price       DECIMAL(10,2),
  stock       INT DEFAULT 0,
  rating      DECIMAL(2,1) DEFAULT 4.0,
  internal_cost DECIMAL(10,2),   -- ⚠️ exposé via IDOR
  supplier    VARCHAR(128),       -- ⚠️ idem
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------- ORDERS -----------
CREATE TABLE orders (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  product_id  INT NOT NULL,
  quantity    INT DEFAULT 1,
  total       DECIMAL(10,2),
  status      ENUM('pending', 'paid', 'shipped') DEFAULT 'pending',
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- ----------- INVOICES -----------
CREATE TABLE invoices (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  order_id    INT NOT NULL,
  number      VARCHAR(32) UNIQUE,
  amount      DECIMAL(10,2),
  pdf_path    VARCHAR(255),
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- ----------- COMMENTS (Stored XSS) -----------
CREATE TABLE comments (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  author      VARCHAR(64),
  content     TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------- SESSIONS (manuel — pas via PHP session_start) -----------
CREATE TABLE sessions (
  id          VARCHAR(64) PRIMARY KEY,
  user_id     INT,
  token       VARCHAR(255),
  expires_at  TIMESTAMP,
  ip          VARCHAR(45),
  user_agent  VARCHAR(255)
);

-- ----------- JWT TOKENS -----------
CREATE TABLE jwt_tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT,
  token       TEXT,
  issued_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  revoked     TINYINT(1) DEFAULT 0
);

-- ----------- MESSAGES (privés — IDOR ciblé) -----------
CREATE TABLE messages (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sender_id   INT,
  recipient_id INT,
  subject     VARCHAR(255),
  body        TEXT,
  read_flag   TINYINT(1) DEFAULT 0,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
