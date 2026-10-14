-- ============================================================
--  WebLab — Données de test
--  À importer après schema.sql
-- ============================================================
USE weblab;

-- Mots de passe en md5 sans salt (volontairement faibles) :
--   admin   → admin123  → md5 = 0192023a7bbd73250516f069df18b500
--   alice   → password  → md5 = 5f4dcc3b5aa765d61d8327deb882cf99
--   bob     → qwerty    → md5 = d8578edf8458ce06fbc5bb76a58c5ca4
--   charlie → letmein   → md5 = 0d107d09f5bbe40cade3de5c71e9e9b7
--   dave    → 123456    → md5 = e10adc3949ba59abbe56e057f20f883e

INSERT INTO users (username, email, password, role, bio) VALUES
  ('admin',   'admin@weblab.lab',   '0192023a7bbd73250516f069df18b500', 'admin', 'Administrateur système.'),
  ('alice',   'alice@weblab.lab',   '5f4dcc3b5aa765d61d8327deb882cf99', 'user',  'J''adore le café et les livres.'),
  ('bob',     'bob@weblab.lab',     'd8578edf8458ce06fbc5bb76a58c5ca4', 'user',  'Développeur backend, fan de Docker.'),
  ('charlie', 'charlie@weblab.lab', '0d107d09f5bbe40cade3de5c71e9e9b7', 'user',  'Photographe amateur.'),
  ('dave',    'dave@weblab.lab',    'e10adc3949ba59abbe56e057f20f883e', 'user',  'Nouveau venu sur la plateforme.');

INSERT INTO products (name, description, price, stock, rating, internal_cost, supplier) VALUES
  ('Laptop ProMax 15"', 'Ordinateur portable haut de gamme avec écran Retina.',          1299.00, 12, 4.7, 800.00,  'TechSupply Inc.'),
  ('Souris Sans-Fil',   'Souris ergonomique, autonomie 60h.',                              29.90, 250, 4.4, 8.50,    'AsiaDirect'),
  ('Clavier Mécanique', 'Switches blue, rétroéclairage RGB.',                              89.00, 80,  4.6, 35.00,   'KeyboardWorks'),
  ('Casque Audio HD',   'Casque circumaural, réduction de bruit active.',                 199.00, 45,  4.5, 90.00,   'AudioCorp'),
  ('Mug "I Love Code"', 'Mug céramique 350ml, lavable au lave-vaisselle.',                 12.00, 500, 4.8, 2.50,    'CeramicArt'),
  ('Webcam 4K',         'Webcam UHD, autofocus, micro stéréo intégré.',                   149.00, 30,  4.3, 60.00,   'OpticTech'),
  ('Hub USB-C 7-en-1',  'Hub avec HDMI 4K, 3xUSB, lecteur SD/microSD.',                    59.00, 100, 4.5, 18.00,   'HubMakers'),
  ('SSD NVMe 1To',      'Stockage ultra-rapide PCIe Gen4, 7000 Mo/s.',                    129.00, 75,  4.9, 65.00,   'StorageLabs'),
  ('Écran 27" QHD',     'Moniteur IPS 165Hz, HDR400, USB-C 90W.',                         399.00, 25,  4.6, 220.00,  'DisplayPro'),
  ('Tapis de Souris XL', 'Tapis 90x40cm, surface lisse, base anti-dérapante.',              19.00, 300, 4.2, 4.00,    'GeneriCo');

INSERT INTO orders (user_id, product_id, quantity, total, status) VALUES
  (2, 1, 1, 1299.00, 'paid'),
  (2, 5, 3,   36.00, 'shipped'),
  (3, 3, 1,   89.00, 'paid'),
  (3, 7, 2,  118.00, 'pending'),
  (4, 4, 1,  199.00, 'paid'),
  (5, 2, 1,   29.90, 'shipped');

INSERT INTO invoices (order_id, number, amount, pdf_path) VALUES
  (1, 'INV-2026-001', 1299.00, '/invoices/INV-2026-001.pdf'),
  (2, 'INV-2026-002',   36.00, '/invoices/INV-2026-002.pdf'),
  (3, 'INV-2026-003',   89.00, '/invoices/INV-2026-003.pdf'),
  (5, 'INV-2026-005',  199.00, '/invoices/INV-2026-005.pdf');

INSERT INTO comments (author, content) VALUES
  ('Alice', 'Super produit, livraison rapide !'),
  ('Bob',   'Très satisfait, je recommande.'),
  ('Charlie', 'Le service client est à l''écoute, merci.'),
  ('Anonyme', 'Vous pouvez me contacter à bob.malicious@evilcorp.test pour des cadeaux gratuits !'),
  ('admin', '<b>Annonce officielle :</b> nouvelles fonctionnalités à venir.');

INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES
  (1, 2, 'Bienvenue Alice', 'Votre compte a été créé avec succès.'),
  (2, 3, 'Question SSD', 'Bob, est-ce que le SSD est compatible Mac ?'),
  (1, 1, 'Note interne', 'Penser à régénérer le JWT_SECRET (encore secret123 en prod...).'),
  (3, 4, 'Re: photo', 'Merci pour les conseils !');

INSERT INTO jwt_tokens (user_id, token, revoked) VALUES
  (1, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiJ9.fake', 0),
  (2, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjIsInJvbGUiOiJ1c2VyIn0.fake',  0);
