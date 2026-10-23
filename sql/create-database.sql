-- Run once with a MySQL administrator account.
-- Change the application password before use.
CREATE DATABASE IF NOT EXISTS colorproxy_rag
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

CREATE USER IF NOT EXISTS 'colorproxy'@'localhost' IDENTIFIED BY 'change-me';
ALTER USER 'colorproxy'@'localhost' IDENTIFIED BY 'change-me';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON colorproxy_rag.* TO 'colorproxy'@'localhost';
FLUSH PRIVILEGES;

-- The tables and ngram FULLTEXT index are created by:
--   python tools/rag_admin.py init
