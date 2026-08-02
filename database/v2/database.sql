BEGIN TRANSACTION;
CREATE TABLE files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
INSERT INTO "files" VALUES(1,1,'a1b2c3d4e5f6.txt','nota.txt','Archivo de ejemplo (admin)','2026-08-02 00:35:46');
INSERT INTO "files" VALUES(2,2,'f6e5d4c3b2a1.csv','reporte.csv','Archivo de ejemplo (jgomez)','2026-08-02 00:35:46');
CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
INSERT INTO "users" VALUES(1,'admin','$2b$12$ItrjZZn4cjW8i1ENocMLDephSFSD.gy1Ak1HPUU4RdH2Tc/MPbW8q','2026-08-02 00:35:45',0,NULL);
INSERT INTO "users" VALUES(2,'jgomez','$2b$12$vqDq56pR4O0wCP24JQpGf.t9lIeshAARJK756spz6T8lsotEgR2g6','2026-08-02 00:35:46',0,NULL);
INSERT INTO "users" VALUES(3,'mlopez','$2b$12$oRp/UlXRFKCToP8XpZAIBOODFtkmOBGumkttKH5z86QSNlqHDqzQm','2026-08-02 00:35:46',0,NULL);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('users',3);
INSERT INTO "sqlite_sequence" VALUES('files',2);
COMMIT;
