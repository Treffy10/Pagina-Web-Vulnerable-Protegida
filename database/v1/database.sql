BEGIN TRANSACTION;
CREATE TABLE files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            description TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
INSERT INTO "files" VALUES(1,1,'nota.txt','Archivo de ejemplo (admin)');
INSERT INTO "files" VALUES(2,2,'reporte.csv','Archivo de ejemplo (jgomez)');
CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
INSERT INTO "users" VALUES(1,'admin','8511e47e5db7e4a4adcca39a7deb5f2c');
INSERT INTO "users" VALUES(2,'jgomez','42f749ade7f9e195bf475f37a44cafcb');
INSERT INTO "users" VALUES(3,'mlopez','6af6a334e946ab5123cd8760db378cfb');
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('users',3);
INSERT INTO "sqlite_sequence" VALUES('files',2);
COMMIT;
