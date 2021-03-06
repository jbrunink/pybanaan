BEGIN TRANSACTION;
DROP TABLE IF EXISTS `quotes`;
CREATE TABLE IF NOT EXISTS `quotes` (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`name`	TEXT,
	`quote`	TEXT
);
DROP TABLE IF EXISTS `karma`;
CREATE TABLE IF NOT EXISTS `karma` (
	`id`	INTEGER PRIMARY KEY AUTOINCREMENT,
	`name`	TEXT,
	`karma`	INTEGER
);
COMMIT;
