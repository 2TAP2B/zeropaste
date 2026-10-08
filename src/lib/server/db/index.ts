import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import schemaSql from './schema.sql?raw';

export type DB = Database.Database;

let db: DB | null = null;

export function openDb(dbPath: string): DB {
	if (db) return db;
	mkdirSync(dirname(dbPath), { recursive: true });
	db = new Database(dbPath);
	db.pragma('journal_mode = WAL');
	db.pragma('foreign_keys = ON');
	db.exec(schemaSql);
	return db;
}

export function getDb(): DB {
	const current = db;
	if (!current) throw new Error('db not opened; call openDb first');
	return current;
}

export function closeDb(): void {
	db?.close();
	db = null;
}
