import { readFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';

const dbPath = process.argv[2];
if (!dbPath) {
	console.error('usage: node scripts/migrate.mjs <db path>');
	process.exit(1);
}
mkdirSync(dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.exec(readFileSync(new URL('../src/lib/server/db/schema.sql', import.meta.url), 'utf8'));
console.log(`migrated ${dbPath}`);
