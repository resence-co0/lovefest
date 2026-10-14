import dotenv from 'dotenv';
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || '.env.local' });
import { readFile } from 'node:fs/promises';
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);
const schema = await readFile(new URL('../schema.sql', import.meta.url), 'utf8');
for (const statement of schema.split(';').map(item => item.trim()).filter(Boolean)) await sql.query(statement);
console.log('Database schema ready.');
