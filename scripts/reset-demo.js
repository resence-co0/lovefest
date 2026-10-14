import dotenv from 'dotenv';
dotenv.config({ path: process.env.DOTENV_CONFIG_PATH || '.env.local' });
import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);
const exchangeId = process.env.EXCHANGE_ID || '00000000-0000-4000-8000-000000000001';
const roster = [
  ['+2348030000001', 'Adaeze Okafor'], ['+2348030000002', 'Bamidele Yusuf'],
  ['+2348030000003', 'Chiamaka Peter'], ['+2348030000004', 'David Musa'],
  ['+2348030000005', 'Esther James'], ['+2348030000006', 'Favour Ibrahim']
];

await sql`DELETE FROM exchanges WHERE id = ${exchangeId}`;
await sql`INSERT INTO exchanges (id, title, fellowship, description, guidance, cutoff_at, exchange_at, is_open, is_closed, is_drawn)
  VALUES (${exchangeId}, 'Love Feast Secret Santa', 'ECWA Goodnews Dawaki Youth Fellowship', 'A small act of kindness for our end-of-year gathering.', 'Suggested gift range: ₦5,000 – ₦10,000', '2026-11-15T18:00:00+01:00', '2026-11-21', true, false, false)`;
for (const [phone, name] of roster) await sql`INSERT INTO eligible_members (id, exchange_id, normalized_phone, display_name) VALUES (${crypto.randomUUID()}, ${exchangeId}, ${phone}, ${name})`;
console.log('Demo database reset with six fictional eligible members.');
