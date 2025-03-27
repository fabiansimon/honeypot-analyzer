import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from './logger.js';

const SAFE_SRC = ['130.89.107.163'];
const VULNERABLE_USERS = [
  {
    name: 'admin',
    pw: 'churros',
    type: 'credentials',
  },
  {
    name: 'carlos',
    pw: 'worms',
    type: 'credentials',
  },
  {
    name: 'hunter',
    pw: 'detect',
    type: 'credentials',
  },
  {
    name: 'developer',
    type: 'weak-key',
  },
  {
    name: 'sysadmin',
    type: 'strong-key',
  },
];

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.join(__dirname, 'data');
const FILE_NAME = 'auth.log'; // SSH logging file
const OUTPUT_FILE = path.join(DATA_DIR, 'full_auth.log');
const SUMMARY_FILE = path.join(DATA_DIR, 'summary.json');

async function combineLogs() {
  const directories = await fs.promises.readdir(DATA_DIR);
  const entries = new Map();

  for (const dir of directories) {
    const filePath = path.join(DATA_DIR, dir, FILE_NAME);
    if (!fs.existsSync(filePath)) continue;

    const content = await fs.promises.readFile(filePath, 'utf8');
    const lines = content.split('\n').filter(Boolean);
    for (const line of lines) {
      const timestamp = line.split(' ')[0];
      entries.set(line, timestamp);
    }
  }

  const sorted = Array.from(entries.keys()).sort();
  await fs.promises.writeFile(OUTPUT_FILE, sorted.join('\n'));
}

function filterIntrusions() {
  const lines = fs.readFileSync(OUTPUT_FILE, 'utf8').split('\n');
  const intrusions = [];
  const attackers = new Map();
  const users = new Set(VULNERABLE_USERS.map(({ name }) => name));
  const safeIps = new Set(SAFE_SRC);

  const log = /^(?<timestamp>\S+) .*sshd\[.*\]: (?<message>.+)$/;
  const success =
    /Accepted (?<method>password|publickey) for (?<username>\S+) from (?<ip>\S+)/;
  const failed =
    /Failed (?<method>password|publickey) for (?<username>\S+) from (?<ip>\S+)/;

  for (const line of lines) {
    const match = log.exec(line);
    if (!match) continue;

    const { timestamp, message } = match.groups;

    let username, ip, type, method;
    if (success.test(message)) {
      ({ method, username, ip } = success.exec(message).groups);
      type = 'success';
    } else if (failed.test(message)) {
      ({ method, username, ip } = failed.exec(message).groups);
      type = 'failure';
    } else continue;

    if (!users.has(username) || safeIps.has(ip)) continue;

    const pick = VULNERABLE_USERS.find(({ name }) => name === username);
    const usedCreds = method === 'password';

    intrusions.push({
      timestamp,
      username,
      ip,
      type,
      methods: usedCreds ? 'credentials' : 'public-key',
      ...(usedCreds && type === 'success' && { password: pick.pw }),
    });

    // Count per attacker IP
    if (!attackers.has(ip)) {
      attackers.set(ip, 1);
    } else {
      attackers.set(ip, attackers.get(ip) + 1);
    }
  }

  const summaryData = {
    intrusions,
    summary: {
      ips: Object.fromEntries(attackers),
      distinctAttackers: attackers.size,
    },
  };

  fs.writeFileSync(SUMMARY_FILE, JSON.stringify(summaryData, null, 2));
  return { intrusions, sources: Array.from(attackers.keys()) };
}

async function analyze() {
  try {
    logger.info('Combining logs...');
    await combineLogs();
    logger.info('Filtering intrusions...');
    const { intrusions, sources } = filterIntrusions();
    logger.info(`Found ${intrusions.length} intrusions`);
    logger.info(`By ${sources.length} distinct IP Addresses`);
  } catch (error) {
    logger.error('Error:', error);
  }
}

analyze();
