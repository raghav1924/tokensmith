#!/usr/bin/env node
/**
 * TokenSmith Executable CLI Launcher
 * Author: Jatin Sharma (https://jatinsh.netlify.app/)
 */

import { runCli } from '../dist/cli.js';

runCli(process.argv.slice(2)).catch((err) => {
  console.error('Fatal TokenSmith Error:', err);
  process.exit(1);
});
