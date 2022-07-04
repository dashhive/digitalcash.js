#!/usr/bin/env node
"use strict";

require("dotenv").config({ path: ".env" });
require("dotenv").config({ path: ".env.secret" });

let Fs = require("fs").promises;

let Dashcore = require("@dashevo/dashcore-lib");
let Wallet = require("./_wallet.js");

/**
 * @param {Object} opts
 * @param {String} opts.addr - full name or prefix of public address
 * @param {String} [opts.filepath] - where to export the file, or '-' for standard out (defaults to <addr>.wif in the current directory)
 * // TODO - hd options for account, index, etc
 */
async function exportKey({ addr, filepath }) {
  let keypath = await Wallet._findWifPath(addr);
  if (!keypath) {
    // TODO CLIError (handle by printing message and existing)
    console.error(`no managed key matches '${addr}'`);
    process.exit(1);
    return;
  }
  let key = await Wallet._maybeReadKeyFileRaw(keypath);
  if (!key) {
    throw new Error(`impossible error: couldn't find '${keypath}'`);
  }

  if (!key.encrypted) {
    console.info(`📖 ${key.addr} [already decrypted]`);
  }

  if ("-" === filepath) {
    console.info(key.wif);
    return;
  }

  if (!filepath) {
    filepath = `${key.addr}.wif`;
  }

  let err = await Fs.access(filepath).catch(Object);
  if (!err) {
    // TODO CLIError
    console.info(`'${filepath}' already exists (will not overwrite)`);
    process.exit(1);
    return;
  }

  let pk = new Dashcore.PrivateKey(key.wif);
  let checkAddr = pk.toAddress().toString();

  console.info(`🔓 Wrote ${filepath}`);
  await Fs.writeFile(filepath, `${key.wif}\n`, "utf8");

  if (checkAddr !== key.addr) {
    console.warn(`warn: ${key.addr}.wif contains a key for ${checkAddr}`);
  }

  return;
}

async function main() {
  // TODO --all for all keys in a single file `keys.wallet`?
  //      or directory `./wallet/<addr>.wif`
  let name = process.argv[2] || "";
  let filepath = process.argv[3] || "";
  if (!name) {
    console.error(`Usage: export <address-or-prefix> [filename | -]`);
    process.exit(1);
    return;
  }

  await Wallet._init();
  await exportKey({ addr: name, filepath });
}

main()
  .then(function () {
    process.exit(0);
  })
  .catch(function (err) {
    console.error(err);
    process.exit(1);
  });
