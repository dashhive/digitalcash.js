#!/usr/bin/env node
"use strict";

require("dotenv").config({ path: ".env" });
require("dotenv").config({ path: ".env.secret" });

let Dashcore = require("@dashevo/dashcore-lib");
let Wallet = require("./_wallet.js");

/**
 * @param {Object} psuedoState
 * @param {Boolean} [psuedoState.plainText] - don't encrypt
 * // TODO - hd options for account, index, etc
 */
async function generateKey({ plainText }) {
  //@ts-ignore - TODO submit JSDoc PR for Dashcore
  // (if no string is given, a new key is created)
  let pk = new Dashcore.PrivateKey();

  let addr = pk.toAddress().toString();
  let plainWif = pk.toWIF();

  let wif = plainWif;
  if (!plainText) {
    wif = await Wallet._maybeEncrypt(plainWif);
  }
  await Wallet._save(wif, addr).then(function ({ filepath, filename, note }) {
    console.info(``);
    console.info(`Generated ${filename} ${note}`);
    console.info(``);
    return addr;
  });
  /*
    // TODO throw EEXIST when we're doing non-random generation
    .catch(function (err) {
      if ("EEXIST" === err.code) {
        console.info(`'${err.filepath}' already exists (will not overwrite)`);
        process.exit(0);
        return "";
      }

      throw err;
    });
  */
}

async function main() {
  await Wallet._init();
  await generateKey({ plainText: false });
}

main()
  .then(function () {
    process.exit(0);
  })
  .catch(function (err) {
    console.error(err);
    process.exit(1);
  });
