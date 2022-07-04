"use strict";

let Wallet = module.exports;

let HOME = process.env.HOME || "";

//@ts-ignore
let pkg = require("../package.json");

let Fs = require("fs").promises;
let Path = require("path");

let Cipher = require("./_cipher.js");
//let Dash = require("../lib/dash.js");
//let Insight = require("../lib/insight.js");
let Prompt = require("./_prompt.js");
//let Qr = require("../lib/qr.js");
//let Ws = require("../lib/ws.js");

//let Dashcore = require("@dashevo/dashcore-lib");

// TODO config option
let configdir = `.config/${pkg.name}`;
let keysDir = Path.join(HOME, `${configdir}/keys`);
let keysDirRel = `~/${configdir}/keys`;
let shadowPath = Path.join(HOME, `${configdir}/shadow`);
//let defaultWifPath = Path.join(HOME, `${configdir}/default`);
let cmds = {};

const NO_SHADOW = "NONE";

// TODO config option
Wallet._init = async function () {
  await Fs.mkdir(keysDir, {
    recursive: true,
  });
};

/**
 * @param {String} wif - the private key encoded as Base58Check
 * @param {String} addr - the public key hash encoded as Base58Check
 */
Wallet._save = async function (wif, addr) {
  let filename = `~/${configdir}/keys/${addr}.wif`;
  let filepath = Path.join(`${keysDir}/${addr}.wif`);

  /*
  let note = "";
  if (name) {
    filename = name;
    filepath = name;
    note = `\n(for pubkey address ${addr})`;
    let err = await Fs.access(filepath).catch(Object);
    if (!err) {
      // TODO
      return;
    }
  }
  */

  await Fs.writeFile(filepath, wif, "utf8");
  /*
  if (!name && !defaultKey) {
    await Fs.writeFile(defaultWifPath, addr, "utf8");
  }
  */

  return {
    filename,
    filepath,
    note: "",
  };
};

async function initPassphrase() {
  let needsInit = false;
  let shadow = await Fs.readFile(shadowPath, "utf8").catch(
    emptyStringOnErrEnoent,
  );
  if (!shadow) {
    needsInit = true;
  }
  if (needsInit) {
    await cmds.getPassphrase({}, []);
  }
}

// tuple example {Promise<[String, Boolean]>}
/**
 * @param {Object} [opts]
 * @param {Boolean} [opts.force]
 * @param {String} plainWif
 */
Wallet._maybeEncrypt = async function (plainWif, opts) {
  let passphrase = cmds._getPassphrase();
  if (!passphrase) {
    let result = await cmds.getPassphrase({}, []);
    passphrase = result.passphrase;
  }
  if (!passphrase) {
    if (opts?.force) {
      throw new Error(`no passphrase with which to encrypt file`);
    }
    return plainWif;
  }

  let key128 = await Cipher.deriveKey(passphrase);
  let cipher = Cipher.create(key128);
  return cipher.encrypt(plainWif);
};

/**
 * @param {Object} state
 * @param {Boolean} [state._askPreviousPassphrase] - don't ask for passphrase again
 * @param {Array<String>} args
 */
async function setPassphrase({ _askPreviousPassphrase }, args) {
  let result = {
    passphrase: "",
    changed: false,
  };
  let date = getFsDateString();

  // get the old passphrase
  if (false !== _askPreviousPassphrase) {
    // TODO should contain the shadow?
    await cmds.getPassphrase({ _rotatePassphrase: true }, []);
  }

  // get the new passphrase
  let newPassphrase = await promptPassphrase();
  let curShadow = await Fs.readFile(shadowPath, "utf8").catch(
    emptyStringOnErrEnoent,
  );

  let newShadow = await Cipher.shadowPassphrase(newPassphrase);
  await Fs.writeFile(shadowPath, newShadow, "utf8");

  let rawKeys = await readAllKeys();
  let encAddrs = rawKeys
    .map(function (raw) {
      if (raw.encrypted) {
        return raw.addr;
      }
    })
    .filter(Boolean);

  // backup all currently encrypted files
  //@ts-ignore
  if (encAddrs.length) {
    let filepath = Path.join(HOME, `${configdir}/keys.${date}.bak`);
    console.info(``);
    console.info(`Backing up previous (encrypted) keys:`);
    encAddrs.unshift(`SHADOW:${curShadow}`);
    await Fs.writeFile(filepath, encAddrs.join("\n") + "\n", "utf8");
    console.info(`  ~/${configdir}/keys.${date}.bak`);
    console.info(``);
  }
  cmds._setPassphrase(newPassphrase);

  await encryptAll(rawKeys, { rotateKey: true });

  result.passphrase = newPassphrase;
  result.changed = true;
  return result;
}

async function promptPassphrase() {
  let newPassphrase;
  for (;;) {
    newPassphrase = await Prompt.prompt("Enter (new) passphrase: ", {
      mask: true,
    });
    newPassphrase = newPassphrase.trim();

    let _newPassphrase = await Prompt.prompt("Enter passphrase again: ", {
      mask: true,
    });
    _newPassphrase = _newPassphrase.trim();

    let match = Cipher.secureCompare(newPassphrase, _newPassphrase);
    if (match) {
      break;
    }

    console.error("passphrases do not match");
  }
  return newPassphrase;
}

/**
 * Import and Encrypt
 * @param {Object} opts
 * @param {String} opts.keypath
 */
async function importKey({ keypath }) {
  let key = await maybeReadKeyFileRaw(keypath);
  if (!key?.wif) {
    console.error(`no key found for '${keypath}'`);
    process.exit(1);
    return;
  }

  let encWif = await Wallet._maybeEncrypt(key.wif);
  let icon = "💾";
  if (encWif.includes(":")) {
    icon = "🔐";
  }
  let date = getFsDateString();

  await safeSave(
    Path.join(keysDir, `${key.addr}.wif`),
    encWif,
    Path.join(keysDir, `${key.addr}.${date}.bak`),
  );

  console.info(`${icon} Imported ${keysDirRel}/${key.addr}.wif`);
  console.info(``);

  return key.addr;
}

/**
 * @param {Object} opts
 * @param {Boolean} [opts._rotatePassphrase]
 * @param {Boolean} [opts._force]
 * @param {Array<String>} args
 */
cmds.getPassphrase = async function ({ _rotatePassphrase, _force }, args) {
  let result = {
    passphrase: "",
    changed: false,
  };
  /*
  if (!_rotatePassphrase) {
    let cachedphrase = cmds._getPassphrase();
    if (cachedphrase) {
      return cachedphrase;
    }
  }
  */

  // Three possible states:
  //   1. no shadow file yet (ask to set one)
  //   2. empty shadow file (initialized, but not set - don't ask to set one)
  //   3. encrypted shadow file (initialized, requires passphrase)
  let needsInit = false;
  let shadow = await Fs.readFile(shadowPath, "utf8").catch(
    emptyStringOnErrEnoent,
  );
  if (!shadow) {
    needsInit = true;
  } else if (NO_SHADOW === shadow && _force) {
    needsInit = true;
  }

  // State 1: not initialized, what does the user want?
  if (needsInit) {
    for (;;) {
      let no;
      if (!_force) {
        no = await Prompt.prompt(
          "Would you like to set an encryption passphrase? [Y/n]: ",
        );
      }

      // Set a passphrase and create shadow file
      if (!no || ["yes", "y"].includes(no.toLowerCase())) {
        result = await setPassphrase({ _askPreviousPassphrase: false }, args);
        cmds._setPassphrase(result.passphrase);
        return result;
      }

      // ask user again
      if (!["no", "n"].includes(no.toLowerCase())) {
        continue;
      }

      // No passphrase, create a NONE shadow file
      await Fs.writeFile(shadowPath, NO_SHADOW, "utf8");
      return result;
    }
  }

  // State 2: shadow already initialized to empty
  // (user doesn't want a passphrase)
  if (!shadow) {
    cmds._setPassphrase("");
    return result;
  }

  // State 3: passphrase & shadow already in use
  for (;;) {
    let prompt = `Enter passphrase: `;
    if (_rotatePassphrase) {
      prompt = `Enter (current) passphrase: `;
    }
    result.passphrase = await Prompt.prompt(prompt, {
      mask: true,
    });
    result.passphrase = result.passphrase.trim();
    if (!result.passphrase || "q" === result.passphrase) {
      console.error("cancel: no passphrase");
      process.exit(1);
      return result;
    }

    let match = await Cipher.checkPassphrase(result.passphrase, shadow);
    if (match) {
      cmds._setPassphrase(result.passphrase);
      console.info(``);
      return result;
    }

    console.error("incorrect passphrase");
  }

  throw new Error("SANITY FAIL: unreachable return");
};

cmds._getPassphrase = function () {
  return "";
};

/**
 * @param {String} passphrase
 */
cmds._setPassphrase = function (passphrase) {
  // Look Ma! A private variable!
  cmds._getPassphrase = function () {
    return passphrase;
  };
};

async function listManagedKeynames() {
  let nodes = await Fs.readdir(keysDir);

  return nodes.filter(isNamedLikeKey);
}

/**
 * @throws
 */
async function readAllKeys() {
  let wifnames = await listManagedKeynames();

  /** @type Array<RawKey> */
  let keys = [];
  await wifnames.reduce(async function (promise, wifname) {
    await promise;

    let keypath = Path.join(keysDir, wifname);
    let key = await maybeReadKeyFileRaw(keypath);
    if (!key?.wif) {
      return;
    }

    if (`${key.addr}.wif` !== wifname) {
      throw new Error(
        `computed pubkey '${key.addr}' of WIF does not match filename '${keypath}'`,
      );
    }

    keys.push(key);
  }, Promise.resolve());

  return keys;
}

/**
 * @param {String} filepath
 * @param {Object} [opts]
 * @param {Boolean} opts.wif
 * @returns {Promise<String>}
 */
async function maybeReadKeyFile(filepath, opts) {
  let key = await maybeReadKeyFileRaw(filepath, opts);
  if (false === opts?.wif) {
    return key?.addr || "";
  }
  return key?.wif || "";
}

/**
 * @param {String} filepath
 * @param {Object} [opts]
 * @param {Boolean} opts.wif
 * @returns {Promise<RawKey?>}
 */
async function maybeReadKeyFileRaw(filepath, opts) {
  let privKey = await Fs.readFile(filepath, "utf8").catch(
    emptyStringOnErrEnoent,
  );
  privKey = privKey.trim();
  if (!privKey) {
    return null;
  }

  let encrypted = false;
  if (privKey.includes(":")) {
    encrypted = true;
    try {
      if (false !== opts?.wif) {
        privKey = await decrypt(privKey);
      }
    } catch (err) {
      //@ts-ignore
      console.error(err.message);
      console.error(`passphrase does not match for key ${filepath}`);
      process.exit(1);
    }
  }
  if (false === opts?.wif) {
    return {
      addr: Path.basename(filepath, ".wif"),
      encrypted: encrypted,
      wif: "",
    };
  }

  //let pk = new Dashcore.PrivateKey(privKey);
  //let pub = pk.toAddress().toString();

  return {
    addr: Path.basename(filepath, ".wif"),
    encrypted: encrypted,
    wif: privKey,
  };
}

/**
 * @param {String} encWif
 */
async function decrypt(encWif) {
  let passphrase = cmds._getPassphrase();
  if (!passphrase) {
    let result = await cmds.getPassphrase({}, []);
    passphrase = result.passphrase;
    // we don't return just in case they're setting a passphrase to
    // decrypt a previously encrypted file (i.e. for recovery from elsewhere)
  }
  let key128 = await Cipher.deriveKey(passphrase);
  let cipher = Cipher.create(key128);

  return cipher.decrypt(encWif);
}

//
// Specific Utility Functions
//

/**
 * @param {String} name - ex: Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.wif.enc
 */
function isNamedLikeKey(name) {
  // TODO distinguish with .enc extension?
  let hasGoodLength = 34 + 4 === name.length || 34 + 4 + 4 === name.length;
  let knownExt = name.endsWith(".wif") || name.endsWith(".wif.enc");
  let isTmp = name.startsWith(".") || name.startsWith("_");
  return hasGoodLength && knownExt && !isTmp;
}

//
// General Utility Functions
//

function getFsDateString() {
  // YYYY-MM-DD_hh-mm_ss
  let date = new Date()
    .toISOString()
    .replace(/:/g, ".")
    .replace(/T/, "_")
    .replace(/\.\d{3}.*/, "");
  return date;
}

/**
 * @param {Error & { code: String }} err
 * @throws
 */
function emptyStringOnErrEnoent(err) {
  if ("ENOENT" !== err.code) {
    throw err;
  }
  return "";
}

/**
 * @param {String} filepath
 * @param {String} wif
 * @param {String} bakpath
 */
async function safeSave(filepath, wif, bakpath) {
  let tmpPath = `${bakpath}.tmp`;
  await Fs.writeFile(tmpPath, wif, "utf8");
  let err = await Fs.access(filepath).catch(Object);
  if (!err) {
    await Fs.rename(filepath, bakpath);
  }
  await Fs.rename(tmpPath, filepath);
  if (!err) {
    await Fs.unlink(bakpath);
  }
}
