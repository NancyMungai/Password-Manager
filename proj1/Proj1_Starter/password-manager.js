"use strict";

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
require('dotenv').config();
const MASTER_PASSWORD = process.env.MASTER_PASSWORD;

const PBKDF2_ITERATIONS = 100000;

class Keychain {
    constructor(iterations = PBKDF2_ITERATIONS) {
        this.data = {
            kvs: {},      // Encrypted key-value pairs with hashed keys
            salt: null ,   // Salt used for master key derivation
            domains: {}  
         
        };
        this.secrets = {};
        this.iterations = iterations;
    }

    static async init(password,  iterations = PBKDF2_ITERATIONS) {
        const keychain = new Keychain(iterations);
        const salt = getRandomBytes(16);
        const passwordBuffer = stringToBuffer(password);

        const baseKey = await subtle.importKey("raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]);

        keychain.secrets.masterKey = await subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PBKDF2_ITERATIONS },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
 // Derive HMAC key for swap attack defense
        keychain.secrets.hmacKey = await subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations },
            baseKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign", "verify"]
        );

        keychain.data.salt = salt;
        return keychain;
    }

    static async load(password, repr, trustedDataCheck,  iterations = PBKDF2_ITERATIONS) {
        const keychain = new Keychain(iterations);
        const parsedData = JSON.parse(repr);
        
        // Decode the stored salt from Base64
        const salt = decodeBuffer(parsedData.salt);
        const passwordBuffer = stringToBuffer(password);
        const baseKey = await subtle.importKey("raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveKey"]);

        // Derive the master key using PBKDF2 with the decoded salt
        keychain.secrets.masterKey = await subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: PBKDF2_ITERATIONS },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        keychain.secrets.hmacKey = await subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: salt, iterations },
            baseKey,
            { name: "HMAC", hash: "SHA-256", length: 256 },
            true,
            ["sign", "verify"]
        );

        // Verify data integrity using SHA-256 checksum if provided
        if (trustedDataCheck) {
            const checksumBuffer = await subtle.digest("SHA-256", stringToBuffer(repr));
            const computedChecksum = encodeBuffer(checksumBuffer);
            if (computedChecksum !== trustedDataCheck) {
                throw new Error("Checksum does not match, possible data tampering!");
            }
        }
        

       // Perform a quick decryption to verify the password (e.g., using a known entry)
    try {
        // Attempt to decrypt one of the entries to verify the password
        const testEntry = Object.values(parsedData.kvs)[0];
        if (testEntry) {
            const iv = decodeBuffer(testEntry.iv);
            const encryptedValue = decodeBuffer(testEntry.value);
            await subtle.decrypt({ name: "AES-GCM", iv: iv }, keychain.secrets.masterKey, encryptedValue);
        }
    } catch (error) {
        throw new Error("Incorrect password provided.");
    }

    keychain.data.kvs = parsedData.kvs;
    keychain.data.domains = parsedData.domains;
    keychain.data.salt = salt;
    return keychain;
}

    async dump() {
        // Serialize data and convert salt to Base64
        const kvsSerialized = JSON.stringify({
            kvs: this.data.kvs,
            domains: this.data.domains,
            salt: encodeBuffer(this.data.salt)
        });

        // Compute SHA-256 checksum
        const checksumBuffer = await subtle.digest("SHA-256", stringToBuffer(kvsSerialized));
        const checksum = encodeBuffer(checksumBuffer);

        return [kvsSerialized, checksum];
    }

    async set(name, value) {
        const iv = getRandomBytes(12); // IV for AES-GCM
        const valueBuffer = stringToBuffer(value);

        // Hash the domain name to avoid storing it in clear
        const nameHashBuffer = await subtle.digest("SHA-256", stringToBuffer(name));
        const nameHash = encodeBuffer(new Uint8Array(nameHashBuffer));

        // Encrypt the password using AES-GCM
        const encryptedValue = await subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            this.secrets.masterKey,
            valueBuffer
        );

        const hmac = await subtle.sign(
            { name: "HMAC" },
            this.secrets.hmacKey,
            nameHashBuffer
        );

          // Encrypt the domain name
          const domainIv = getRandomBytes(12);
          const encryptedDomain = await subtle.encrypt(
              { name: "AES-GCM", iv: domainIv },
              this.secrets.masterKey,
              stringToBuffer(name)
          );

        // Store the encrypted value and IV in kvs using the hashed name as the key
        this.data.kvs[nameHash] = {
            iv: encodeBuffer(iv),
            value: encodeBuffer(new Uint8Array(encryptedValue)),
            hmac: encodeBuffer(new Uint8Array(hmac)),
            domainIv: encodeBuffer(domainIv)

        };
          // Store the encrypted domain name
          this.data.domains[nameHash] = encodeBuffer(new Uint8Array(encryptedDomain));
          console.log(`Password for domain '${name}' has been set.`);
      
    }

    async get(name) {
        // Hash the domain name to retrieve the encrypted data
        const nameHashBuffer = await subtle.digest("SHA-256", stringToBuffer(name));
        const nameHash = encodeBuffer(new Uint8Array(nameHashBuffer));
        
        const entry = this.data.kvs[nameHash];
        if (!entry) return null;

        if (!entry.hmac) throw new Error("HMAC is missing for the entry.");
        
        const hmacValid = await subtle.verify(
            { name: "HMAC" },
            this.secrets.hmacKey,
            decodeBuffer(entry.hmac),
            nameHashBuffer
        );

        if (!hmacValid) 
            throw new Error("Data integrity check failed! Potential swap attack detected.");
        

        const iv = decodeBuffer(entry.iv);
        const encryptedValue = decodeBuffer(entry.value);

       
            const decryptedValue = await subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                this.secrets.masterKey,
                encryptedValue
            );

            return bufferToString(decryptedValue);
       
    }
    async getAll() {
        const allEntries = [];
        for (const hashedDomain in this.data.kvs) {
            const entry = this.data.kvs[hashedDomain];
            const encryptedDomain = this.data.domains[hashedDomain];
            if (encryptedDomain) {
                // Decrypt domain name
                const domainIv = decodeBuffer(entry.domainIv);
                const decryptedDomainBuffer = await subtle.decrypt(
                    { name: "AES-GCM", iv: domainIv },
                    this.secrets.masterKey,
                    decodeBuffer(encryptedDomain)
                );
                const domain = bufferToString(decryptedDomainBuffer);

                // Decrypt password
                const iv = decodeBuffer(entry.iv);
                const encryptedValue = decodeBuffer(entry.value);
                const decryptedValue = await subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    this.secrets.masterKey,
                    encryptedValue
                );
                const password = bufferToString(decryptedValue);

                allEntries.push({ domain, password });
            }
        }
        console.log(`Retrieved all entries:`, allEntries);
        return allEntries;
    }

    async remove(name) {
        const nameHashBuffer = await subtle.digest("SHA-256", stringToBuffer(name));
        const nameHash = encodeBuffer(new Uint8Array(nameHashBuffer));

        if (this.data.kvs.hasOwnProperty(nameHash)) {
            delete this.data.kvs[nameHash];
            return true;
        }
        return false;
    }
}

module.exports = { Keychain };
