# Encrypted Password Manager

## Description
The **Encrypted Password Manager** is a JavaScript library designed to securely store and manage passwords and other private data. It combines strong encryption and hashing techniques to keep your data safe while ensuring easy integration into applications.

## What it Does
•	Uses a password provided by the user to create a master encryption key.

•	Protects stored data with AES-GCM encryption, ensuring it’s secure even if accessed without authorization.

•	Verifies the integrity of data with SHA-256 checksums to detect tampering.

•	Hashes key names to avoid storing sensitive information like domain names in plain text.

## Installation steps
•	Clone the repository

Open terminal and run the following command

git clone https://github.com/NancyMungai/Password-Manager


•	Install dependencies

Navigate to the project directory and install the necessary packages

npm install


•	Start the development server

npm run dev


•	Test in your browser

Open your browser and navigate to the local development server (typically http://localhost:3000 or as specified in the terminal output).


### Short answer questions on implementation:
1. Briefly describe your method for preventing the adversary from learning information about the lengths of the passwords stored in your password manager.
The method chosen is the use of AES-GCM encryption which includes a randomly generated Initialisation Vector for each entry. In addition, each entry stored in the key-value store is in a consistent format to ensure lengths of encrypted values are less predictable.

2. Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument for why the attack is prevented in your scheme.
The domain name is hashed using SHA-256. The hashed value is then used as they key to store the encrypted password data, meaning each password is bound to its specific domain. 

3. In our proposed defense against the rollback attack (Section 2.2), we assume that we can store the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to assume that such a trusted location exists, in order to defend against rollback attacks? Briefly justify your answer.
Yes it is necessary to assume a trusted location exists to store the SHA-256 checksum. This is used to validate the integrity and freshness of the stored data. Were there no trusted location, it would be possible to replace the password store and checksum with an outdated version, causing the data to roll back to a previous state.
  
4. Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple
times with the same input), we were able to look up domain names using their HMAC values. There are also randomized MACs, which can output different tags on multiple runs with the same input. Explain how you would do the look up if you had to use a randomized MAC instead of HMAC. Is there a performance penalty involved, and if so, what?
If using a randomized MAC, we would need to store another unique deterministic identifier for each entry. The identifier would allow retrieval without needing a consistent MAC value. Each time a password is stored/retrieved, we would generate and store this deterministic identifier for domain name lookups. 
The performance penalty is that each lookup would require both the deterministic identifier lookup and the MAC generation for the encryption and decryption process.

5. In our specification, we leak the number of records in the password manager. Describe an approach to reduce the information leaked about the number of records. Specifically, if there are k records, your scheme should only leak log2(k) (that is, if k1 and k2 are such that log2(k1)  = log2(k2) , the attacker should not be able to distinguish between a case where the true number of records is k1 and another case where the true number of records is k2).
The approach would involve organizing the records into fixed size groups so that if there are k entries, only the approximate size is revealed. This means the system would only leak log2(k2), preventing the exact number of records from being guessed or inferred.

6. What is a way we can add multi-user support for specific sites to our password manager
system without compromising security for other sites that these users may wish to store
passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes) that either of them can get and update, without allowing the other to access their passwords for other websites
To add multi-user support for specific sites, we can use a shared key which is encrypted separately for each user. This allows both users, Alice and Bob, to decrypt the same password for a shared domain, while non-shared entries remain encrypted with individual master keys, preserving privacy for other sites.

