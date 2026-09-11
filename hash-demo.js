import bcrypt from 'bcrypt';

const passwords = [
  "Nairobi2026!",
  "securePass123",
  "myS3cretK3y",
  "W@njiku#Strong",
  "simple"
];

async function RunHashDemo() { 
    // ---part 1: Hash 5 different passwords ---
    console.log('--- hashing 5 passwords ---');
    const storedHashes = [];

    for (const password of passwords) {
        // hash password with const factor of 10
        const hash = await bcrypt.hash(password, 10);
        storedHashes.push(hash);
        console.log('Passwords: "${password}" hashed to: "${hash}"');
    }

    // ---part 2 :Demonstrate salting (same password, diifferent hashes) ---
    console.log('\nSame password, different hashes:');
    const sample = passwords[0];  // "Nairobi2026!"

    const hash1 = await bcrypt.hash(sample, 10);
    const hash2 = await bcrypt.hash(sample, 10);
    
    console.log('"${sample}" hashed to: "${hash1}"');
    console.log('"${sample}" hashed to: "${hash2}"');
    console.log('Hashes are differnt: ${hash1 !== hash2}');

    //3. verify passwords using bcrypt.compare()
    console.log('\nverification:');
    const isValid = await bcrypt.compare(sample, hash1);
    console.log('"${sample}" vs Hash 1: ${isValid}');

    const isInvalid = await bcrypt.compare('wrongPassword', hash1);
    console.log('"wrongPassword" vs Hash 1: ${isInvalid}');
}

RunHashDemo();
