# Libsodium's-crypto_box-with-BouncyCastle

Implementation of Libsodium's crypto_box with BouncyCastle and comparison with a Java Libsodium wrapper (Lazysodium).

Dependencies:
```none
org.bouncycastle:bcprov-jdk18on:1.78.1
com.goterl:lazysodium-java:5.1.1
org.slf4j:slf4j-api:1.7.30
org.slf4j:slf4j-simple:1.7.30
net.java.dev.jna:jna:5.8.0
com.goterl:resource-loader:2.0.1
```

Sample output:
```none
nonce: 8edba568653c7c1cee329f97208f9be8cdab06cb3d9225e8
ciphertext - BC: 10b9136efff21b4f2208535cedf4d9d977816f26f7a02bcae5399b9d8227ece554783b3c32e56df2f433f6ea2eacb1d9bdffa772b81d08279058dc
ciphertext - LS: 10b9136efff21b4f2208535cedf4d9d977816f26f7a02bcae5399b9d8227ece554783b3c32e56df2f433f6ea2eacb1d9bdffa772b81d08279058dc
```
