# GostCryptography

GostCryptography is .NET driver for [ViPNet CSP](http://www.infotecs.ru/) and [CryptoPro CSP](http://www.cryptopro.ru/).
Provides abstractions for working with russian national cryptographic algorithms (GOST).

- [NuGet Package](https://www.nuget.org/packages/GostCryptography)
- [Examples](Source/GostCryptography.Tests)
- [License](LICENSE.md)

## Implemented algorithms

- [Symmetric algorithm based on the GOST 28147](Source/GostCryptography/Cryptography/Gost28147SymmetricAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on the GOST 28147](Source/GostCryptography/Cryptography/Gost28147ImitHashAlgorithm.cs)

- [Asymmetric algorithm based on the GOST R 34.10](Source/GostCryptography/Cryptography/Gost3410AsymmetricAlgorithm.cs)
- [Asymmetric algorithm with an ephemeral key based on the GOST R 34.10](Source/GostCryptography/Cryptography/Gost3410EphemeralAsymmetricAlgorithm.cs)

- [Hash algorithm based on the GOST R 34.11](Source/GostCryptography/Cryptography/Gost3411HashAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on the GOST R 34.11](Source/GostCryptography/Cryptography/Gost3411Hmac.cs)

- [Asymmetric key exchange deformatter based on the GOST R 34.10](Source/GostCryptography/Cryptography/GostKeyExchangeDeformatter.cs)
- [Asymmetric key exchange formatter based on the GOST R 34.10](Source/GostCryptography/Cryptography/GostKeyExchangeFormatter.cs)

- [Asymmetric signature deformatter based on the GOST R 34.10](Source/GostCryptography/Cryptography/GostSignatureDeformatter.cs)
- [Asymmetric signature formatter based on the GOST R 34.10](Source/GostCryptography/Cryptography/GostSignatureFormatter.cs)

- [Pseudorandom Function (PRF) based on the GOST R 34.11](Source/GostCryptography/Cryptography/Gost3411Prf.cs)

- [XML encryption based on the GOST R 34.10](Source/GostCryptography/Xml/GostEncryptedXml.cs)
- [XML signing based on XML-DSig and the GOST R 34.10](Source/GostCryptography/Xml/GostSignedXml.cs)
