# GostCryptography

.NET driver for [ViPNet CSP](http://www.infotecs.ru/) and [CryptoPro CSP](http://www.cryptopro.ru/).
Implements crypto algorithms based on Russian national cryptographic standards `GOST 28147-89`, `GOST R 34.12`,
`GOST R 34.10` and `GOST R 34.11`. Also provides abstractions to sign and verify `CMS/PKCS #7` messages, sign,
verify and encrypt XML documents.

- [NuGet Package](https://www.nuget.org/packages/GostCryptography)
- [Examples](Source/GostCryptography.Tests)
- [License](LICENSE)

## Implemented Algorithms

- [Symmetric algorithm based on GOST 28147-89](Source/GostCryptography/Gost_28147_89/Gost_28147_89_SymmetricAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on GOST 28147-89](Source/GostCryptography/Gost_28147_89/Gost_28147_89_ImitHashAlgorithm.cs)

- [Symmetric algorithm based on GOST R 34.12 Magma](Source/GostCryptography/Gost_28147_89/Gost_3412_M_SymmetricAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on GOST R 34.12 Magma](Source/GostCryptography/Gost_28147_89/Gost_3412_M_ImitHashAlgorithm.cs)

- [Symmetric algorithm based on GOST R 34.12 Kuznyechik](Source/GostCryptography/Gost_28147_89/Gost_3412_K_SymmetricAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on GOST R 34.12 Kuznyechik](Source/GostCryptography/Gost_28147_89/Gost_3412_K_ImitHashAlgorithm.cs)

- [Hash algorithm based on GOST R 34.11-94](Source/GostCryptography/Gost_R3411/Gost_R3411_94_HashAlgorithm.cs), [2012/256](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_256_HashAlgorithm.cs), [2012/512](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_512_HashAlgorithm.cs)
- [Hash-based Message Authentication Code (HMAC) based on GOST R 34.11-94](Source/GostCryptography/Gost_R3411/Gost_R3411_94_HMAC.cs), [2012/256](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_256_HMAC.cs), [2012/512](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_512_HMAC.cs)
- [Pseudorandom Function (PRF) based on GOST R 34.11-94](Source/GostCryptography/Gost_R3411/Gost_R3411_94_PRF.cs), [2012/256](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_256_PRF.cs), [2012/512](Source/GostCryptography/Gost_R3411/Gost_R3411_2012_512_PRF.cs)

- [Asymmetric algorithm based on GOST R 34.10-2001](Source/GostCryptography/Gost_R3410/Gost_R3410_2001_AsymmetricAlgorithm.cs), [2012/256](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_256_AsymmetricAlgorithm.cs), [2012/512](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_512_AsymmetricAlgorithm.cs)
- [Asymmetric algorithm with an ephemeral key based on GOST R 34.10-2001](Source/GostCryptography/Gost_R3410/Gost_R3410_2001_EphemeralAsymmetricAlgorithm.cs), [2012/256](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm.cs), [2012/512](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm.cs)

- [Asymmetric key exchange formatter based on GOST R 34.10-2001](Source/GostCryptography/Gost_R3410/Gost_R3410_2001_KeyExchangeFormatter.cs), [2012/256](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_256_KeyExchangeFormatter.cs), [2012/512](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_512_KeyExchangeFormatter.cs)
- [Asymmetric key exchange deformatter based on GOST R 34.10-2001](Source/GostCryptography/Gost_R3410/Gost_R3410_2001_KeyExchangeDeformatter.cs), [2012/256](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_256_KeyExchangeDeformatter.cs), [2012/512](Source/GostCryptography/Gost_R3410/Gost_R3410_2012_512_KeyExchangeDeformatter.cs)

- [Asymmetric signature formatter based on GOST R 34.10-2001, 2012/256, 2012/512](Source/GostCryptography/Base/GostSignatureFormatter.cs)
- [Asymmetric signature deformatter based on GOST R 34.10-2001, 2012/256, 2012/512](Source/GostCryptography/Base/GostSignatureDeformatter.cs)

- [XML encryption based on GOST R 34.10-2001, 2012/256, 2012/512](Source/GostCryptography/Xml/GostEncryptedXml.cs)
- [XML signing based on XML-DSig and GOST R 34.10-2001, 2012/256, 2012/512](Source/GostCryptography/Xml/GostSignedXml.cs)
- [Signing and verifying of CMS/PKCS #7 messages based on GOST R 34.10-2001, 2012/256, 2012/512](Source/GostCryptography/Pkcs/GostSignedCms.cs)

## Tested On

- Windows 10 x64, CryptoPro CSP 5.0.13000 KC1
- Windows 10 x64, ViPNet CSP 4.2.8.51670

## Build instructions

To build package run in repository root:

```
dotnet build --configuration Release
```
