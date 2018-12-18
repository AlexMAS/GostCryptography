using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Asn1.Gost.Gost_R3410_94;

namespace GostCryptography.Asn1.Gost.PublicKey
{
	static class PkiConstants
	{
		// ГОСТ 28147-89

		private static readonly AlgorithmId Gost_28147_89_EncryptAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_28147_89_Constants.EncryptAlgorithm),
			new Gost_28147_89_Params());

		// ГОСТ Р 34.10-94

		private static readonly AlgorithmId Gost_R3410_94_KeyAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_94_Constants.KeyAlgorithm),
			new Gost_R3410_94_PublicKeyType());

		private static readonly AlgorithmId Gost_R3410_94_DhAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_94_Constants.DhAlgorithm),
			new Gost_R3410_94_DhPublicKeyType());

		private static readonly AlgorithmId Gost_R3410_94_SignatureAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_94_Constants.SignatureAlgorithm),
			new NullParams());

		private static readonly AlgorithmId Gost_R3411_94_HashAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_94_Constants.HashAlgorithm),
			new Gost_R3411_94_DigestParamsType());

		// ГОСТ Р 34.10-2001

		private static readonly AlgorithmId Gost_R3410_2001_KeyAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2001_Constants.KeyAlgorithm),
			new Gost_R3410_2001_PublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2001_DhAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2001_Constants.DhAlgorithm),
			new Gost_R3410_2001_DhPublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2001_SignatureAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2001_Constants.SignatureAlgorithm),
			new NullParams());

		private static readonly AlgorithmId Gost_R3411_2001_HashAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2001_Constants.HashAlgorithm),
			new Gost_R3411_2001_DigestParamsType());

		// ГОСТ Р 34.10-2012/256

		private static readonly AlgorithmId Gost_R3410_2012_256_KeyAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_256_Constants.KeyAlgorithm),
			new Gost_R3410_2012_256_PublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2012_256_DhAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_256_Constants.DhAlgorithm),
			new Gost_R3410_2012_256_DhPublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2012_256_SignatureAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_256_Constants.SignatureAlgorithm),
			new NullParams());

		private static readonly AlgorithmId Gost_R3411_2012_256_HashAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_256_Constants.HashAlgorithm),
			new Gost_R3411_2012_256_DigestParamsType());

		// ГОСТ Р 34.10-2012/512

		private static readonly AlgorithmId Gost_R3410_2012_512_KeyAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_512_Constants.KeyAlgorithm),
			new Gost_R3410_2012_512_PublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2012_512_DhAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_512_Constants.DhAlgorithm),
			new Gost_R3410_2012_512_DhPublicKeyType());

		private static readonly AlgorithmId Gost_R3410_2012_512_SignatureAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_512_Constants.SignatureAlgorithm),
			new NullParams());

		private static readonly AlgorithmId Gost_R3411_2012_512_HashAlgorithm = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost_R3410_2012_512_Constants.HashAlgorithm),
			new Gost_R3411_2012_512_DigestParamsType());


		public static readonly AlgorithmId[] SupportedAlgorithms =
		{
			Gost_28147_89_EncryptAlgorithm,

			Gost_R3410_94_KeyAlgorithm,
			Gost_R3410_94_DhAlgorithm,
			Gost_R3410_94_SignatureAlgorithm,
			Gost_R3411_94_HashAlgorithm,

			Gost_R3410_2001_KeyAlgorithm,
			Gost_R3410_2001_DhAlgorithm,
			Gost_R3410_2001_SignatureAlgorithm,
			Gost_R3411_2001_HashAlgorithm,

			Gost_R3410_2012_256_KeyAlgorithm,
			Gost_R3410_2012_256_DhAlgorithm,
			Gost_R3410_2012_256_SignatureAlgorithm,
			Gost_R3411_2012_256_HashAlgorithm,

			Gost_R3410_2012_512_KeyAlgorithm,
			Gost_R3410_2012_512_DhAlgorithm,
			Gost_R3410_2012_512_SignatureAlgorithm,
			Gost_R3411_2012_512_HashAlgorithm
		};
	}
}