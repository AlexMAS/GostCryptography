using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Digest.GostR341194;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Asn1.PKI.GostR34102001;
using GostCryptography.Asn1.PKI.GostR341094;

namespace GostCryptography.Asn1.PKI.Explicit88
{
	static class PkiConstants
	{
		// GOST R 34.10-94

		private static readonly AlgorithmId Gost94PubKey = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR341094Constants.IdGostR341094),
			new Gost94PubKeyType());

		private static readonly AlgorithmId Gost94DhPubKey = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR341094Constants.IdGostR341094Dh),
			new Gost94DhPubKeyType());

		private static readonly AlgorithmId Gost94WithGostR341094SigNullParams = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR341094Constants.IdGostR341194WithGostR341094),
			new NullParams());


		// GOST R 34.10-2001

		private static readonly AlgorithmId Gost2001PubKey = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR34102001Constants.IdGostR34102001),
			new Gost2001PubKeyType());

		private static readonly AlgorithmId Gost2001DhPubKey = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR34102001Constants.IdGostR34102001Dh),
			new Gost2001DhPubKeyType());

		private static readonly AlgorithmId Gost2001WithGostR341094SigNullParams = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR34102001Constants.IdGostR341194WithGostR34102001),
			new NullParams());


		// GOST 28147-89

		private static readonly AlgorithmId Gost2814789Params = new AlgorithmId(
			new Asn1ObjectIdentifier(Gost2814789Constants.IdGost2814789),
			new Gost2814789Parameters());


		// GOST R 34.11-94

		private static readonly AlgorithmId GostR341194DigestParams = new AlgorithmId(
			new Asn1ObjectIdentifier(GostR341194Constants.IdGostR341194),
			new GostR341194DigestParamsType());


		public static readonly AlgorithmId[] SupportedAlgorithms = 
		{
			Gost94PubKey,
			Gost94DhPubKey,
			Gost94WithGostR341094SigNullParams,

			Gost2001PubKey,
			Gost2001DhPubKey,
			Gost2001WithGostR341094SigNullParams,

			Gost2814789Params,

			GostR341194DigestParams
		};
	}
}