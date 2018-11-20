using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_94
{
	/// <inheritdoc />
	public sealed class Gost_R3410_94_KeyExchange : Gost_R3410_KeyExchange
	{
		/// <inheritdoc />
		protected override OidValue KeyAlgorithm => Gost_R3410_94_Constants.KeyAlgorithm;

		/// <inheritdoc />
		protected override Gost_R3410_PublicKeyParams CreatePublicKeyParams() => new Gost_R3410_94_PublicKeyParams();

		/// <inheritdoc />
		protected override Gost_R3410_KeyExchangeParams CreateKeyExchangeParams() => new Gost_R3410_94_KeyExchangeParams();
	}
}