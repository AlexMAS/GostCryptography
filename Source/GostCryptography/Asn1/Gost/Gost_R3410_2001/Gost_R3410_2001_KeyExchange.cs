using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2001
{
	/// <inheritdoc />
	public sealed class Gost_R3410_2001_KeyExchange : Gost_R3410_KeyExchange
	{
		/// <inheritdoc />
		protected override OidValue KeyAlgorithm => Gost_R3410_2001_Constants.KeyAlgorithm;

		/// <inheritdoc />
		protected override Gost_R3410_PublicKeyParams CreatePublicKeyParams() => new Gost_R3410_2001_PublicKeyParams();

		/// <inheritdoc />
		protected override Gost_R3410_KeyExchangeParams CreateKeyExchangeParams() => new Gost_R3410_2001_KeyExchangeParams();
	}
}