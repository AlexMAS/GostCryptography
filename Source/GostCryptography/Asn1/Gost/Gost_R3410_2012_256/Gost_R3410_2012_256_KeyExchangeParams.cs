using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2012_256
{
	/// <inheritdoc />
	public sealed class Gost_R3410_2012_256_KeyExchangeParams : Gost_R3410_KeyExchangeParams
	{
		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeParams()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeParams(Gost_R3410_2012_256_KeyExchangeParams other) : base(other)
		{
		}


		/// <inheritdoc />
		public override Gost_R3410_KeyExchangeParams Clone() => new Gost_R3410_2012_256_KeyExchangeParams(this);

		/// <inheritdoc />
		protected override Gost_R3410_PublicKey CreatePublicKey() => new Gost_R3410_2012_256_PublicKey();

		/// <inheritdoc />
		protected override Gost_R3410_PublicKeyParams CreatePublicKeyParams() => new Gost_R3410_2012_256_PublicKeyParams();
	}
}