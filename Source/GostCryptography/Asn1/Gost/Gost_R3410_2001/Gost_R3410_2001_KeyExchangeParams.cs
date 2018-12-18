using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2001
{
	/// <inheritdoc />
	public sealed class Gost_R3410_2001_KeyExchangeParams : Gost_R3410_KeyExchangeParams
	{
		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeParams()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeParams(Gost_R3410_2001_KeyExchangeParams other) : base(other)
		{
		}


		/// <inheritdoc />
		public override Gost_R3410_KeyExchangeParams Clone() => new Gost_R3410_2001_KeyExchangeParams(this);

		/// <inheritdoc />
		protected override Gost_R3410_PublicKey CreatePublicKey() => new Gost_R3410_2001_PublicKey();

		/// <inheritdoc />
		protected override Gost_R3410_PublicKeyParams CreatePublicKeyParams() => new Gost_R3410_2001_PublicKeyParams();
	}
}