using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Base;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация шифрования общего секретного ключа по ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class Gost_R3410_2001_KeyExchangeFormatter : Gost_R3410_KeyExchangeFormatter<
		Gost_R3410_2001_KeyExchange,
		Gost_R3410_2001_KeyExchangeParams,
		Gost_R3410_2001_KeyExchangeAlgorithm>
	{
		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeFormatter()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeFormatter(AsymmetricAlgorithm publicKey) : base(publicKey)
		{
		}

		/// <inheritdoc />
		protected override Gost_R3410_EphemeralAsymmetricAlgorithm<Gost_R3410_2001_KeyExchangeParams, Gost_R3410_2001_KeyExchangeAlgorithm> CreateEphemeralAlgorithm(ProviderType providerType, Gost_R3410_2001_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2001_EphemeralAsymmetricAlgorithm(providerType, keyExchangeParameters);
		}
	}
}