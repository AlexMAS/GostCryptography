using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Base;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация шифрования общего секретного ключа по ГОСТ Р 34.10-2012/256.
	/// </summary>
	public sealed class Gost_R3410_2012_256_KeyExchangeFormatter : Gost_R3410_KeyExchangeFormatter<
		Gost_R3410_2012_256_KeyExchange,
		Gost_R3410_2012_256_KeyExchangeParams,
		Gost_R3410_2012_256_KeyExchangeAlgorithm>
	{
		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeFormatter()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeFormatter(AsymmetricAlgorithm publicKey) : base(publicKey)
		{
		}

		/// <inheritdoc />
		protected override Gost_R3410_EphemeralAsymmetricAlgorithm<Gost_R3410_2012_256_KeyExchangeParams, Gost_R3410_2012_256_KeyExchangeAlgorithm> CreateEphemeralAlgorithm(ProviderType providerType, Gost_R3410_2012_256_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm(providerType, keyExchangeParameters);
		}
	}
}