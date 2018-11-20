using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация дешифрования общего секретного ключа по ГОСТ Р 34.10-2012/256.
	/// </summary>
	public sealed class Gost_R3410_2012_256_KeyExchangeDeformatter : Gost_R3410_KeyExchangeDeformatter<
		Gost_R3410_2012_256_KeyExchange,
		Gost_R3410_2012_256_KeyExchangeParams,
		Gost_R3410_2012_256_KeyExchangeAlgorithm>
	{
		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeDeformatter()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeDeformatter(AsymmetricAlgorithm privateKey) : base(privateKey)
		{
		}
	}
}