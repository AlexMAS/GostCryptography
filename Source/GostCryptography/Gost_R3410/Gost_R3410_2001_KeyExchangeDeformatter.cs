using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2001;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация дешифрования общего секретного ключа по ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class Gost_R3410_2001_KeyExchangeDeformatter : Gost_R3410_KeyExchangeDeformatter<
		Gost_R3410_2001_KeyExchange,
		Gost_R3410_2001_KeyExchangeParams,
		Gost_R3410_2001_KeyExchangeAlgorithm>
	{
		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeDeformatter()
		{
		}

		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeDeformatter(AsymmetricAlgorithm privateKey) : base(privateKey)
		{
		}
	}
}