using GostCryptography.Asn1.Gost.Gost_R3410_2001;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// XML-сериализатора параметров ключа цифровой подписи ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class Gost_R3410_2001_KeyExchangeXmlSerializer : Gost_R3410_KeyExchangeXmlSerializer<Gost_R3410_2001_KeyExchangeParams>
	{
		/// <summary>
		/// Имя тега с информацией о параметрах ключа ГОСТ Р 34.10-2001.
		/// </summary>
		public const string KeyValueTag = "GostKeyValue";


		/// <inheritdoc />
		public Gost_R3410_2001_KeyExchangeXmlSerializer() : base(KeyValueTag)
		{
		}
	}
}