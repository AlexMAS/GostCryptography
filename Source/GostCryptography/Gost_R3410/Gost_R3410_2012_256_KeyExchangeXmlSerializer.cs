using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// XML-сериализатора параметров ключа цифровой подписи ГОСТ Р 34.10-2012/256.
	/// </summary>
	public sealed class Gost_R3410_2012_256_KeyExchangeXmlSerializer : Gost_R3410_KeyExchangeXmlSerializer<Gost_R3410_2012_256_KeyExchangeParams>
	{
		/// <summary>
		/// Имя тега с информацией о параметрах ключа ГОСТ Р 34.10-2012/256.
		/// </summary>
		public const string KeyValueTag = "Gost_R3410_2012_256_KeyValue";


		/// <inheritdoc />
		public Gost_R3410_2012_256_KeyExchangeXmlSerializer() : base(KeyValueTag)
		{
		}
	}
}