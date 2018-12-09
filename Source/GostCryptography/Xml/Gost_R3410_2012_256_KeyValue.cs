using System.Security.Cryptography.Xml;

using GostCryptography.Gost_R3410;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Параметры открытого ключа цифровой подписи ГОСТ Р 34.10-2012/256 элемента <see cref="KeyInfo"/>.
	/// </summary>
	public sealed class Gost_R3410_2012_256_KeyValue : GostKeyValue
	{
		/// <summary>
		/// URI параметров ключа ГОСТ Р 34.10-2012/256.
		/// </summary>
		public const string KeyValueUrl = SignedXml.XmlDsigNamespaceUrl + " KeyValue/" + Gost_R3410_2012_256_KeyExchangeXmlSerializer.KeyValueTag;

		/// <summary>
		/// Известные URIs параметров ключа ГОСТ Р 34.10-2012/256.
		/// </summary>
		public static readonly string[] KnownValueUrls = { KeyValueUrl };


		/// <summary>
		/// Создает экземпляр класса с новым ключом ГОСТ Р 34.10-2012/256.
		/// </summary>
		public Gost_R3410_2012_256_KeyValue() : base(new Gost_R3410_2012_256_AsymmetricAlgorithm())
		{
		}

		/// <summary>
		/// Создает экземпляр класса с заданным ключом ГОСТ Р 34.10-2012/256.
		/// </summary>
		public Gost_R3410_2012_256_KeyValue(Gost_R3410_2012_256_AsymmetricAlgorithm publicKey) : base(publicKey)
		{
		}
	}
}