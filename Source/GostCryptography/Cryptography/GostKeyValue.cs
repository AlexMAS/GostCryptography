using System;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Параметры ключа цифровой подписи ГОСТ Р 34.10.
	/// Представлен элементом &lt;KeyValue&gt; в XML подписи.
	/// </summary>
	public sealed class GostKeyValue : KeyInfoClause
	{
		/// <summary>
		/// Наименование ключа цифровой подписи ГОСТ Р 34.10.
		/// </summary>
		public const string XmlDsigGostKeyValueUrl = "http://www.w3.org/2000/09/xmldsig# KeyValue/GostKeyValue";


		public GostKeyValue()
		{
			Key = new Gost3410AsymmetricAlgorithm();
		}

		public GostKeyValue(Gost3410AsymmetricAlgorithmBase key)
		{
			Key = key;
		}


		public Gost3410AsymmetricAlgorithmBase Key { get; private set; }


		public override void LoadXml(XmlElement element)
		{
			if (element == null)
			{
				throw new ArgumentNullException("element");
			}

			Key.FromXmlString(element.OuterXml);
		}

		public override XmlElement GetXml()
		{
			var document = new XmlDocument { PreserveWhitespace = true };
			var element = document.CreateElement("KeyValue", SignedXml.XmlDsigNamespaceUrl);
			element.InnerXml = Key.ToXmlString(false);
			return element;
		}
	}
}