using System;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Параметры открытого ключа цифровой подписи ГОСТ Р 34.10.
	/// </summary>
	public sealed class GostKeyValue : KeyInfoClause
	{
		/// <summary>
		/// Наименование ключа.
		/// </summary>
		public const string NameValue = "urn:ietf:params:xml:ns:cpxmlsec:GOSTKeyValue";

		/// <summary>
		/// Устаревшее наименование ключа.
		/// </summary>
		public const string ObsoleteNameValue = "http://www.w3.org/2000/09/xmldsig#KeyValue/GostKeyValue";

		/// <summary>
		/// Известные наименования ключа.
		/// </summary>
		public static readonly string[] KnownNames = { NameValue, ObsoleteNameValue };


		/// <inheritdoc />
		public GostKeyValue()
		{
		}

		/// <inheritdoc />
		public GostKeyValue(GostAsymmetricAlgorithm publicKey)
		{
			PublicKey = publicKey;
		}


		/// <summary>
		/// Открытый ключ.
		/// </summary>
		public GostAsymmetricAlgorithm PublicKey { get; set; }


		/// <inheritdoc />
		public override void LoadXml(XmlElement element)
		{
			if (element == null)
			{
				throw new ArgumentNullException(nameof(element));
			}

			PublicKey.FromXmlString(element.OuterXml);
		}

		/// <inheritdoc />
		public override XmlElement GetXml()
		{
			var document = new XmlDocument { PreserveWhitespace = true };
			var element = document.CreateElement("KeyValue", SignedXml.XmlDsigNamespaceUrl);
			element.InnerXml = PublicKey.ToXmlString(false);
			return element;
		}
	}
}