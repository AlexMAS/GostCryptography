using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Параметры открытого ключа цифровой подписи ГОСТ Р 34.10 элемента <see cref="KeyInfo"/>.
	/// </summary>
	public abstract class GostKeyValue : KeyInfoClause
	{
		/// <summary>
		/// URI пространства имен для XML-подписи ГОСТ Р 34.10.
		/// </summary>
		public const string XmlDsigNamespaceUrl = "urn:ietf:params:xml:ns:cpxmlsec";


		/// <summary>
		/// Создает экземпляр класса с заданным публичным ключом.
		/// </summary>
		protected GostKeyValue(GostAsymmetricAlgorithm publicKey)
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
				throw ExceptionUtility.ArgumentNull(nameof(element));
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