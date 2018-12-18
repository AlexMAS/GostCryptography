using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Config;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Объект для работы с подписями XML по ГОСТ 34.10.
	/// </summary>
	/// <remarks>
	/// Данный класс реализует стандарт XML-DSig с использованием ГОСТ 34.10. Стандарт XML-DSig разработан консорциумом W3C
	/// и определяет рекомендации по формированию подписанных сообщений в формате XML. Фактически XML-DSig решает те же вопросы,
	/// что и CMS/PKCS#7.  Основное отличие в том, что в CMS/PKCS#7 данные хранятся в структурах, сформированных в соответствии 
	/// с разметкой ANS.1 (фактически, бинарные данные), а в XML-DSig данные хранятся в текстовом формате в соответствии с правилами
	/// документа "XML Signature Syntax and Processing". Основное применение XML-DSig - это XML-ориентированные протоколы, например,
	/// Web- и SOAP-сервисы.
	/// </remarks>
	public sealed class GostSignedXml
	{
		static GostSignedXml()
		{
			GostCryptoConfig.Initialize();
		}


		/// <inheritdoc cref="SignedXml()"/>
		public GostSignedXml()
		{
			_signedXml = new GostSignedXmlImpl();
		}

		/// <inheritdoc cref="SignedXml(XmlElement)"/>
		public GostSignedXml(XmlElement element)
		{
			if (element == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(element));
			}

			_signedXml = new GostSignedXmlImpl(element);
		}

		/// <inheritdoc cref="SignedXml(XmlDocument)"/>
		public GostSignedXml(XmlDocument document)
		{
			if (document == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(document));
			}

			_signedXml = new GostSignedXmlImpl(document);
		}


		private readonly GostSignedXmlImpl _signedXml;


		/// <inheritdoc cref="SignedXml.SignedInfo"/>
		public SignedInfo SignedInfo => _signedXml.SignedInfo;

		/// <inheritdoc cref="SignedXml.KeyInfo"/>
		public KeyInfo KeyInfo
		{
			get => _signedXml.KeyInfo;
			set => _signedXml.KeyInfo = value;
		}

		/// <inheritdoc cref="SignedXml.SigningKey"/>
		public AsymmetricAlgorithm SigningKey
		{
			get => _signedXml.SigningKey;
			set => _signedXml.SigningKey = value;
		}


		/// <summary>
		/// Обработчик для перекрытия метода <see cref="GetIdElement"/>.
		/// </summary>
		public GetIdElementDelegate GetIdElementHandler
		{
			get => _signedXml.GetIdElementHandler;
			set => _signedXml.GetIdElementHandler = value;
		}


		/// <summary>
		/// Устанавливает сертификат для вычисления цифровой подписи.
		/// </summary>
		[SecuritySafeCritical]
		public void SetSigningCertificate(X509Certificate2 certificate)
		{
			SigningKey = certificate.GetPrivateKeyAlgorithm();
		}


		/// <inheritdoc cref="SignedXml.AddReference"/>
		public void AddReference(Reference reference)
		{
			_signedXml.AddReference(reference);
		}


		/// <inheritdoc cref="SignedXml.ComputeSignature()"/>
		public void ComputeSignature()
		{
			_signedXml.ComputeSignatureGost();
		}

		/// <inheritdoc cref="SignedXml.CheckSignature()"/>
		public bool CheckSignature()
		{
			return _signedXml.CheckSignature();
		}

		/// <inheritdoc cref="SignedXml.CheckSignature(AsymmetricAlgorithm)"/>
		public bool CheckSignature(AsymmetricAlgorithm publicKey)
		{
			return _signedXml.CheckSignature(publicKey);
		}


		/// <inheritdoc cref="SignedXml.LoadXml(XmlElement)"/>
		public void LoadXml(XmlElement element)
		{
			_signedXml.LoadXml(element);
		}

		/// <inheritdoc cref="SignedXml.GetXml()"/>
		public XmlElement GetXml()
		{
			return _signedXml.GetXml();
		}

		/// <inheritdoc cref="SignedXml.GetIdElement(XmlDocument,string)"/>
		public XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			return _signedXml.GetIdElement(document, idValue);
		}
	}
}