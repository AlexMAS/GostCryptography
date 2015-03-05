using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Cryptography;

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
		/// <summary>
		/// Наименование алгоритма цифровой подписи по ГОСТ Р 34.10.
		/// </summary>
		public const string XmlDsigGost3410Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма цифровой подписи по ГОСТ Р 34.10.
		/// </summary>
		public const string XmlDsigGost3410ObsoleteUrl = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

		/// <summary>
		/// Наименование алгоритма алгоритма хэширования по ГОСТ Р 34.11.
		/// </summary>
		public const string XmlDsigGost3411Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма алгоритма хэширования по ГОСТ Р 34.11.
		/// </summary>
		public const string XmlDsigGost3411ObsoleteUrl = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";

		/// <summary>
		/// Наименование алгоритма алгоритма хэширования HMAC по ГОСТ Р 34.11.
		/// </summary>
		public const string XmlDsigGost3411HmacUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr3411";


		static GostSignedXml()
		{
			GostCryptoConfig.Initialize();
		}

		public GostSignedXml()
		{
			_signedXml = new GostSignedXmlImpl();
		}

		public GostSignedXml(XmlElement element)
		{
			if (element == null)
			{
				throw new ArgumentNullException("element");
			}

			_signedXml = new GostSignedXmlImpl(element);
		}

		public GostSignedXml(XmlDocument document)
		{
			if (document == null)
			{
				throw new ArgumentNullException("document");
			}

			_signedXml = new GostSignedXmlImpl(document);
		}


		private readonly GostSignedXmlImpl _signedXml;


		/// <summary>
		/// Информация об алгоритмах нормализации и подписи данных.
		/// </summary>
		public SignedInfo SignedInfo
		{
			get { return _signedXml.SignedInfo; }
		}

		/// <summary>
		/// Информация о ключе цифровой подписи.
		/// </summary>
		public KeyInfo KeyInfo
		{
			get { return _signedXml.KeyInfo; }
			set { _signedXml.KeyInfo = value; }
		}

		/// <summary>
		/// Ключ цифровой подписи.
		/// </summary>
		public AsymmetricAlgorithm SigningKey
		{
			get { return _signedXml.SigningKey; }
			set { _signedXml.SigningKey = value; }
		}


		/// <summary>
		/// Устанавливает сертификат для вычисления цифровой подписи.
		/// </summary>
		[SecuritySafeCritical]
		public void SetSigningCertificate(X509Certificate2 certificate)
		{
			SigningKey = certificate.GetPrivateKeyAlgorithm();
		}

		/// <summary>
		/// Добавляет информацию о методе хэширования.
		/// </summary>
		public void AddReference(Reference reference)
		{
			_signedXml.AddReference(reference);
		}


		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		public void ComputeSignature()
		{
			_signedXml.ComputeSignatureGost();
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public bool CheckSignature()
		{
			return _signedXml.CheckSignature();
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		/// <param name="publicKey">Ключ для проверки цифровой подписи.</param>
		public bool CheckSignature(AsymmetricAlgorithm publicKey)
		{
			return _signedXml.CheckSignature(publicKey);
		}


		/// <summary>
		/// Загружает состояние из <see cref="XmlElement"/>.
		/// </summary>
		public void LoadXml(XmlElement element)
		{
			_signedXml.LoadXml(element);
		}

		/// <summary>
		/// Возвращает состояние в <see cref="XmlElement"/>.
		/// </summary>
		public XmlElement GetXml()
		{
			return _signedXml.GetXml();
		}


		/// <summary>
		/// Обработчик для перекрытия метода <see cref="GetIdElement"/>.
		/// </summary>
		public GetIdElementDelegate GetIdElementHandler
		{
			get { return _signedXml.GetIdElementHandler; }
			set { _signedXml.GetIdElementHandler = value; }
		}

		/// <summary>
		/// Возвращает XML-элемент с указанным идентификатором.
		/// </summary>
		/// <param name="document">Документ для поиска идентификатора элемента.</param>
		/// <param name="idValue">Значение идентификатора элемента.</param>
		public XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			return _signedXml.GetIdElement(document, idValue);
		}
	}
}