using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Gost_R3411;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Sign
{
	/// <summary>
	/// Подпись и проверка подписи запроса к сервису СМЭВ (Система межведомственного электронного взаимодействия).
	/// </summary>
	/// <remarks>
	/// Тест создает запрос к сервису СМЭВ, подписывает определенную часть данного запроса с использованием сертификата,
	/// а затем проверяет полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи запроса к сервису СМЭВ (Система межведомственного электронного взаимодействия)")]
	public sealed class SignedXmlSmevTest
	{
		private const string WsSecurityExtNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
		private const string WsSecurityUtilityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

		[Test]
		public void ShouldSignXml()
		{
			// Given
			var signingCertificate = TestConfig.GetCertificate();
			var smevRequest = CreateSmevRequest();

			// When
			var signedXmlDocument = SignSmevRequest(smevRequest, signingCertificate);

			// Then
			Assert.IsTrue(VerifySmevRequestSignature(signedXmlDocument));
		}

		private static XmlDocument CreateSmevRequest()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.SmevExample);
			return document;
		}

		private static XmlDocument SignSmevRequest(XmlDocument smevRequest, X509Certificate2 signingCertificate)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(smevRequest) { GetIdElementHandler = GetSmevIdElement };

			// Установка ключа для создания подписи
			signedXml.SetSigningCertificate(signingCertificate);

			// Ссылка на узел, который нужно подписать, с указанием алгоритма хэширования ГОСТ Р 34.11-94 (в соответствии с методическими рекомендациями СМЭВ)
			var dataReference = new Reference { Uri = "#body", DigestMethod = Gost_R3411_94_HashAlgorithm.ObsoleteAlgorithmNameValue };

			// Метод преобразования, применяемый к данным перед их подписью (в соответствии с методическими рекомендациями СМЭВ)
			var dataTransform = new XmlDsigExcC14NTransform();
			dataReference.AddTransform(dataTransform);

			// Установка ссылки на узел
			signedXml.AddReference(dataReference);

			// Установка алгоритма нормализации узла SignedInfo (в соответствии с методическими рекомендациями СМЭВ)
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			// Установка алгоритма хэширования (в соответствии с методическими рекомендациями СМЭВ)
			signedXml.SignedInfo.SignatureMethod = Gost_R3411_94_HashAlgorithm.ObsoleteAlgorithmNameValue;

			// Вычисление подписи
			signedXml.ComputeSignature();

			// Получение XML-представления подписи
			var signatureXml = signedXml.GetXml();

			// Добавление подписи в исходный документ
			smevRequest.GetElementsByTagName("ds:Signature")[0].PrependChild(smevRequest.ImportNode(signatureXml.GetElementsByTagName("SignatureValue")[0], true));
			smevRequest.GetElementsByTagName("ds:Signature")[0].PrependChild(smevRequest.ImportNode(signatureXml.GetElementsByTagName("SignedInfo")[0], true));
			smevRequest.GetElementsByTagName("wsse:BinarySecurityToken")[0].InnerText = Convert.ToBase64String(signingCertificate.RawData);

			return smevRequest;
		}

		private static bool VerifySmevRequestSignature(XmlDocument signedSmevRequest)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(signedSmevRequest) { GetIdElementHandler = GetSmevIdElement };

			// Поиск узла с подписью
			var nodeList = signedSmevRequest.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

			// Загрузка найденной подписи
			signedXml.LoadXml((XmlElement)nodeList[0]);

			// Поиск ссылки на BinarySecurityToken
			var references = signedXml.KeyInfo.GetXml().GetElementsByTagName("Reference", WsSecurityExtNamespace);

			if (references.Count > 0)
			{
				// Определение ссылки на сертификат (ссылка на узел документа)
				var binaryTokenReference = ((XmlElement)references[0]).GetAttribute("URI");

				if (!String.IsNullOrEmpty(binaryTokenReference) && binaryTokenReference[0] == '#')
				{
					// Поиск элемента с закодированным в Base64 сертификатом
					var binaryTokenElement = signedXml.GetIdElement(signedSmevRequest, binaryTokenReference.Substring(1));

					if (binaryTokenElement != null)
					{
						// Загрузка сертификата, который был использован для подписи
						var signingCertificate = new X509Certificate2(Convert.FromBase64String(binaryTokenElement.InnerText));

						// Проверка подписи
						return signedXml.CheckSignature(signingCertificate.GetPublicKeyAlgorithm());
					}
				}
			}

			return false;
		}

		private static XmlElement GetSmevIdElement(XmlDocument document, string idValue)
		{
			var namespaceManager = new XmlNamespaceManager(document.NameTable);
			namespaceManager.AddNamespace("wsu", WsSecurityUtilityNamespace);

			return document.SelectSingleNode("//*[@wsu:Id='" + idValue + "']", namespaceManager) as XmlElement;
		}
	}
}