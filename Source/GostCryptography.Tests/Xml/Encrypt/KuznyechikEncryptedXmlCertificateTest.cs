using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Encrypt
{
    /// <summary>
    /// Шифрация и дешифрация XML документа с использованием сертификата и алгоритма ГОСТ Р 34.12-2015 Кузнечик.
    /// </summary>
    /// <remarks>
    /// Тест создает XML-документ, шифрует его целиком с использованием сертификата, а затем дешифрует зашифрованный документ.
    /// </remarks>
    [TestFixture(Description = "Шифрация и дешифрация XML документа с использованием сертификата и алгоритма ГОСТ Р 34.12-2015 Кузнечик")]
    public sealed class KuznyechikEncryptedXmlCertificateTest
    {
        [Test]
        [TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_Certificates))]
        public void ShouldEncryptXml(TestCertificateInfo testCase)
        {
            // Given
            var certificate = testCase.Certificate;
            var xmlDocument = CreateXmlDocument();
            var expectedXml = xmlDocument.OuterXml.Replace("\r\n", "\n");

            // When
            var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, certificate);
            var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument);
            var actualXml = decryptedXmlDocument.OuterXml.Replace("\r\n", "\n");

            // Then
            Assert.AreEqual(expectedXml, actualXml);
        }

        private static XmlDocument CreateXmlDocument()
        {
            var document = new XmlDocument();
            document.LoadXml(Resources.EncryptedXmlExample);
            return document;
        }

        private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, X509Certificate2 certificate)
        {
            var publicKeyAlgorithm = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm();

            using (var sessionKey = new Gost_3412_K_SymmetricAlgorithm(publicKeyAlgorithm.ProviderType))
            {
                var encryptedSessionKeyData = GostEncryptedXml.EncryptKey(sessionKey, publicKeyAlgorithm);

                var encryptedSessionKey = new EncryptedKey
                {
                    CipherData = new CipherData(encryptedSessionKeyData),
                    EncryptionMethod = new EncryptionMethod(publicKeyAlgorithm.KeyExchangeAlgorithm),
                };

                encryptedSessionKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

                var elementEncryptedData = new EncryptedData
                {
                    EncryptionMethod = new EncryptionMethod(sessionKey.AlgorithmName),
                };

                var encryptedXml = new GostEncryptedXml();
                var xmlBytes = Encoding.UTF8.GetBytes(xmlDocument.OuterXml);
                var encryptedData = encryptedXml.EncryptData(xmlBytes, sessionKey);

                elementEncryptedData.CipherData.CipherValue = encryptedData;
                elementEncryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedSessionKey));

                GostEncryptedXml.ReplaceElement(xmlDocument.DocumentElement, elementEncryptedData, false);
            }

            return xmlDocument;
        }

        private static XmlDocument DecryptXmlDocument(XmlDocument encryptedXmlDocument)
        {
            // Создание объекта для дешифрации XML
            var encryptedXml = new GostEncryptedXml(encryptedXmlDocument);

            // Расшифровка зашифрованных элементов документа
            encryptedXml.DecryptDocument();

            return encryptedXmlDocument;
        }
    }
}