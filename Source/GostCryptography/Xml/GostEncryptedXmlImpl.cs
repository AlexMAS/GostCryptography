using System;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Policy;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_28147_89;
using GostCryptography.Properties;
using GostCryptography.Reflection;

namespace GostCryptography.Xml
{
	sealed class GostEncryptedXmlImpl : EncryptedXml
	{
		public GostEncryptedXmlImpl(ProviderType providerType)
		{
			ProviderType = providerType;
		}

		public GostEncryptedXmlImpl(ProviderType providerType, XmlDocument document) : base(document)
		{
			ProviderType = providerType;
		}

		public GostEncryptedXmlImpl(ProviderType providerType, XmlDocument document, Evidence evidence) : base(document, evidence)
		{
			ProviderType = providerType;
		}


		public ProviderType ProviderType { get; }


		public new void AddKeyNameMapping(string keyName, object keyObject)
		{
			if (string.IsNullOrEmpty(keyName))
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyName));
			}

			if (keyObject == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyObject));
			}

			if (keyObject is GostAsymmetricAlgorithm)
			{
				this.GetKeyNameMapping().Add(keyName, keyObject);
			}
			else
			{
				base.AddKeyNameMapping(keyName, keyObject);
			}
		}


		[SecuritySafeCritical]
		public new EncryptedData Encrypt(XmlElement element, X509Certificate2 certificate)
		{
			if (element == null || certificate == null || !certificate.IsGost())
			{
				return base.Encrypt(element, certificate);
			}

			var publicKey = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm();
			var encryptionKey = new Gost_28147_89_SymmetricAlgorithm(publicKey.ProviderType);

			var encryptedKey = new EncryptedKey();
			encryptedKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));
			encryptedKey.EncryptionMethod = new EncryptionMethod(publicKey.KeyExchangeAlgorithm);
			encryptedKey.CipherData.CipherValue = EncryptKey(encryptionKey, publicKey);

			var encryptedData = new EncryptedData
			{
				Type = XmlEncElementUrl,
				EncryptionMethod = new EncryptionMethod(encryptionKey.AlgorithmName)
			};

			encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
			encryptedData.CipherData.CipherValue = EncryptData(element, encryptionKey, false);

			return encryptedData;
		}

		public static byte[] EncryptKey(Gost_28147_89_SymmetricAlgorithmBase sessionKey, GostAsymmetricAlgorithm publicKey)
		{
			if (sessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(sessionKey));
			}

			if (publicKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(publicKey));
			}

			var formatter = publicKey.CreateKeyExchangeFormatter();
			return formatter.CreateKeyExchangeData(sessionKey);
		}

		public static byte[] EncryptKey(Gost_28147_89_SymmetricAlgorithmBase sessionKey, Gost_28147_89_SymmetricAlgorithmBase sharedKey, GostKeyExchangeExportMethod exportMethod)
		{
			if (sessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(sessionKey));
			}

			if (sharedKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(sharedKey));
			}

			return sharedKey.EncodePrivateKey(sessionKey, exportMethod);
		}


		public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptedData));
			}

			if (symmetricAlgorithmUri == null)
			{
				if (encryptedData.EncryptionMethod == null)
				{
					return base.GetDecryptionIV(encryptedData, null);
				}

				symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
			}

			if (Gost_28147_89_SymmetricAlgorithm.AlgorithmNameValue.Equals(symmetricAlgorithmUri, StringComparison.OrdinalIgnoreCase))
			{
				var iv = new byte[8];
				Buffer.BlockCopy(this.GetCipherValue(encryptedData.CipherData), 0, iv, 0, iv.Length);

				return iv;
			}

			return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
		}

		public override SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptedData));
			}

			SymmetricAlgorithm decryptionKey = null;

			if (encryptedData.KeyInfo != null)
			{
				EncryptedKey encryptedKey = null;

				foreach (var keyInfo in encryptedData.KeyInfo)
				{
					// Извлечение ключа по имени
					if (keyInfo is KeyInfoName)
					{
						var keyName = ((KeyInfoName)keyInfo).Value;
						var keyAlgorithm = this.GetKeyNameMapping()[keyName];

						if (keyAlgorithm == null)
						{
							var nsManager = new XmlNamespaceManager(this.GetDocument().NameTable);
							nsManager.AddNamespace("enc", XmlEncNamespaceUrl);

							var encryptedKeyNodes = this.GetDocument().SelectNodes("//enc:EncryptedKey", nsManager);

							if (encryptedKeyNodes != null)
							{
								foreach (XmlElement encryptedKeyNode in encryptedKeyNodes)
								{
									var currentEncryptedKey = new EncryptedKey();
									currentEncryptedKey.LoadXml(encryptedKeyNode);

									if ((currentEncryptedKey.CarriedKeyName == keyName) && (currentEncryptedKey.Recipient == Recipient))
									{
										encryptedKey = currentEncryptedKey;
										break;
									}
								}
							}
						}
						else
						{
							decryptionKey = (SymmetricAlgorithm)keyAlgorithm;
						}

						break;
					}

					// Извлечение ключа по ссылке
					if (keyInfo is KeyInfoRetrievalMethod)
					{
						var idValue = CryptographyXmlUtils.ExtractIdFromLocalUri(((KeyInfoRetrievalMethod)keyInfo).Uri);
						var idElement = GetIdElement(this.GetDocument(), idValue);

						if (idElement != null)
						{
							encryptedKey = new EncryptedKey();
							encryptedKey.LoadXml(idElement);
						}

						break;
					}

					// Ключ в готовом виде
					if (keyInfo is KeyInfoEncryptedKey)
					{
						encryptedKey = ((KeyInfoEncryptedKey)keyInfo).EncryptedKey;
						break;
					}
				}

				if (decryptionKey == null && encryptedKey != null)
				{
					if (symmetricAlgorithmUri == null)
					{
						if (encryptedData.EncryptionMethod == null)
						{
							throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
						}

						symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
					}

					decryptionKey = DecryptEncryptedKeyClass(encryptedKey, symmetricAlgorithmUri);
				}
			}

			return decryptionKey;
		}

		[SecuritySafeCritical]
		private SymmetricAlgorithm DecryptEncryptedKeyClass(EncryptedKey encryptedKey, string symmetricAlgorithmUri)
		{
			if (encryptedKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptedKey));
			}

			SymmetricAlgorithm decryptionKey = null;

			if (encryptedKey.KeyInfo != null)
			{
				foreach (var keyInfo in encryptedKey.KeyInfo)
				{
					// Извлечение ключа по имени
					if (keyInfo is KeyInfoName)
					{
						var keyName = ((KeyInfoName)keyInfo).Value;
						var keyAlgorithm = this.GetKeyNameMapping()[keyName];

						if (keyAlgorithm != null)
						{
							if (keyAlgorithm is SymmetricAlgorithm)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (SymmetricAlgorithm)keyAlgorithm, symmetricAlgorithmUri, encryptedKey.EncryptionMethod.KeyAlgorithm);
							}
							else if (keyAlgorithm is RSA)
							{
								var useOaep = (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl);
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (RSA)keyAlgorithm, useOaep, symmetricAlgorithmUri);
							}
							else if (keyAlgorithm is GostAsymmetricAlgorithm)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (GostAsymmetricAlgorithm)keyAlgorithm);
							}
						}

						break;
					}

					// Извлечение ключа из сертификата
					if (keyInfo is KeyInfoX509Data)
					{
						var certificates = CryptographyXmlUtils.BuildBagOfCertsDecryption((KeyInfoX509Data)keyInfo);

						foreach (var certificate in certificates)
						{
							var privateKey = certificate.GetPrivateKeyAlgorithm();

							if (privateKey is RSA)
							{
								var useOaep = (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl);
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (RSA)privateKey, useOaep, symmetricAlgorithmUri);
							}
							else if (privateKey is GostAsymmetricAlgorithm)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (GostAsymmetricAlgorithm)privateKey);
							}
						}

						break;
					}

					// Извлечение ключа по ссылке
					if (keyInfo is KeyInfoRetrievalMethod)
					{
						var idValue = CryptographyXmlUtils.ExtractIdFromLocalUri(((KeyInfoRetrievalMethod)keyInfo).Uri);
						var idElement = GetIdElement(this.GetDocument(), idValue);

						if (idElement != null)
						{
							var secondEncryptedKey = new EncryptedKey();
							secondEncryptedKey.LoadXml(idElement);

							decryptionKey = DecryptEncryptedKeyClass(secondEncryptedKey, symmetricAlgorithmUri);
						}

						break;
					}

					// Ключ в готовом виде
					if (keyInfo is KeyInfoEncryptedKey)
					{
						var secondEncryptedKey = ((KeyInfoEncryptedKey)keyInfo).EncryptedKey;
						var symmetricAlgorithm = DecryptEncryptedKeyClass(secondEncryptedKey, symmetricAlgorithmUri);

						if (symmetricAlgorithm != null)
						{
							decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, symmetricAlgorithm, symmetricAlgorithmUri, encryptedKey.EncryptionMethod.KeyAlgorithm);
						}

						break;
					}
				}
			}

			return decryptionKey;
		}

		private static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, SymmetricAlgorithm algorithm, string symmetricAlgorithmUri, string encryptionKeyAlgorithm)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyData));
			}

			if (algorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(algorithm));
			}

			SymmetricAlgorithm decryptionKey = null;

			if (algorithm is Gost_28147_89_SymmetricAlgorithmBase gost28147)
			{
				if (string.Equals(encryptionKeyAlgorithm, GostEncryptedXml.XmlEncGostKeyExportUrl, StringComparison.OrdinalIgnoreCase))
				{
					decryptionKey = gost28147.DecodePrivateKey(keyData, GostKeyExchangeExportMethod.GostKeyExport);
				}

				if (string.Equals(encryptionKeyAlgorithm, GostEncryptedXml.XmlEncGostCryptoProKeyExportUrl, StringComparison.OrdinalIgnoreCase))
				{
					decryptionKey = gost28147.DecodePrivateKey(keyData, GostKeyExchangeExportMethod.CryptoProKeyExport);
				}
			}
			else
			{
				var decryptionKeyBytes = DecryptKey(keyData, algorithm);

				if (decryptionKeyBytes != null)
				{
					decryptionKey = (SymmetricAlgorithm)GostCryptoConfig.CreateFromName(symmetricAlgorithmUri);
					decryptionKey.Key = decryptionKeyBytes;
				}
			}

			if (decryptionKey == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
			}

			return decryptionKey;
		}

		private static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, RSA algorithm, bool useOaep, string symmetricAlgorithmUri)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyData));
			}

			if (algorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(algorithm));
			}

			SymmetricAlgorithm decryptionKey = null;

			var decryptionKeyBytes = DecryptKey(keyData, algorithm, useOaep);

			if (decryptionKeyBytes != null)
			{
				decryptionKey = (SymmetricAlgorithm)GostCryptoConfig.CreateFromName(symmetricAlgorithmUri);
				decryptionKey.Key = decryptionKeyBytes;
			}

			if (decryptionKey == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
			}

			return decryptionKey;
		}

		public static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, GostAsymmetricAlgorithm privateKey)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyData));
			}

			if (privateKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(privateKey));
			}

			var deformatter = privateKey.CreateKeyExchangeDeformatter();
			var decryptionKey = deformatter.DecryptKeyExchangeAlgorithm(keyData);

			return decryptionKey;
		}
	}
}