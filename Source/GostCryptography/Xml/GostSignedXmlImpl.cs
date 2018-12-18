using System.Collections;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Properties;
using GostCryptography.Reflection;

namespace GostCryptography.Xml
{
	sealed class GostSignedXmlImpl : SignedXml
	{
		public GostSignedXmlImpl()
		{
		}

		public GostSignedXmlImpl(XmlElement element) : base(element)
		{
		}

		public GostSignedXmlImpl(XmlDocument document) : base(document)
		{
		}


		public GetIdElementDelegate GetIdElementHandler { get; set; }


		private IEnumerator KeyInfoEnumerable
		{
			get => this.GetKeyInfoEnumerable();
			set => this.SetKeyInfoEnumerable(value);
		}

		private IEnumerator X509Enumerable
		{
			get => this.GetX509Enumerable();
			set => this.SetX509Enumerable(value);
		}

		private X509Certificate2Collection X509Collection
		{
			get => this.GetX509Collection();
			set => this.SetX509Collection(value);
		}


		[SecuritySafeCritical]
		public void ComputeSignatureGost()
		{
			var signingKey = SigningKey;

			if (signingKey == null)
			{
				ComputeSignatureBase();
			}
			else
			{
				if ((SignedInfo.SignatureMethod == null) && (signingKey is GostAsymmetricAlgorithm))
				{
					SignedInfo.SignatureMethod = signingKey.SignatureAlgorithm;
				}

				ComputeSignatureBase();
			}
		}

		[SecurityCritical]
		private void ComputeSignatureBase()
		{
			ComputeSignature();
		}


		protected override AsymmetricAlgorithm GetPublicKey()
		{
			if (KeyInfo == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlKeyInfoRequired);
			}

			if (X509Enumerable != null)
			{
				var nextCertificatePublicKey = GetNextCertificatePublicKey();

				if (nextCertificatePublicKey != null)
				{
					return nextCertificatePublicKey;
				}
			}

			if (KeyInfoEnumerable == null)
			{
				KeyInfoEnumerable = KeyInfo.GetEnumerator();
			}

			var keyInfoEnum = KeyInfoEnumerable;

			while (keyInfoEnum.MoveNext())
			{
				if (keyInfoEnum.Current is RSAKeyValue rsaKeyValue)
				{
					return rsaKeyValue.Key;
				}

				if (keyInfoEnum.Current is DSAKeyValue dsaKeyValue)
				{
					return dsaKeyValue.Key;
				}

				if (keyInfoEnum.Current is GostKeyValue gostKeyValue)
				{
					return gostKeyValue.PublicKey;
				}

				if (keyInfoEnum.Current is KeyInfoX509Data keyInfoX509Data)
				{
					X509Collection = CryptographyXmlUtils.BuildBagOfCertsVerification(keyInfoX509Data);

					if (X509Collection.Count > 0)
					{
						X509Enumerable = X509Collection.GetEnumerator();

						var nextCertificatePublicKey = GetNextCertificatePublicKey();

						if (nextCertificatePublicKey != null)
						{
							return nextCertificatePublicKey;
						}
					}
				}
			}

			return null;
		}

		[SecuritySafeCritical]
		private AsymmetricAlgorithm GetNextCertificatePublicKey()
		{
			while (X509Enumerable.MoveNext())
			{
				if (X509Enumerable.Current is X509Certificate2 certificate)
				{
					return certificate.GetPublicKeyAlgorithm();
				}
			}

			return null;
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			if (GetIdElementHandler != null)
			{
				return GetIdElementHandler(document, idValue);
			}

			return base.GetIdElement(document, idValue);
		}
	}
}