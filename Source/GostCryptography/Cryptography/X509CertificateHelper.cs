using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Asn1.Common;
using GostCryptography.Native;

namespace GostCryptography.Cryptography
{
	[SecurityCritical]
	public static class X509CertificateHelper
	{
		private static volatile MethodInfo _getPrivateKeyInfoMethod;
		private static readonly object GetPrivateKeyInfoMethodSync = new object();

		public static CspParameters GetPrivateKeyInfo(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw ExceptionUtility.ArgumentNull("certificate");
			}

			if (certificate.HasPrivateKey)
			{
				if (_getPrivateKeyInfoMethod == null)
				{
					lock (GetPrivateKeyInfoMethodSync)
					{
						if (_getPrivateKeyInfoMethod == null)
						{
							_getPrivateKeyInfoMethod = typeof(X509Certificate2).GetMethod("GetPrivateKeyInfo", BindingFlags.Static | BindingFlags.NonPublic);
						}
					}
				}

				if (_getPrivateKeyInfoMethod != null)
				{
					object certContext = GetCertContext(certificate);

					if (certContext != null)
					{
						try
						{
							var parameters = new CspParameters();

							object success = _getPrivateKeyInfoMethod.Invoke(null, new[] { certContext, parameters });

							if (Equals(success, true))
							{
								return parameters;
							}
						}
						catch
						{
						}
					}
				}
			}

			return null;
		}


		private static volatile FieldInfo _certContextField;
		private static readonly object CertContextFieldSync = new object();

		private static object GetCertContext(X509Certificate2 certificate)
		{
			if (_certContextField == null)
			{
				lock (CertContextFieldSync)
				{
					if (_certContextField == null)
					{
						_certContextField = typeof(X509Certificate2).GetField("m_safeCertContext", BindingFlags.Instance | BindingFlags.NonPublic);
					}
				}
			}

			if (_certContextField != null)
			{
				try
				{
					return _certContextField.GetValue(certificate);
				}
				catch
				{
				}
			}

			return null;
		}


		public static AsymmetricAlgorithm GetPrivateKeyAlgorithm(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw ExceptionUtility.ArgumentNull("certificate");
			}

			var cspParameters = GetPrivateKeyInfo(certificate);
			var privateKey = new Gost3410AsymmetricAlgorithm(cspParameters);

			return privateKey;
		}


		public static AsymmetricAlgorithm GetPublicKeyAlgorithm(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw ExceptionUtility.ArgumentNull("certificate");
			}

			var cspObject = new GostKeyExchangeParameters();
			cspObject.DecodeParameters(certificate.PublicKey.EncodedParameters.RawData);
			cspObject.DecodePublicKey(certificate.PublicKey.EncodedKeyValue.RawData);

			var cspBlobData = CryptoApiHelper.EncodePublicBlob(cspObject);

			var publicKey = new Gost3410AsymmetricAlgorithm();
			publicKey.ImportCspBlob(cspBlobData);

			return publicKey;
		}
	}
}