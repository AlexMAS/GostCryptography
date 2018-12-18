using System.Reflection;

using GostCryptography;
using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Asn1.Gost.Gost_R3410_94;
using GostCryptography.Gost_R3410;

// ReSharper disable once CheckNamespace
namespace System.Security.Cryptography.X509Certificates
{
	/// <summary>
	/// Методы расширения <see cref="X509Certificate2"/>.
	/// </summary>
	[SecurityCritical]
	public static class X509CertificateHelper
	{
		/// <summary>
		/// Возвращает <see langword="true"/> для сертификатов ГОСТ.
		/// </summary>
		public static bool IsGost(this X509Certificate2 certificate)
		{
			return certificate.IsGost_R3410_2012_512()
				|| certificate.IsGost_R3410_2012_256()
				|| certificate.IsGost_R3410_2001()
				|| certificate.IsGost_R3410_94();
		}

		/// <summary>
		/// Возвращает <see langword="true"/> для сертификатов ГОСТ Р 34.10-94.
		/// </summary>
		public static bool IsGost_R3410_94(this X509Certificate2 certificate)
		{
			return Gost_R3410_94_Constants.KeyAlgorithm.Value.Equals(certificate.GetKeyAlgorithm());
		}

		/// <summary>
		/// Возвращает <see langword="true"/> для сертификатов ГОСТ Р 34.10-2001.
		/// </summary>
		public static bool IsGost_R3410_2001(this X509Certificate2 certificate)
		{
			return Gost_R3410_2001_Constants.KeyAlgorithm.Value.Equals(certificate.GetKeyAlgorithm());
		}

		/// <summary>
		/// Возвращает <see langword="true"/> для сертификатов ГОСТ Р 34.10-2012/256.
		/// </summary>
		public static bool IsGost_R3410_2012_256(this X509Certificate2 certificate)
		{
			return Gost_R3410_2012_256_Constants.KeyAlgorithm.Value.Equals(certificate.GetKeyAlgorithm());
		}

		/// <summary>
		/// Возвращает <see langword="true"/> для сертификатов ГОСТ Р 34.10-2012/512.
		/// </summary>
		public static bool IsGost_R3410_2012_512(this X509Certificate2 certificate)
		{
			return Gost_R3410_2012_512_Constants.KeyAlgorithm.Value.Equals(certificate.GetKeyAlgorithm());
		}


		/// <summary>
		/// Возвращает <see cref="Oid"/> функции хэширования сертификата.
		/// </summary>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public static Oid GetHashAlgorithm(this X509Certificate2 certificate)
		{
			if (certificate.IsGost_R3410_2012_512())
			{
				return Gost_R3410_2012_512_Constants.HashAlgorithm.ToOid();
			}

			if (certificate.IsGost_R3410_2012_256())
			{
				return Gost_R3410_2012_256_Constants.HashAlgorithm.ToOid();
			}

			if (certificate.IsGost_R3410_2001())
			{
				return Gost_R3410_2001_Constants.HashAlgorithm.ToOid();
			}

			if (certificate.IsGost_R3410_94())
			{
				return Gost_R3410_94_Constants.HashAlgorithm.ToOid();
			}

			return null;
		}


		private static volatile MethodInfo _getPrivateKeyInfoMethod;
		private static readonly object GetPrivateKeyInfoMethodSync = new object();

		/// <summary>
		/// Возвращает параметры <see cref="CspParameters"/> закрытого ключа сертификата.
		/// </summary>
		/// <param name="certificate"></param>
		/// <returns></returns>
		public static CspParameters GetPrivateKeyInfo(this X509Certificate2 certificate)
		{
			if (certificate == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(certificate));
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


		/// <summary>
		/// Возвращает закрытый ключ сертификата.
		/// </summary>
		public static AsymmetricAlgorithm GetPrivateKeyAlgorithm(this X509Certificate2 certificate)
		{
			if (certificate.IsGost_R3410_2012_512())
			{
				var cspParameters = GetPrivateKeyInfo(certificate);
				return new Gost_R3410_2012_512_AsymmetricAlgorithm(cspParameters);
			}

			if (certificate.IsGost_R3410_2012_256())
			{
				var cspParameters = GetPrivateKeyInfo(certificate);
				return new Gost_R3410_2012_256_AsymmetricAlgorithm(cspParameters);
			}

			if (certificate.IsGost_R3410_2001())
			{
				var cspParameters = GetPrivateKeyInfo(certificate);
				return new Gost_R3410_2001_AsymmetricAlgorithm(cspParameters);
			}

			return certificate.PrivateKey;
		}

		/// <summary>
		/// Возвращает открытый ключ сертификата.
		/// </summary>
		public static AsymmetricAlgorithm GetPublicKeyAlgorithm(this X509Certificate2 certificate)
		{
			if (certificate.IsGost_R3410_2012_512())
			{
				var publicKey = new Gost_R3410_2012_512_AsymmetricAlgorithm();
				var encodedParameters = certificate.PublicKey.EncodedParameters.RawData;
				var encodedKeyValue = certificate.PublicKey.EncodedKeyValue.RawData;
				publicKey.ImportCspBlob(encodedParameters, encodedKeyValue);
				return publicKey;
			}

			if (certificate.IsGost_R3410_2012_256())
			{
				var publicKey = new Gost_R3410_2012_256_AsymmetricAlgorithm();
				var encodedParameters = certificate.PublicKey.EncodedParameters.RawData;
				var encodedKeyValue = certificate.PublicKey.EncodedKeyValue.RawData;
				publicKey.ImportCspBlob(encodedParameters, encodedKeyValue);
				return publicKey;
			}

			if (certificate.IsGost_R3410_2001())
			{
				var publicKey = new Gost_R3410_2001_AsymmetricAlgorithm();
				var encodedParameters = certificate.PublicKey.EncodedParameters.RawData;
				var encodedKeyValue = certificate.PublicKey.EncodedKeyValue.RawData;
				publicKey.ImportCspBlob(encodedParameters, encodedKeyValue);
				return publicKey;
			}

			return certificate.PublicKey.Key;
		}
	}
}