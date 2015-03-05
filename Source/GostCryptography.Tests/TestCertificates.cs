using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Cryptography;

namespace GostCryptography.Tests
{
	static class TestCertificates
	{
		/// <summary>
		/// Имя хранилища для поиска тестового сертификата.
		/// </summary>
		/// <remarks>
		/// Значение равно <see cref="StoreName.My"/>.
		/// </remarks>
		public const StoreName CertStoreName = StoreName.My;

		/// <summary>
		/// Местоположение для поиска тестового сертификата.
		/// </summary>
		/// <remarks>
		/// Значение равно <see cref="StoreLocation.LocalMachine"/>.
		/// </remarks>
		public const StoreLocation CertStoreLocation = StoreLocation.LocalMachine;

		/// <summary>
		/// Сертификат ГОСТ Р 34.10-2001 с закрытым ключем.
		/// </summary>
		private static readonly X509Certificate2 GostCetificate = FindGostCertificate();


		/// <summary>
		/// Возвращает тестовый контейнер ключей ГОСТ.
		/// </summary>
		/// <remarks>
		/// Для простоты берется контейнер ключей сертификата, однако можно явно указать контейнер, например так:
		/// <code>
		/// var keyContainer1 = new CspParameters(ProviderTypes.VipNet, null, "MyVipNetContainer");
		/// var keyContainer2 = new CspParameters(ProviderTypes.CryptoPro, null, "MyCryptoProContainer");
		/// </code>
		/// </remarks>
		public static CspParameters GetKeyContainer()
		{
			return GostCetificate.GetPrivateKeyInfo();
		}

		/// <summary>
		/// Возвращает тестовый сертификат ГОСТ с закрытым ключем.
		/// </summary>
		public static X509Certificate2 GetCertificate()
		{
			return GostCetificate;
		}


		private static X509Certificate2 FindGostCertificate()
		{
			// Для тестирования берется первый найденный сертификат ГОСТ с закрытым ключем.

			var store = new X509Store(CertStoreName, CertStoreLocation);
			store.Open(OpenFlags.ReadOnly);

			try
			{
				foreach (var certificate in store.Certificates)
				{
					if (certificate.HasPrivateKey && certificate.SignatureAlgorithm.Value == "1.2.643.2.2.3")
					{
						return certificate;
					}
				}
			}
			finally
			{
				store.Close();
			}

			return null;
		}
	}
}