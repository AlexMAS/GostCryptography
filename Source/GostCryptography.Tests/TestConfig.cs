using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Base;

namespace GostCryptography.Tests
{
	static class TestConfig
	{
		public const ProviderTypes ProviderType = ProviderTypes.VipNet;

		public const ProviderTypes ProviderType_2012_512 = ProviderTypes.VipNet_2012_512;

		public const ProviderTypes ProviderType_2012_1024 = ProviderTypes.VipNet_2012_1024;


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
		private static readonly X509Certificate2 GostCetificate2001 = FindGostCertificate(c => c.IsGost_R3410_2001());

		/// <summary>
		/// Сертификат ГОСТ Р 34.10-2012 с закрытым ключем.
		/// </summary>
		private static readonly X509Certificate2 GostCetificate = FindGostCertificate(c => c.IsGost_R3410_2012_256());


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


		public static X509Certificate2 FindGostCertificate(Predicate<X509Certificate2> filter)
		{
			var store = new X509Store(CertStoreName, CertStoreLocation);
			store.Open(OpenFlags.ReadOnly);

			try
			{
				foreach (var certificate in store.Certificates)
				{
					if (certificate.HasPrivateKey && certificate.IsGost() && filter(certificate))
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