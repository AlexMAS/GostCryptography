using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Base;
using GostCryptography.Config;

namespace GostCryptography.Tests
{
	public static class TestConfig
	{
		static TestConfig()
		{
			Providers = new[] { GostCryptoConfig.ProviderType, GostCryptoConfig.ProviderType_2012_512, GostCryptoConfig.ProviderType_2012_1024 };

			var gost_R3410_2001 = new TestCertificateInfo("ГОСТ Р 34.10-2001", FindGostCertificate(filter: c => c.IsGost_R3410_2001()));
			var gost_R3410_2012_256 = new TestCertificateInfo("ГОСТ Р 34.10-2012/256", FindGostCertificate(filter: c => c.IsGost_R3410_2012_256()));
			var gost_R3410_2012_512 = new TestCertificateInfo("ГОСТ Р 34.10-2012/512", FindGostCertificate(filter: c => c.IsGost_R3410_2012_512()));

			var gost_R3410_Certificates = new List<TestCertificateInfo> { gost_R3410_2001, gost_R3410_2012_256, gost_R3410_2012_512 };
			var gost_R3410_2001_Certificates = new List<TestCertificateInfo> { gost_R3410_2001 };
			var gost_R3410_2012_256_Certificates = new List<TestCertificateInfo> { gost_R3410_2012_256 };
			var gost_R3410_2012_512_Certificates = new List<TestCertificateInfo> { gost_R3410_2012_512 };

			gost_R3410_Certificates.RemoveAll(c => c.Certificate == null);
			gost_R3410_2001_Certificates.RemoveAll(c => c.Certificate == null);
			gost_R3410_2012_256_Certificates.RemoveAll(c => c.Certificate == null);
			gost_R3410_2012_512_Certificates.RemoveAll(c => c.Certificate == null);

			Gost_R3410_Certificates = gost_R3410_Certificates;
			Gost_R3410_2001_Certificates = gost_R3410_2001_Certificates;
			Gost_R3410_2012_256_Certificates = gost_R3410_2012_256_Certificates;
			Gost_R3410_2012_512_Certificates = gost_R3410_2012_512_Certificates;
		}


		public const StoreName DefaultStoreName = StoreName.My;

		public const StoreLocation DefaultStoreLocation = StoreLocation.LocalMachine;

		public static IEnumerable<ProviderType> Providers { get; }

		public static IEnumerable<TestCertificateInfo> Gost_R3410_Certificates { get; }

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2001_Certificates { get; }

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2012_256_Certificates { get; }

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2012_512_Certificates { get; }

		public const string ContainerPassword = "GostCryptography";


		[SecuritySafeCritical]
		public static X509Certificate2 FindGostCertificate(StoreName storeName = DefaultStoreName, StoreLocation storeLocation = DefaultStoreLocation, Predicate<X509Certificate2> filter = null)
		{
			var store = new X509Store(storeName, storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

			try
			{
				foreach (var certificate in store.Certificates)
				{
					if (certificate.HasPrivateKey && certificate.IsGost() && (filter == null || filter(certificate)))
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