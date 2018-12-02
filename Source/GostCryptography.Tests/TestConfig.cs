using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Base;

namespace GostCryptography.Tests
{
	public static class TestConfig
	{
		public static StoreName StoreName => StoreName.My;
		public static StoreLocation StoreLocation => StoreLocation.LocalMachine;
		public static readonly IEnumerable<ProviderTypes> Providers = ProviderTypesExtensions.VipNetProviders;
		public static readonly TestCertificateInfo Gost_R3410_2001 = new TestCertificateInfo("ГОСТ Р 34.10-2001", () => FindGostCertificate(filter: c => c.IsGost_R3410_2001()));
		public static readonly TestCertificateInfo Gost_R3410_2012_256 = new TestCertificateInfo("ГОСТ Р 34.10-2012/256", () => FindGostCertificate(filter: c => c.IsGost_R3410_2012_256()));
		public static readonly TestCertificateInfo Gost_R3410_2012_512 = new TestCertificateInfo("ГОСТ Р 34.10-2012/512", () => FindGostCertificate(filter: c => c.IsGost_R3410_2012_512()));
		public static readonly IEnumerable<TestCertificateInfo> Certificates = new[] { Gost_R3410_2001, Gost_R3410_2012_256, Gost_R3410_2012_512 };


		public static X509Certificate2 FindGostCertificate(StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.LocalMachine, Predicate<X509Certificate2> filter = null)
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