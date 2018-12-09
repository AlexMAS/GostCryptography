using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Base;

namespace GostCryptography.Tests
{
	public static class TestConfig
	{
		public const StoreName DefaultStoreName = StoreName.My;
		public const StoreLocation DefaultStoreLocation = StoreLocation.LocalMachine;

		public static StoreName StoreName => DefaultStoreName;
		public static StoreLocation StoreLocation => DefaultStoreLocation;

		public static readonly IEnumerable<ProviderTypes> Providers = ProviderTypesExtensions.CryptoProProviders;

		public static readonly TestCertificateInfo Gost_R3410_2001 = new TestCertificateInfo("ГОСТ Р 34.10-2001", () => FindGostCertificate(filter: c => c.IsGost_R3410_2001()));
		public static readonly TestCertificateInfo Gost_R3410_2012_256 = new TestCertificateInfo("ГОСТ Р 34.10-2012/256", () => FindGostCertificate(filter: c => c.IsGost_R3410_2012_256()));
		public static readonly TestCertificateInfo Gost_R3410_2012_512 = new TestCertificateInfo("ГОСТ Р 34.10-2012/512", () => FindGostCertificate(filter: c => c.IsGost_R3410_2012_512()));

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2001_Certificates
		{
			get
			{
				if (Gost_R3410_2001.Certificate != null) yield return Gost_R3410_2001;
			}
		}

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2012_256_Certificates
		{
			get
			{
				if (Gost_R3410_2012_256.Certificate != null) yield return Gost_R3410_2012_256;
			}
		}

		public static IEnumerable<TestCertificateInfo> Gost_R3410_2012_512_Certificates
		{
			get
			{
				if (Gost_R3410_2012_512.Certificate != null) yield return Gost_R3410_2012_512;
			}
		}

		public static IEnumerable<TestCertificateInfo> Certificates
		{
			get
			{
				if (Gost_R3410_2001.Certificate != null) yield return Gost_R3410_2001;
				if (Gost_R3410_2012_256.Certificate != null) yield return Gost_R3410_2012_256;
				if (Gost_R3410_2012_512.Certificate != null) yield return Gost_R3410_2012_512;
			}
		}


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