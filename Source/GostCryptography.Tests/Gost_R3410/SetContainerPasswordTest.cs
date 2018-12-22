using System;
using System.Security;

using GostCryptography.Gost_R3410;

using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Base;

namespace GostCryptography.Tests.Gost_R3410
{
	[TestFixture(Description = "Проверка возможности установки пароля для контейнера ключей")]
	public class SetContainerPasswordTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2001_Certificates))]
		public void ShouldSetContainerPassword_R3410_2001(TestCertificateInfo testCase)
		{
			// Given
			var data = GetSomeData();
			var certificate = testCase.Certificate;
			var securePassword = CreateSecureString(TestConfig.ContainerPassword);

			// When

			var privateKeyInfo = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2001_AsymmetricAlgorithm(privateKeyInfo);
			privateKey.SetContainerPassword(securePassword);

			var signature = CreateSignature(privateKey, data);
			var isValidSignature = VerifySignature(privateKey, data, signature);

			// Then
			Assert.IsTrue(isValidSignature);
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_256_Certificates))]
		public void ShouldSetContainerPassword_R3410_2012_256(TestCertificateInfo testCase)
		{
			// Given
			var data = GetSomeData();
			var certificate = testCase.Certificate;
			var securePassword = CreateSecureString(TestConfig.ContainerPassword);

			// When

			var privateKeyInfo = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2012_256_AsymmetricAlgorithm(privateKeyInfo);
			privateKey.SetContainerPassword(securePassword);

			var signature = CreateSignature(privateKey, data);
			var isValidSignature = VerifySignature(privateKey, data, signature);

			// Then
			Assert.IsTrue(isValidSignature);
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_512_Certificates))]
		public void ShouldSetContainerPassword_R3410_2012_512(TestCertificateInfo testCase)
		{
			// Given
			var data = GetSomeData();
			var certificate = testCase.Certificate;
			var securePassword = CreateSecureString(TestConfig.ContainerPassword);

			// When

			var privateKeyInfo = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2012_512_AsymmetricAlgorithm(privateKeyInfo);
			privateKey.SetContainerPassword(securePassword);

			var signature = CreateSignature(privateKey, data);
			var isValidSignature = VerifySignature(privateKey, data, signature);

			// Then
			Assert.IsTrue(isValidSignature);
		}


		private static byte[] CreateSignature(GostAsymmetricAlgorithm privateKey, byte[] data)
		{
			byte[] hash;

			using (var hashAlg = privateKey.CreateHashAlgorithm())
			{
				hash = hashAlg.ComputeHash(data);
			}

			return privateKey.CreateSignature(hash);
		}

		private static bool VerifySignature(GostAsymmetricAlgorithm publicKey, byte[] data, byte[] signature)
		{
			byte[] hash;

			using (var hashAlg = publicKey.CreateHashAlgorithm())
			{
				hash = hashAlg.ComputeHash(data);
			}

			return publicKey.VerifySignature(hash, signature);
		}

		private static SecureString CreateSecureString(string value)
		{
			var result = new SecureString();

			foreach (var c in value)
			{
				result.AppendChar(c);
			}

			result.MakeReadOnly();

			return result;
		}

		private static byte[] GetSomeData()
		{
			var random = new Random();
			var data = new byte[1024];
			random.NextBytes(data);
			return data;
		}
	}
}