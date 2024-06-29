﻿using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Gost_R3411;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_R3411
{
	/// <summary>
	/// Использование PRF на базе алгоритма хэширования ГОСТ Р 34.11-2012/256.
	/// </summary>
	[TestFixture(Description = "Использование PRF на базе алгоритма хэширования ГОСТ Р 34.11-2012/256")]
	public class Gost_R3411_2012_256_PRFTest
	{
		private static readonly byte[] Label = { 1, 2, 3, 4, 5 };
		private static readonly byte[] Seed = { 6, 7, 8, 9, 0 };
		private static readonly byte[] TestData = Encoding.UTF8.GetBytes("Some data to encrypt...");


		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Providers))]
		public void ShouldDeriveBytes(ProviderType providerType)
		{
			// Given
			var initKey = new Gost_28147_89_SymmetricAlgorithm(providerType);

			// When

			byte[] randomBytes1;
			byte[] randomBytes2;
			byte[] randomBytes3;

			using (var prf = new Gost_R3411_2012_256_PRF(initKey, Label, Seed))
			{
				randomBytes1 = prf.DeriveBytes();
				randomBytes2 = prf.DeriveBytes();
				randomBytes3 = prf.DeriveBytes();
			}

			// Then
			Assert.IsNotNull(randomBytes1);
			Assert.IsNotNull(randomBytes2);
			Assert.IsNotNull(randomBytes3);
			Assert.AreEqual(256, 8 * randomBytes1.Length);
			Assert.AreEqual(256, 8 * randomBytes2.Length);
			Assert.AreEqual(256, 8 * randomBytes3.Length);
			CollectionAssert.AreNotEqual(randomBytes1, randomBytes2);
			CollectionAssert.AreNotEqual(randomBytes1, randomBytes3);
			CollectionAssert.AreNotEqual(randomBytes2, randomBytes3);
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Providers))]
		public void ShouldDeriveKey(ProviderType providerType)
		{
			// TODO: VipNet does not support this feature - https://infotecs.ru/forum/topic/10142-oshibka-pri-sozdanii-klyucha-shifrovaniya-na-osnove-dannyih-polzovatelya-cryptderivekey/
			if (providerType.IsVipNet())
			{
				Assert.Ignore("VipNet does not support this feature");
			}

			// Given
			var initKey = new Gost_28147_89_SymmetricAlgorithm(providerType);

			// When

			GostSymmetricAlgorithm randomKey1;
			GostSymmetricAlgorithm randomKey2;
			GostSymmetricAlgorithm randomKey3;

			using (var prf = new Gost_R3411_2012_256_PRF(initKey, Label, Seed))
			{
				randomKey1 = prf.DeriveKey();
				randomKey2 = prf.DeriveKey();
				randomKey3 = prf.DeriveKey();
			}

			// Then
			Assert.IsNotNull(randomKey1);
			Assert.IsNotNull(randomKey2);
			Assert.IsNotNull(randomKey3);
			AssertKeyIsValid(randomKey1);
			AssertKeyIsValid(randomKey2);
			AssertKeyIsValid(randomKey3);
			AssertKeysAreNotEqual(randomKey1, randomKey2);
			AssertKeysAreNotEqual(randomKey1, randomKey3);
			AssertKeysAreNotEqual(randomKey2, randomKey3);
		}


		public static void AssertKeyIsValid(GostSymmetricAlgorithm key)
		{
			var encryptedData = EncryptData(key, TestData);
			var decryptedData = DecryptData(key, encryptedData);
			CollectionAssert.AreEqual(TestData, decryptedData);
		}

		public static void AssertKeysAreNotEqual(GostSymmetricAlgorithm key1, GostSymmetricAlgorithm key2)
		{
			var encryptedData1 = EncryptData(key1, TestData);
			var encryptedData2 = EncryptData(key2, TestData);
			CollectionAssert.AreNotEqual(encryptedData1, encryptedData2);
		}


		public static byte[] EncryptData(GostSymmetricAlgorithm key, byte[] data)
		{
			var transform = key.CreateEncryptor();
			return transform.TransformFinalBlock(data, 0, data.Length);
		}

		public static byte[] DecryptData(GostSymmetricAlgorithm key, byte[] data)
		{
			var transform = key.CreateDecryptor();
			return transform.TransformFinalBlock(data, 0, data.Length);
		}
	}
}