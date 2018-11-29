using System.IO;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_R3411;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_R3411
{
	/// <summary>
	/// Вычисление хэша в соответствии с ГОСТ Р 34.11-2012/256.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет хэш в соответствии с ГОСТ Р 34.11-2012/256 и проверяет его корректность.
	/// </remarks>
	[TestFixture(Description = "Вычисление хэша в соответствии с ГОСТ Р 34.11-2012/256")]
	public class Gost_R3411_2012_256_HashAlgorithmTest
	{
		[Test]
		[TestCase(TestConfig.ProviderType)]
		[TestCase(TestConfig.ProviderType_2012_512)]
		[TestCase(TestConfig.ProviderType_2012_1024)]
		public void ShouldComputeHash(ProviderTypes providerType)
		{
			// Given
			var dataStream = CreateDataStream();

			// When

			byte[] hashValue;

			using (var hash = new Gost_R3411_2012_256_HashAlgorithm(providerType))
			{
				hashValue = hash.ComputeHash(dataStream);
			}

			// Then
			Assert.IsNotNull(hashValue);
			Assert.AreEqual(256, 8 * hashValue.Length);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data to hash..."));
		}
	}
}