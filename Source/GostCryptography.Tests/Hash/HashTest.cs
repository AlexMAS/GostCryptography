using System.IO;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Hash
{
	/// <summary>
	/// Вычисление хэша.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет хэш и проверяет его корректность.
	/// </remarks>
	[TestFixture(Description = "Вычисление хэша")]
	public sealed class HashTest
	{
		[Test]
		public void ShouldComputeHash()
		{
			// Given
			var dataStream = CreateDataStream();

			// When

			byte[] hashValue;

			using (var hash = new Gost3411HashAlgorithm())
			{
				hashValue = hash.ComputeHash(dataStream);
			}

			// Then
			Assert.IsNotNull(hashValue);
			Assert.AreEqual(32, hashValue.Length);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for hash..."));
		}
	}
}