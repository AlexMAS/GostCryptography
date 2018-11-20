using System.IO;
using System.Linq;
using System.Text;

using GostCryptography.Gost_28147_89;
using GostCryptography.Gost_R3411;

using NUnit.Framework;

namespace GostCryptography.Tests.Hash
{
	/// <summary>
	/// Вычисление HMAC (Hash-based Message Authentication Code) и его проверка на базе общего симметричного ключа.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет HMAC на базе общего симметричного ключа, добавляя его в выходной поток, 
	/// а затем проверяет полученный HMAC.
	/// </remarks>
	[TestFixture(Description = "Вычисление HMAC (Hash-based Message Authentication Code) и его проверка на базе общего симметричного ключа")]
	public sealed class HmacTest
	{
		private Gost_28147_89_SymmetricAlgorithmBase _sharedKey;

		[SetUp]
		public void SetUp()
		{
			_sharedKey = new Gost_28147_89_SymmetricAlgorithm();
		}

		[TearDown]
		public void TearDown()
		{
			try
			{
				_sharedKey.Dispose();
			}
			finally
			{
				_sharedKey = null;
			}
		}

		[Test]
		public void ShouldComputeHmacHash()
		{
			// Given
			var dataStream = CreateDataStream();

			// When
			var hmacDataStream = CreateHmacDataStream(_sharedKey, dataStream);
			var isValidHmacDataStream = VerifyHmacDataStream(_sharedKey, hmacDataStream);

			// Then
			Assert.IsTrue(isValidHmacDataStream);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for hash..."));
		}

		private static Stream CreateHmacDataStream(Gost_28147_89_SymmetricAlgorithmBase sharedKey, Stream dataStream)
		{
			// Создание объекта для вычисления HMAC
			using (var imitHash = new Gost_R3411_HMAC(sharedKey))
			{
				// Вычисление HMAC для потока данных
				var imitHashValue = imitHash.ComputeHash(dataStream);

				// Запись HMAC в начало выходного потока данных
				var imitDataStream = new MemoryStream();
				imitDataStream.Write(imitHashValue, 0, imitHashValue.Length);

				// Копирование исходного потока данных в выходной поток
				dataStream.Position = 0;
				dataStream.CopyTo(imitDataStream);

				imitDataStream.Position = 0;

				return imitDataStream;
			}
		}

		private static bool VerifyHmacDataStream(Gost_28147_89_SymmetricAlgorithmBase sharedKey, Stream imitDataStream)
		{
			// Создание объекта для вычисления HMAC
			using (var imitHash = new Gost_R3411_HMAC(sharedKey))
			{
				// Считывание HMAC из потока данных
				var imitHashValue = new byte[imitHash.HashSize / 8];
				imitDataStream.Read(imitHashValue, 0, imitHashValue.Length);

				// Вычисление реального значения HMAC для потока данных
				var expectedImitHashValue = imitHash.ComputeHash(imitDataStream);

				// Сравнение исходного HMAC с ожидаемым
				return imitHashValue.SequenceEqual(expectedImitHashValue);
			}
		}
	}
}