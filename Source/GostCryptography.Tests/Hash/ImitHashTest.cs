using System.IO;
using System.Linq;
using System.Text;

using GostCryptography.Gost_28147_89;

using NUnit.Framework;

namespace GostCryptography.Tests.Hash
{
	/// <summary>
	/// Вычисление имитовставки и ее проверка на базе общего симметричного ключа.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет имитовставку на базе общего симметричного ключа, 
	/// добавляя ее в выходной поток, а затем проверяет полученную имитовставку. 
	/// </remarks>
	[TestFixture(Description = "Вычисление имитовставки и ее проверка на базе общего симметричного ключа")]
	public sealed class ImitHashTest
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
		public void ShouldComputeImitHash()
		{
			// Given
			var dataStream = CreateDataStream();

			// When
			var imitDataStream = CreateImitDataStream(_sharedKey, dataStream);
			var isValidImitDataStream = VerifyImitDataStream(_sharedKey, imitDataStream);

			// Then
			Assert.IsTrue(isValidImitDataStream);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for hash..."));
		}

		private static Stream CreateImitDataStream(Gost_28147_89_SymmetricAlgorithmBase sharedKey, Stream dataStream)
		{
			// Создание объекта для вычисления имитовставки
			using (var imitHash = new Gost_28147_89_ImitHashAlgorithm(sharedKey))
			{
				// Вычисление имитовставки для потока данных
				var imitHashValue = imitHash.ComputeHash(dataStream);

				// Запись имитовставки в начало выходного потока данных
				var imitDataStream = new MemoryStream();
				imitDataStream.Write(imitHashValue, 0, imitHashValue.Length);

				// Копирование исходного потока данных в выходной поток
				dataStream.Position = 0;
				dataStream.CopyTo(imitDataStream);

				imitDataStream.Position = 0;

				return imitDataStream;
			}
		}

		private static bool VerifyImitDataStream(Gost_28147_89_SymmetricAlgorithmBase sharedKey, Stream imitDataStream)
		{
			// Создание объекта для вычисления имитовставки
			using (var imitHash = new Gost_28147_89_ImitHashAlgorithm(sharedKey))
			{
				// Считывание имитовставки из потока данных
				var imitHashValue = new byte[imitHash.HashSize / 8];
				imitDataStream.Read(imitHashValue, 0, imitHashValue.Length);

				// Вычисление реального значения имитовставки для потока данных
				var expectedImitHashValue = imitHash.ComputeHash(imitDataStream);

				// Сравнение исходной имитовствки с ожидаемой
				return imitHashValue.SequenceEqual(expectedImitHashValue);
			}
		}
	}
}