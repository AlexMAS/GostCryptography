using System.IO;
using System.Linq;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_28147_89
{
	/// <summary>
	/// Вычисление имитовставки на базе общего симметричного ключа ГОСТ 28147-89.
	/// </summary>
	/// <remarks>
	/// Тест выполняет подпись и проверку подписи потока байт с использованием имитовставки.
	/// </remarks>
	[TestFixture(Description = "Вычисление имитовставки на базе общего симметричного ключа ГОСТ 28147-89")]
	public class Gost_28147_89_ImitHashAlgorithmTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Providers))]
		public void ShouldComputeImitHash(ProviderType providerType)
		{
			// Given
			var dataStream = CreateDataStream();
			var sharedKey = new Gost_28147_89_SymmetricAlgorithm(providerType);

			// When
			var imitDataStream = CreateImitDataStream(sharedKey, dataStream);
			var isValidImitDataStream = VerifyImitDataStream(sharedKey, imitDataStream);

			// Then
			Assert.IsTrue(isValidImitDataStream);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for imit..."));
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

				// Сравнение исходной имитовставки с ожидаемой
				return imitHashValue.SequenceEqual(expectedImitHashValue);
			}
		}
	}
}