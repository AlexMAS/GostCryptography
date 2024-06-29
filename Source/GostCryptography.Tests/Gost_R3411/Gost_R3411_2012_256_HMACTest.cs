﻿using System.IO;
using System.Linq;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Gost_R3411;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_R3411
{
	/// <summary>
	/// Вычисление HMAC на базе алгоритма хэширования ГОСТ Р 34.11-2012/256 и общего симметричного ключа ГОСТ 28147-89.
	/// </summary>
	/// <remarks>
	/// Тест выполняет подпись и проверку подписи потока байт с использованием HMAC.
	/// </remarks>
	[TestFixture(Description = "Вычисление HMAC на базе алгоритма хэширования ГОСТ Р 34.11-2012/256 и общего симметричного ключа ГОСТ 28147-89")]
	public class Gost_R3411_2012_256_HMACTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Providers))]
		public void ShouldComputeHMAC(ProviderType providerType)
		{
			// Given
			var dataStream = CreateDataStream();
			var sharedKey = new Gost_28147_89_SymmetricAlgorithm(providerType);

			// When
			var hmacDataStream = CreateHmacDataStream(sharedKey, dataStream);
			var isValidHmacDataStream = VerifyHmacDataStream(sharedKey, hmacDataStream);

			// Then
			Assert.IsTrue(isValidHmacDataStream);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data to HMAC..."));
		}

		private static Stream CreateHmacDataStream(GostSymmetricAlgorithm sharedKey, Stream dataStream)
		{
			// Создание объекта для вычисления HMAC
			using (var hmac = new Gost_R3411_2012_256_HMAC(sharedKey))
			{
				// Вычисление HMAC для потока данных
				var hmacValue = hmac.ComputeHash(dataStream);

				// Запись HMAC в начало выходного потока данных
				var hmacDataStream = new MemoryStream();
				hmacDataStream.Write(hmacValue, 0, hmacValue.Length);

				// Копирование исходного потока данных в выходной поток
				dataStream.Position = 0;
				dataStream.CopyTo(hmacDataStream);

				hmacDataStream.Position = 0;

				return hmacDataStream;
			}
		}

		private static bool VerifyHmacDataStream(GostSymmetricAlgorithm sharedKey, Stream hmacDataStream)
		{
			// Создание объекта для вычисления HMAC
			using (var hmac = new Gost_R3411_2012_256_HMAC(sharedKey))
			{
				// Считывание HMAC из потока данных
				var hmacValue = new byte[hmac.HashSize / 8];
				hmacDataStream.Read(hmacValue, 0, hmacValue.Length);

				// Вычисление реального значения HMAC для потока данных
				var expectedHmacValue = hmac.ComputeHash(hmacDataStream);

				// Сравнение исходного HMAC с ожидаемым
				return hmacValue.SequenceEqual(expectedHmacValue);
			}
		}
	}
}