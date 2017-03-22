using System.IO;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Hash
{
    /// <summary>
    /// Вычисление хэша в соответствии с ГОСТ Р 34.11.
    /// </summary>
    /// <remarks>
    /// Тест создает поток байт, вычисляет хэш в соответствии с ГОСТ Р 34.11 и проверяет его корректность.
    /// </remarks>
    [TestFixture(Description = "Вычисление хэша в соответствии с ГОСТ Р 34.11")]
    public sealed class HashTest
    {
        [Test]
        public void ShouldComputeHash3411_94()
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

        [Test]
        public void ShouldComputeHash3411_2012_256()
        {
            // Given
            var dataStream = CreateDataStream();

            // When

            byte[] hashValue;

            using (var hash = new Gost34112012256HashAlgorithm())
            {
                hashValue = hash.ComputeHash(dataStream);
            }

            // Then
            Assert.IsNotNull(hashValue);
            Assert.AreEqual(32, hashValue.Length);
        }

        [Test]
        public void ShouldComputeHash3411_2012_512()
        {
            // Given
            var dataStream = CreateDataStream();

            // When

            byte[] hashValue;

            using (var hash = new Gost34112012512HashAlgorithm())
            {
                hashValue = hash.ComputeHash(dataStream);
            }

            // Then
            Assert.IsNotNull(hashValue);
            Assert.AreEqual(64, hashValue.Length);
        }


        private static Stream CreateDataStream()
        {
            // Некоторый поток байт

            return new MemoryStream(Encoding.UTF8.GetBytes("Some data for hash..."));
        }
    }
}