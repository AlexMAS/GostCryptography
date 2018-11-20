using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех алгоритмов хэширования ГОСТ.
	/// </summary>
	public abstract class GostHashAlgorithm : HashAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostHashAlgorithm(int hashSize) : this(GostCryptoConfig.ProviderType, hashSize)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		[SecuritySafeCritical]
		protected GostHashAlgorithm(int providerType, int hashSize)
		{
			ProviderType = providerType;
			HashSizeValue = hashSize;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public int ProviderType { get; }


		/// <summary>
		/// Наименование алгоритма хэширования.
		/// </summary>
		public abstract string AlgorithmName { get; }
	}
}