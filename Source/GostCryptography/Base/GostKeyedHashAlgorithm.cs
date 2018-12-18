using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех алгоритмов хэширования ГОСТ на основе ключей.
	/// </summary>
	public abstract class GostKeyedHashAlgorithm : KeyedHashAlgorithm, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostKeyedHashAlgorithm(int hashSize) : this(GostCryptoConfig.ProviderType, hashSize)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		[SecuritySafeCritical]
		protected GostKeyedHashAlgorithm(ProviderType providerType, int hashSize)
		{
			ProviderType = providerType;
			HashSizeValue = hashSize;
		}


		/// <inheritdoc />
		public ProviderType ProviderType { get; }

		/// <inheritdoc />
		public abstract string AlgorithmName { get; }
	}
}