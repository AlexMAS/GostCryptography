using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех реализаций Hash-based Message Authentication Code (HMAC) на базе алгоритмов ГОСТ.
	/// </summary>
	public abstract class GostHMAC : HMAC, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostHMAC(int hashSize) : this(GostCryptoConfig.ProviderType, hashSize)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="hashSize">Размер хэш-кода в битах.</param>
		[SecuritySafeCritical]
		protected GostHMAC(ProviderType providerType, int hashSize)
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