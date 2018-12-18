using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех алгоритмов симметричного шифрования ГОСТ.
	/// </summary>
	public abstract class GostSymmetricAlgorithm : SymmetricAlgorithm, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostSymmetricAlgorithm() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostSymmetricAlgorithm(ProviderType providerType)
		{
			ProviderType = providerType;
		}


		/// <inheritdoc />
		public ProviderType ProviderType { get; }

		/// <inheritdoc />
		public abstract string AlgorithmName { get; }
	}
}