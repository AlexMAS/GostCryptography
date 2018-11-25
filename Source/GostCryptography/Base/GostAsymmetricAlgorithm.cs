using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех ассиметричных алгоритмов ГОСТ.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public abstract class GostAsymmetricAlgorithm : AsymmetricAlgorithm, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecurityCritical]
		[SecuritySafeCritical]
		protected GostAsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecurityCritical]
		[SecuritySafeCritical]
		protected GostAsymmetricAlgorithm(ProviderTypes providerType)
		{
			ProviderType = providerType;
		}


		/// <inheritdoc />
		public ProviderTypes ProviderType { get; }

		/// <inheritdoc />
		public abstract string AlgorithmName { get; }


		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		public abstract byte[] CreateSignature(byte[] hash);

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		public abstract bool VerifySignature(byte[] hash, byte[] signature);


		/// <summary>
		/// Создает экземпляр <see cref="GostHashAlgorithm"/>.
		/// </summary>
		public abstract GostHashAlgorithm CreateHashAlgorithm();


		/// <summary>
		/// Создает экземпляр <see cref="GostKeyExchangeFormatter"/>.
		/// </summary>
		/// <returns></returns>
		public abstract GostKeyExchangeFormatter CreatKeyExchangeFormatter();

		/// <summary>
		/// Создает экземпляр <see cref="GostKeyExchangeDeformatter"/>.
		/// </summary>
		public abstract GostKeyExchangeDeformatter CreateKeyExchangeDeformatter();
	}
}