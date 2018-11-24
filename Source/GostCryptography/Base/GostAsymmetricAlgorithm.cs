using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех ассиметричных алгоритмов ГОСТ.
	/// </summary>
	public abstract class GostAsymmetricAlgorithm : AsymmetricAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostAsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostAsymmetricAlgorithm(ProviderTypes providerType)
		{
			ProviderType = providerType;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public ProviderTypes ProviderType { get; }


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