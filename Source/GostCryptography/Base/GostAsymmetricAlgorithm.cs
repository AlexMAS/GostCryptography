using System.Security.Cryptography;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех асимметричных алгоритмов ГОСТ.
	/// </summary>
	public abstract class GostAsymmetricAlgorithm : AsymmetricAlgorithm, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		/// <param name="keySize">Размер ключа в битах.</param>
		protected GostAsymmetricAlgorithm(ProviderType providerType, int keySize)
		{
			ProviderType = providerType;
			KeySizeValue = keySize;
			LegalKeySizesValue = new[] { new KeySizes(keySize, keySize, 0) };
		}


		/// <inheritdoc />
		public ProviderType ProviderType { get; }

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
		public abstract GostKeyExchangeFormatter CreateKeyExchangeFormatter();

		/// <summary>
		/// Создает экземпляр <see cref="GostKeyExchangeDeformatter"/>.
		/// </summary>
		public abstract GostKeyExchangeDeformatter CreateKeyExchangeDeformatter();
	}
}