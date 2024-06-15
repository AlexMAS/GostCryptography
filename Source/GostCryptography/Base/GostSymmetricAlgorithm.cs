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


		/// <summary>
		/// Хэширует секретный ключ.
		/// </summary>
		public abstract byte[] ComputeHash(HashAlgorithm hash);

		/// <summary>
		/// Экспортирует (шифрует) секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract byte[] EncodePrivateKey(GostSymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod);

		/// <summary>
		/// Импортирует (дешифрует) секретный ключ.
		/// </summary>
		/// <param name="encodedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract SymmetricAlgorithm DecodePrivateKey(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod);


		public abstract GostSymmetricAlgorithm Clone();
	}
}