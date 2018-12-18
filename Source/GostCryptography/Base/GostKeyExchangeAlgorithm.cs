using System;
using System.Security;
using System.Security.Cryptography;

using GostCryptography.Config;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс всех реализаций общего секретного ключа ГОСТ.
	/// </summary>
	public abstract class GostKeyExchangeAlgorithm : IDisposable, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostKeyExchangeAlgorithm() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostKeyExchangeAlgorithm(ProviderType providerType)
		{
			ProviderType = providerType;
		}


		/// <inheritdoc />
		public ProviderType ProviderType { get; }

		/// <inheritdoc />
		public virtual string AlgorithmName => GetType().Name;


		/// <summary>
		/// Экспортирует (шифрует) общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract byte[] EncodeKeyExchange(SymmetricAlgorithm keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod);

		/// <summary>
		/// Импортирует (дешифрует) общий секретный ключ.
		/// </summary>
		/// <param name="encodedKeyExchangeData">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract SymmetricAlgorithm DecodeKeyExchange(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod);


		/// <summary>
		/// Освобождает неуправляемые ресурсы.
		/// </summary>
		protected virtual void Dispose(bool disposing)
		{
		}

		/// <inheritdoc />
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		/// <inheritdoc />
		~GostKeyExchangeAlgorithm()
		{
			Dispose(false);
		}
	}
}