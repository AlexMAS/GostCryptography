using System;
using System.Security;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех алгоритмов генерации псевдослучайной последовательности (Pseudorandom Function, PRF) ГОСТ.
	/// </summary>
	public abstract class GostPRF : IDisposable, IGostAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostPRF(ProviderType providerType)
		{
			ProviderType = providerType;
		}


		/// <inheritdoc />
		public ProviderType ProviderType { get; }

		/// <inheritdoc />
		public abstract string AlgorithmName { get; }


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
		~GostPRF()
		{
			Dispose(false);
		}
	}
}