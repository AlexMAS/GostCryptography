using System.Security;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для всех алгоритмов генерации псевдослучайной последовательности (Pseudorandom Function, PRF) ГОСТ.
	/// </summary>
	public abstract class GostPRF
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostPRF(int providerType)
		{
			ProviderType = providerType;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public int ProviderType { get; }
	}
}