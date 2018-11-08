using System.Security;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех алгоритмов генерации псевдослучайной последовательности (Pseudorandom Function, PRF) ГОСТ.
	/// </summary>
	public abstract class GostPrf
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostPrf(int providerType)
		{
			ProviderType = providerType;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public int ProviderType { get; }
	}
}