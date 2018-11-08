using System.Security;
using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций Hash-based Message Authentication Code (HMAC) на базе алгоритмов ГОСТ.
	/// </summary>
	public abstract class GostHmac : HMAC
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <remarks>
		/// По умолчанию использует криптографический провайдер, установленный в <see cref="GostCryptoConfig.ProviderType"/>.
		/// </remarks>
		[SecuritySafeCritical]
		protected GostHmac() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="providerType">Тип криптографического провайдера.</param>
		[SecuritySafeCritical]
		protected GostHmac(int providerType)
		{
			ProviderType = providerType;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public int ProviderType { get; }
	}
}