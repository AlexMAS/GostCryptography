﻿using System.Security;
using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех алгоритмов симметричного шифрования ГОСТ.
	/// </summary>
	public abstract class GostSymmetricAlgorithm : SymmetricAlgorithm
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
		protected GostSymmetricAlgorithm(int providerType)
		{
			ProviderType = providerType;
		}


		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		public int ProviderType { get; }
	}
}