using System;
using System.Security.Cryptography;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для дешифрования общего секретного ключа по ГОСТ.
	/// </summary>
	public abstract class GostKeyExchangeDeformatter : AsymmetricKeyExchangeDeformatter
	{
		/// <summary>
		/// Дешифрует общий секретный ключ.
		/// </summary>
		/// <param name="encryptedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public abstract SymmetricAlgorithm DecryptKeyExchangeAlgorithm(byte[] encryptedKeyExchangeData);
	}
}