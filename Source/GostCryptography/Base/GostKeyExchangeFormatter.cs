using System;
using System.Security.Cryptography;

namespace GostCryptography.Base
{
	/// <summary>
	/// Базовый класс для шифрования общего секретного ключа по ГОСТ.
	/// </summary>
	public abstract class GostKeyExchangeFormatter : AsymmetricKeyExchangeFormatter
	{
		/// <summary>
		/// Шифрует общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Алгоритм шифрования общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public abstract byte[] CreateKeyExchangeData(SymmetricAlgorithm keyExchangeAlgorithm);
	}
}