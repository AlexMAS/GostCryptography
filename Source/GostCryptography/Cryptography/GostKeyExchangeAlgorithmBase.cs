using System;
using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций общего секретного ключа.
	/// </summary>
	public abstract class GostKeyExchangeAlgorithmBase : IDisposable
	{
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


		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
		}
	}
}