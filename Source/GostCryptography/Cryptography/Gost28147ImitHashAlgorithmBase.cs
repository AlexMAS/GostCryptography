using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций функции вычисления имитовставки по ГОСТ 28147.
	/// </summary>
	public abstract class Gost28147ImitHashAlgorithmBase : KeyedHashAlgorithm
	{
		/// <summary>
		/// Размер хэша по умолчанию.
		/// </summary>
		public const int DefaultHashSize = 32;

		/// <summary>
		/// Алгоритм симметричного шифрования ключа.
		/// </summary>
		public abstract Gost28147SymmetricAlgorithmBase KeyAlgorithm { get; set; }
	}
}