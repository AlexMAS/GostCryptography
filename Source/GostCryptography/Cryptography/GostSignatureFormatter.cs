using System;
using System.Security.Cryptography;

using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Класс вычисления цифровой подписи по ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class GostSignatureFormatter : AsymmetricSignatureFormatter
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		public GostSignatureFormatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="privateKey">Закрытый ключ для вычисления цифровой подписи.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public GostSignatureFormatter(AsymmetricAlgorithm privateKey)
			: this()
		{
			SetKey(privateKey);
		}


		private Gost3410AsymmetricAlgorithmBase _privateKey;


		/// <summary>
		/// Устанавливает закрытый ключ для вычисления цифрововй подписи.
		/// </summary>
		/// <param name="privateKey">Закрытый ключ для вычисления цифровой подписи.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public override void SetKey(AsymmetricAlgorithm privateKey)
		{
			if (privateKey == null)
			{
				throw ExceptionUtility.ArgumentNull("privateKey");
			}

			if (!(privateKey is Gost3410AsymmetricAlgorithmBase))
			{
				throw ExceptionUtility.ArgumentOutOfRange("privateKey", Resources.ShouldSupportGost3410);
			}

			_privateKey = (Gost3410AsymmetricAlgorithmBase)privateKey;
		}

		/// <summary>
		/// Устанавливает алгоритм хэширования для вычисления цифрововй подписи.
		/// </summary>
		/// <param name="hashAlgorithmName">Наименование алгоритма хэширования.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public override void SetHashAlgorithm(string hashAlgorithmName)
		{
		}

		/// <summary>
		/// Вычисляет цифровую подпись.
		/// </summary>
		/// <param name="hash">Значение хэша данных.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public override byte[] CreateSignature(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			var reverseSignature = _privateKey.CreateSignature(hash);
			Array.Reverse(reverseSignature);

			return reverseSignature;
		}
	}
}