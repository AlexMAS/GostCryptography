using System;
using System.Security.Cryptography;

using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Класс проверки цифровой подписи по ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class GostSignatureDeformatter : AsymmetricSignatureDeformatter
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		public GostSignatureDeformatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="publicKey">Открытый ключ для проверки цифровой подписи.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public GostSignatureDeformatter(AsymmetricAlgorithm publicKey)
			: this()
		{
			SetKey(publicKey);
		}


		private Gost3410AsymmetricAlgorithmBase _publicKey;


		/// <summary>
		/// Устанавливает открытый ключ для проверки цифрововй подписи.
		/// </summary>
		/// <param name="publicKey">Открытый ключ для проверки цифровой подписи.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public override void SetKey(AsymmetricAlgorithm publicKey)
		{
			if (publicKey == null)
			{
				throw ExceptionUtility.ArgumentNull("publicKey");
			}

			if (!(publicKey is Gost3410AsymmetricAlgorithmBase))
			{
				throw ExceptionUtility.ArgumentOutOfRange("publicKey", Resources.ShouldSupportGost3410);
			}

			_publicKey = (Gost3410AsymmetricAlgorithmBase)publicKey;
		}

		/// <summary>
		/// Устанавливает алгоритм хэширования для проверки цифрововй подпси.
		/// </summary>
		/// <param name="hashAlgorithmName">Наименование алгоритма хэширования.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		public override void SetHashAlgorithm(string hashAlgorithmName)
		{
		}

		/// <summary>
		/// Проверяет цифровую подпись.
		/// </summary>
		/// <param name="hash">Значение хэша данных.</param>
		/// <param name="signature">Значение цифровой подписи данных.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull("hash");
			}

			if (signature == null)
			{
				throw ExceptionUtility.ArgumentNull("signature");
			}

			var reverseSignature = (byte[])signature.Clone();
			Array.Reverse(reverseSignature);

			return _publicKey.VerifySignature(hash, reverseSignature);
		}
	}
}