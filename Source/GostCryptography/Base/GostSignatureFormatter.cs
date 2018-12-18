using System;
using System.Security.Cryptography;

using GostCryptography.Properties;

namespace GostCryptography.Base
{
	/// <summary>
	/// Класс вычисления цифровой подписи ГОСТ.
	/// </summary>
	public class GostSignatureFormatter : AsymmetricSignatureFormatter
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
		public GostSignatureFormatter(AsymmetricAlgorithm privateKey) : this()
		{
			SetKey(privateKey);
		}


		private GostAsymmetricAlgorithm _privateKey;


		/// <inheritdoc />
		public override void SetKey(AsymmetricAlgorithm privateKey)
		{
			if (privateKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(privateKey));
			}

			if (!(privateKey is GostAsymmetricAlgorithm gostPrivateKey))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(privateKey), Resources.ShouldSupportGost3410);
			}

			_privateKey = gostPrivateKey;
		}

		/// <inheritdoc />
		public override void SetHashAlgorithm(string hashAlgorithmName)
		{
		}

		/// <inheritdoc />
		public override byte[] CreateSignature(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hash));
			}

			var reverseSignature = _privateKey.CreateSignature(hash);
			Array.Reverse(reverseSignature);

			return reverseSignature;
		}
	}
}