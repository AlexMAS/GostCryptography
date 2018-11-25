using System;
using System.Security.Cryptography;

using GostCryptography.Properties;

namespace GostCryptography.Base
{
	/// <summary>
	/// Класс проверки цифровой подписи ГОСТ.
	/// </summary>
	public class GostSignatureDeformatter : AsymmetricSignatureDeformatter
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
		public GostSignatureDeformatter(AsymmetricAlgorithm publicKey) : this()
		{
			SetKey(publicKey);
		}


		private GostAsymmetricAlgorithm _publicKey;


		/// <inheritdoc />
		public override void SetKey(AsymmetricAlgorithm publicKey)
		{
			if (publicKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(publicKey));
			}

			if (!(publicKey is GostAsymmetricAlgorithm gostPublicKey))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(publicKey), Resources.ShouldSupportGost3410);
			}

			_publicKey = gostPublicKey;
		}

		/// <inheritdoc />
		public override void SetHashAlgorithm(string hashAlgorithmName)
		{
		}

		/// <inheritdoc />
		public override bool VerifySignature(byte[] hash, byte[] signature)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hash));
			}

			if (signature == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(signature));
			}

			var reverseSignature = (byte[])signature.Clone();
			Array.Reverse(reverseSignature);

			return _publicKey.VerifySignature(hash, reverseSignature);
		}
	}
}