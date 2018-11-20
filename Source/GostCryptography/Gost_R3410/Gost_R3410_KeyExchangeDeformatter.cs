using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс для реализации дешифрования общего секретного ключа по ГОСТ Р 34.10.
	/// </summary>
	/// <typeparam name="TKey">Информация о ключе цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyParams">Параметры ключа цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyAlgorithm">Алгоритм общего секретного ключа ГОСТ Р 34.10.</typeparam>
	public abstract class Gost_R3410_KeyExchangeDeformatter<TKey, TKeyParams, TKeyAlgorithm> : GostKeyExchangeDeformatter
		where TKey : Gost_R3410_KeyExchange, new()
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		protected Gost_R3410_KeyExchangeDeformatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="privateKey">Секретный ключ для расшифровки общего секретного ключа.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		protected Gost_R3410_KeyExchangeDeformatter(AsymmetricAlgorithm privateKey)
		{
			SetKey(privateKey);
		}


		private Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> _privateKey;


		/// <inheritdoc />
		public override string Parameters
		{
			get
			{
				return null;
			}
			set
			{
			}
		}


		/// <inheritdoc />
		public override void SetKey(AsymmetricAlgorithm privateKey)
		{
			if (privateKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(privateKey));
			}

			if (!(privateKey is Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> gostPublicKey))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(privateKey), Resources.ShouldSupportGost3410);
			}

			_privateKey = gostPublicKey;
		}

		/// <inheritdoc />
		public override byte[] DecryptKeyExchange(byte[] encryptedKeyExchangeData)
		{
			var symmetricAlgorithm = DecryptKeyExchangeAlgorithm(encryptedKeyExchangeData);

			return symmetricAlgorithm.Key;
		}

		/// <inheritdoc />
		public override SymmetricAlgorithm DecryptKeyExchangeAlgorithm(byte[] encryptedKeyExchangeData)
		{
			if (encryptedKeyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptedKeyExchangeData));
			}

			var keyExchange = new TKey();
			keyExchange.Decode(encryptedKeyExchangeData);

			return DecryptKeyExchangeAlgorithm(keyExchange);
		}

		private SymmetricAlgorithm DecryptKeyExchangeAlgorithm(TKey encryptedKeyExchangeInfo)
		{
			if (encryptedKeyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptedKeyExchangeInfo));
			}

			var keyExchangeParameters = (TKeyParams)encryptedKeyExchangeInfo.TransportParameters;
			var keyExchangeAlg = _privateKey.CreateKeyExchange(keyExchangeParameters);
			var encodedKeyExchangeInfo = encryptedKeyExchangeInfo.SessionEncryptedKey.Encode();

			return keyExchangeAlg.DecodeKeyExchange(encodedKeyExchangeInfo, GostKeyExchangeExportMethod.CryptoProKeyExport);
		}
	}
}