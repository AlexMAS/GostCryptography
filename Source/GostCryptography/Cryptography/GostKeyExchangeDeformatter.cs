using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Common;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализует дешифрацию общего секретного ключа по ГОСТ Р 34.10.
	/// </summary>
	public sealed class GostKeyExchangeDeformatter : AsymmetricKeyExchangeDeformatter
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		public GostKeyExchangeDeformatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="privateKey">Секретный ключ для расшифровки общего секретного ключа.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public GostKeyExchangeDeformatter(AsymmetricAlgorithm privateKey)
		{
			SetKey(privateKey);
		}


		private Gost3410AsymmetricAlgorithmBase _privateKey;


		/// <summary>
		/// Параметры алгоритма.
		/// </summary>
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


		/// <summary>
		/// Устанавливает секретный ключ для расшифровки общего секретного ключа.
		/// </summary>
		/// <param name="privateKey">Секретный ключ для расшифровки общего секретного ключа.</param>
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
		/// Дешифрует общий секретный ключ.
		/// </summary>
		/// <param name="encryptedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public override byte[] DecryptKeyExchange(byte[] encryptedKeyExchangeData)
		{
			return DecryptKeyExchangeAlgorithm(encryptedKeyExchangeData).Key;
		}

		/// <summary>
		/// Дешифрует общий секретный ключ.
		/// </summary>
		/// <param name="encryptedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public SymmetricAlgorithm DecryptKeyExchangeAlgorithm(byte[] encryptedKeyExchangeData)
		{
			if (encryptedKeyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptedKeyExchangeData");
			}

			var keyExchange = new GostKeyExchange();
			keyExchange.Decode(encryptedKeyExchangeData);

			return DecryptKeyExchangeAlgorithm(keyExchange);
		}

		/// <summary>
		/// Дешифрует общий секретный ключ.
		/// </summary>
		/// <param name="encryptedKeyExchangeInfo">Зашифрованный общий секретный ключ.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public SymmetricAlgorithm DecryptKeyExchangeAlgorithm(GostKeyExchange encryptedKeyExchangeInfo)
		{
			if (encryptedKeyExchangeInfo == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptedKeyExchangeInfo");
			}

			var keyExchangeAlg = _privateKey.CreateKeyExchange(encryptedKeyExchangeInfo.TransportParameters);
			var encodedKeyExchangeInfo = encryptedKeyExchangeInfo.SessionEncryptedKey.Encode();

			return keyExchangeAlg.DecodeKeyExchange(encodedKeyExchangeInfo, GostKeyExchangeExportMethod.CryptoProKeyExport);
		}
	}
}