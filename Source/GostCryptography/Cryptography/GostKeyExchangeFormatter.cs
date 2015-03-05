using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Common;
using GostCryptography.Properties;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Реализует шифрацию общего секретного ключа по ГОСТ Р 34.10.
	/// </summary>
	public sealed class GostKeyExchangeFormatter : AsymmetricKeyExchangeFormatter
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		public GostKeyExchangeFormatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="publicKey">Открытый ключ для шифрации общего секретного ключа.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		public GostKeyExchangeFormatter(AsymmetricAlgorithm publicKey)
		{
			SetKey(publicKey);
		}


		private Gost3410AsymmetricAlgorithmBase _publicKey;


		/// <summary>
		/// Параметры алгоритма.
		/// </summary>
		public override string Parameters
		{
			get { return null; }
		}


		/// <summary>
		/// Устанавливает открытый ключ для шифрации общего секретного ключа.
		/// </summary>
		/// <param name="publicKey">Открытый ключ для шифрации общего секретного ключа.</param>
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
		/// Шифрует общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeData">Общий секретный ключ.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public override byte[] CreateKeyExchange(byte[] keyExchangeData)
		{
			if (keyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeData");
			}

			using (var keyExchangeAlgorithm = new Gost28147SymmetricAlgorithm())
			{
				keyExchangeAlgorithm.Key = keyExchangeData;

				return CreateKeyExchangeData(keyExchangeAlgorithm);
			}
		}

		/// <summary>
		/// Шифрует общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeData">Общий секретный ключ.</param>
		/// <param name="keyExchangeAlgorithmType">Тип алгоритма шифрации общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		/// <returns></returns>
		public override byte[] CreateKeyExchange(byte[] keyExchangeData, Type keyExchangeAlgorithmType)
		{
			if (keyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeData");
			}

			using (var keyExchangeAlgorithm = (SymmetricAlgorithm)Activator.CreateInstance(keyExchangeAlgorithmType))
			{
				keyExchangeAlgorithm.Key = keyExchangeData;

				return CreateKeyExchangeData(keyExchangeAlgorithm);
			}
		}

		/// <summary>
		/// Шифрует общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Алгоритм шифрации общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public byte[] CreateKeyExchangeData(SymmetricAlgorithm keyExchangeAlgorithm)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeAlgorithm");
			}

			var keyExchangeInfo = CreateKeyExchangeInfo(keyExchangeAlgorithm);

			return keyExchangeInfo.Encode();
		}

		/// <summary>
		/// Шифрует общий секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Алгоритм шифрации общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		public GostKeyExchange CreateKeyExchangeInfo(SymmetricAlgorithm keyExchangeAlgorithm)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("keyExchangeAlgorithm");
			}

			var keyExchange = new GostKeyExchange();
			var keyExchangeParameters = _publicKey.ExportParameters(false);

			using (var keyExchangeAsym = new Gost3410EphemeralAsymmetricAlgorithm(keyExchangeParameters))
			{
				byte[] encodedKeyExchangeInfo;

				using (var keyExchangeAlg = keyExchangeAsym.CreateKeyExchange(keyExchangeParameters))
				{
					encodedKeyExchangeInfo = keyExchangeAlg.EncodeKeyExchange(keyExchangeAlgorithm, GostKeyExchangeExportMethod.CryptoProKeyExport);
				}

				var keyExchangeInfo = new GostKeyExchangeInfo();
				keyExchangeInfo.Decode(encodedKeyExchangeInfo);

				keyExchange.SessionEncryptedKey = keyExchangeInfo;
				keyExchange.TransportParameters = keyExchangeAsym.ExportParameters(false);
			}

			return keyExchange;
		}
	}
}