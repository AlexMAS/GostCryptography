using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс для реализации шифрования общего секретного ключа по ГОСТ Р 34.10.
	/// </summary>
	/// <typeparam name="TKey">Информация о ключе цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyParams">Параметры ключа цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyAlgorithm">Алгоритм общего секретного ключа ГОСТ Р 34.10.</typeparam>
	public abstract class Gost_R3410_KeyExchangeFormatter<TKey, TKeyParams, TKeyAlgorithm> : GostKeyExchangeFormatter
		where TKey : Gost_R3410_KeyExchange, new()
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		/// <summary>
		/// Конструктор.
		/// </summary>
		protected Gost_R3410_KeyExchangeFormatter()
		{
		}

		/// <summary>
		/// Конструктор.
		/// </summary>
		/// <param name="publicKey">Открытый ключ для шифрации общего секретного ключа.</param>
		/// <exception cref="ArgumentOutOfRangeException"></exception>
		/// <exception cref="ArgumentNullException"></exception>
		protected Gost_R3410_KeyExchangeFormatter(AsymmetricAlgorithm publicKey)
		{
			SetKey(publicKey);
		}


		private Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> _publicKey;


		/// <inheritdoc />
		public override string Parameters => null;


		/// <inheritdoc />
		public override void SetKey(AsymmetricAlgorithm publicKey)
		{
			if (publicKey == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(publicKey));
			}

			if (!(publicKey is Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> gostPublicKey))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(publicKey), Resources.ShouldSupportGost3410);
			}

			_publicKey = gostPublicKey;
		}

		/// <inheritdoc />
		public override byte[] CreateKeyExchange(byte[] keyExchangeData)
		{
			if (keyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeData));
			}

			using (var keyExchangeAlgorithm = new Gost_28147_89_SymmetricAlgorithm(_publicKey.ProviderType))
			{
				keyExchangeAlgorithm.Key = keyExchangeData;

				return CreateKeyExchangeData(keyExchangeAlgorithm);
			}
		}

		/// <inheritdoc />
		public override byte[] CreateKeyExchange(byte[] keyExchangeData, Type keyExchangeAlgorithmType)
		{
			if (keyExchangeData == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeData));
			}

			if (keyExchangeAlgorithmType == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeAlgorithmType));
			}

			if (!typeof(GostSymmetricAlgorithm).IsAssignableFrom(keyExchangeAlgorithmType))
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(keyExchangeAlgorithmType));
			}

			GostSymmetricAlgorithm keyExchangeAlgorithm;

			if (_publicKey != null)
			{
				var constructorInfo = keyExchangeAlgorithmType.GetConstructor(new[] { typeof(ProviderType) });
				keyExchangeAlgorithm = (GostSymmetricAlgorithm)constructorInfo.Invoke(new object[] { _publicKey.ProviderType });
			}
			else
			{
				keyExchangeAlgorithm = (GostSymmetricAlgorithm)Activator.CreateInstance(keyExchangeAlgorithmType);
			}

			using (keyExchangeAlgorithm)
			{
				keyExchangeAlgorithm.Key = keyExchangeData;

				return CreateKeyExchangeData(keyExchangeAlgorithm);
			}
		}

		/// <inheritdoc />
		public override byte[] CreateKeyExchangeData(SymmetricAlgorithm keyExchangeAlgorithm)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeAlgorithm));
			}

			var keyExchangeInfo = CreateKeyExchangeInfo(keyExchangeAlgorithm);

			return keyExchangeInfo.Encode();
		}

		private TKey CreateKeyExchangeInfo(SymmetricAlgorithm keyExchangeAlgorithm)
		{
			if (keyExchangeAlgorithm == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyExchangeAlgorithm));
			}

			var keyExchange = new TKey();
			var keyExchangeParameters = _publicKey.ExportParameters(false);

			using (var keyExchangeAsym = CreateEphemeralAlgorithm(_publicKey.ProviderType, keyExchangeParameters))
			{
				byte[] encodedKeyExchangeInfo;

				using (var keyExchangeAlg = keyExchangeAsym.CreateKeyExchange(keyExchangeParameters))
				{
					encodedKeyExchangeInfo = keyExchangeAlg.EncodeKeyExchange(keyExchangeAlgorithm, GostKeyExchangeExportMethod.CryptoProKeyExport);
				}

				var keyExchangeInfo = new Gost_28147_89_KeyExchangeInfo();
				keyExchangeInfo.Decode(encodedKeyExchangeInfo);

				keyExchange.SessionEncryptedKey = keyExchangeInfo;
				keyExchange.TransportParameters = keyExchangeAsym.ExportParameters(false);
			}

			return keyExchange;
		}


		/// <summary>
		/// Создает экземпляр алгоритма шифрования общего секретного ключа.
		/// </summary>
		protected abstract Gost_R3410_EphemeralAsymmetricAlgorithm<TKeyParams, TKeyAlgorithm> CreateEphemeralAlgorithm(ProviderType providerType, TKeyParams keyExchangeParameters);
	}
}