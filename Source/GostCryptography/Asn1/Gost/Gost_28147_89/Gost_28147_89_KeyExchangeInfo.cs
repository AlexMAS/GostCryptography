using System;

using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	/// <summary>
	/// Информация о зашифрованном ключе ГОСТ 28147-89.
	/// </summary>
	public sealed class Gost_28147_89_KeyExchangeInfo
	{
		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet { get; set; }

		/// <summary>
		/// Зашифрованный ключ.
		/// </summary>
		public byte[] EncryptedKey { get; set; }

		/// <summary>
		/// Контрольная сумма зашифрованного ключа (Message Authentication Code, MAC).
		/// </summary>
		public byte[] Mac { get; set; }

		/// <summary>
		/// Материал ключа пользователя (User Keying Material, UKM).
		/// </summary>
		public byte[] Ukm { get; set; }


		/// <summary>
		/// Зашифровать информацию о ключе.
		/// </summary>
		public void Decode(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(data));
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var keyWrap = new Gost_28147_89_KeyWrap();
				keyWrap.Decode(asnDecoder);

				EncryptionParamSet = keyWrap.EncryptedParams.EncryptionParamSet.Oid.Value;
				EncryptedKey = keyWrap.EncryptedKey.EncryptedKey.Value;
				Mac = keyWrap.EncryptedKey.MacKey.Value;
				Ukm = keyWrap.EncryptedParams.Ukm.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, nameof(Gost_28147_89_KeyWrap));
			}
		}

		/// <summary>
		/// Расшифровать информацию о ключе.
		/// </summary>
		public byte[] Encode()
		{
			byte[] data;

			var keyWrap = new Gost_28147_89_KeyWrap();

			try
			{
				keyWrap.EncryptedKey = new Gost_28147_89_EncryptedKey
				{
					EncryptedKey = new Gost_28147_89_Key(EncryptedKey),
					MacKey = new Gost_28147_89_Mac(Mac)
				};

				keyWrap.EncryptedParams = new Gost_28147_89_KeyWrapParams
				{
					EncryptionParamSet = Gost_28147_89_ParamSet.FromString(EncryptionParamSet),
					Ukm = new Asn1OctetString(Ukm)
				};

				var asnEncoder = new Asn1BerEncodeBuffer();
				keyWrap.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, nameof(Gost_28147_89_KeyWrap));
			}

			return data;
		}


		/// <summary>
		/// Расшифровать идентификатор OID параметров шифрования.
		/// </summary>
		public static string DecodeEncryptionParamSet(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(data));
			}

			string encryptionParamSet;

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var parameters = new Gost_28147_89_BlobParams();
				parameters.Decode(asnDecoder);

				encryptionParamSet = parameters.EncryptionParamSet.Oid.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(Gost_28147_89_BlobParams).FullName);
			}

			return encryptionParamSet;
		}

		/// <summary>
		/// Зашифровать идентификатор OID параметров шифрования.
		/// </summary>
		public static byte[] EncodeEncryptionParamSet(string encryptionParamSet)
		{
			if (encryptionParamSet == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(encryptionParamSet));
			}

			byte[] data;

			try
			{
				var parameters = new Gost_28147_89_BlobParams { EncryptionParamSet = Gost_28147_89_ParamSet.FromString(encryptionParamSet) };

				var asnEncoder = new Asn1BerEncodeBuffer();
				parameters.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, nameof(Gost_28147_89_BlobParams));
			}

			return data;
		}
	}
}