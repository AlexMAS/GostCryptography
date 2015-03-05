using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Asn1.Encryption.GostR3410;
using GostCryptography.Asn1.GostXmlDsig;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Информация о зашифрованном ключе по ГОСТ 28147.
	/// </summary>
	public sealed class GostKeyExchangeInfo
	{
		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet;

		/// <summary>
		/// Зашифрованный ключ.
		/// </summary>
		public byte[] EncryptedKey;

		/// <summary>
		/// Контрольная сумма зашифрованного ключа (Message Authentication Code, MAC).
		/// </summary>
		public byte[] Mac;

		/// <summary>
		/// Материал ключа пользователя (User Keying Material, UKM).
		/// </summary>
		public byte[] Ukm;


		public byte[] Encode()
		{
			byte[] data;

			var keyWrap = new GostR3410KeyWrap();

			try
			{
				keyWrap.EncryptedKey = new Gost2814789EncryptedKey
									   {
										   EncryptedKey = new Gost2814789Key(EncryptedKey),
										   MacKey = new Gost2814789Mac(Mac)
									   };

				keyWrap.EncryptedParameters = new Gost2814789KeyWrapParameters
											  {
												  EncryptionParamSet = CreateEncryptionParamSet(EncryptionParamSet),
												  Ukm = new Asn1OctetString(Ukm)
											  };

				var asnEncoder = new Asn1BerEncodeBuffer();
				keyWrap.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(GostR3410KeyWrap).FullName);
			}

			return data;
		}

		public void Decode(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var keyWrap = new GostR3410KeyWrap();
				keyWrap.Decode(asnDecoder);

				EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(keyWrap.EncryptedParameters.EncryptionParamSet);
				EncryptedKey = keyWrap.EncryptedKey.EncryptedKey.Value;
				Mac = keyWrap.EncryptedKey.MacKey.Value;
				Ukm = keyWrap.EncryptedParameters.Ukm.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(GostR3410KeyWrap).FullName);
			}
		}


		public static string DecodeEncryptionParamSet(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			string encryptionParamSet;

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var parameters = new Gost2814789BlobParameters();
				parameters.Decode(asnDecoder);

				encryptionParamSet = Asn1ObjectIdentifier.ToOidString(parameters.EncryptionParamSet);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(Gost2814789BlobParameters).FullName);
			}

			return encryptionParamSet;
		}

		public static byte[] EncodeEncryptionParamSet(string encryptionParamSet)
		{
			if (encryptionParamSet == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptionParamSet");
			}

			byte[] data;

			try
			{
				var asnEncoder = new Asn1BerEncodeBuffer();
				var parameters = new Gost2814789BlobParameters { EncryptionParamSet = CreateEncryptionParamSet(encryptionParamSet) };
				parameters.Encode(asnEncoder);

				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, typeof(Gost2814789BlobParameters).FullName);
			}

			return data;
		}


		private static Gost2814789ParamSet CreateEncryptionParamSet(string value)
		{
			return (value != null) ? new Gost2814789ParamSet(Asn1ObjectIdentifier.FromOidString(value).Value) : null;
		}
	}
}