using System;

using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	/// <summary>
	/// Параметры ключа цифровой подписи ГОСТ Р 34.10.
	/// </summary>
	public abstract class Gost_R3410_KeyExchangeParams
	{
		/// <inheritdoc />
		protected Gost_R3410_KeyExchangeParams()
		{
		}

		/// <inheritdoc />
		protected Gost_R3410_KeyExchangeParams(Gost_R3410_KeyExchangeParams other)
		{
			DigestParamSet = other.DigestParamSet;
			PublicKeyParamSet = other.PublicKeyParamSet;
			EncryptionParamSet = other.EncryptionParamSet;
			PublicKey = other.PublicKey;
			PrivateKey = other.PrivateKey;
		}


		/// <summary>
		/// Идентификатор OID параметров хэширования.
		/// </summary>
		public string DigestParamSet { get; set; }

		/// <summary>
		/// Идентификатор OID параметров открытого ключа.
		/// </summary>
		public string PublicKeyParamSet { get; set; }

		/// <summary>
		/// Идентификатор OID параметров шифрования.
		/// </summary>
		public string EncryptionParamSet { get; set; }

		/// <summary>
		/// Открытый ключ.
		/// </summary>
		public byte[] PublicKey { get; set; }

		/// <summary>
		/// Закрытый ключ.
		/// </summary>
		public byte[] PrivateKey { get; set; }


		public abstract Gost_R3410_KeyExchangeParams Clone();

		protected abstract Gost_R3410_PublicKey CreatePublicKey();

		protected abstract Gost_R3410_PublicKeyParams CreatePublicKeyParams();


		/// <summary>
		/// Расшифровать параметры.
		/// </summary>
		public void DecodeParameters(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(data));
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var publicKeyParams = CreatePublicKeyParams();
				publicKeyParams.Decode(asnDecoder);

				DigestParamSet = publicKeyParams.DigestParamSet.Oid.Value;
				PublicKeyParamSet = publicKeyParams.PublicKeyParamSet.Oid.Value;
				EncryptionParamSet = publicKeyParams.EncryptionParamSet?.Oid.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, nameof(Gost_R3410_PublicKeyParams));
			}
		}

		/// <summary>
		/// Зашифровать параметры.
		/// </summary>
		public byte[] EncodeParameters()
		{
			byte[] data;

			try
			{
				var publicKeyParams = CreatePublicKeyParams();
				publicKeyParams.DigestParamSet = new Asn1ObjectIdentifier(OidValue.FromString(DigestParamSet));
				publicKeyParams.PublicKeyParamSet = new Asn1ObjectIdentifier(OidValue.FromString(PublicKeyParamSet));
				publicKeyParams.EncryptionParamSet = Gost_28147_89_ParamSet.FromString(EncryptionParamSet);

				var asnEncoder = new Asn1BerEncodeBuffer();
				publicKeyParams.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, nameof(Gost_R3410_PublicKeyParams));
			}

			return data;
		}


		/// <summary>
		/// Расшифровать публичный ключ.
		/// </summary>
		public void DecodePublicKey(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(data));
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var publicKey = CreatePublicKey();
				publicKey.Decode(asnDecoder);

				PublicKey = publicKey.Value;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, nameof(Gost_R3410_PublicKey));
			}
		}

		/// <summary>
		/// Зашифровать публичный ключ.
		/// </summary>
		public byte[] EncodePublicKey()
		{
			byte[] data;

			try
			{
				var publicKey = CreatePublicKey();
				publicKey.Value = PublicKey;

				var asnEncoder = new Asn1BerEncodeBuffer();
				publicKey.Encode(asnEncoder);
				data = asnEncoder.MsgCopy;
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, nameof(Gost_R3410_PublicKeyParams));
			}

			return data;
		}
	}
}