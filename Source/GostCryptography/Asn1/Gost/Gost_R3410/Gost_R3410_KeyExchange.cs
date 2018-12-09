using System;

using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Asn1.Gost.PublicKey;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	/// <summary>
	/// Информация о ключе цифровой подписи ГОСТ Р 34.10.
	/// </summary>
	public abstract class Gost_R3410_KeyExchange
	{
		/// <summary>
		/// Информация о зашифрованном ключе ГОСТ 28147-89.
		/// </summary>
		public Gost_28147_89_KeyExchangeInfo SessionEncryptedKey { get; set; }

		/// <summary>
		/// Параметры ключа цифровой подписи ГОСТ Р 34.10.
		/// </summary>
		public Gost_R3410_KeyExchangeParams TransportParameters { get; set; }


		protected abstract OidValue KeyAlgorithm { get; }

		protected abstract Gost_R3410_PublicKeyParams CreatePublicKeyParams();

		protected abstract Gost_R3410_KeyExchangeParams CreateKeyExchangeParams();


		/// <summary>
		/// Расшифровать информацию о ключе.
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
				var keyTransport = new Gost_R3410_KeyTransport();
				keyTransport.Decode(asnDecoder);
				DecodeSessionKey(keyTransport);
				DecodePublicKey(keyTransport);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, nameof(Gost_R3410_KeyTransport));
			}
		}

		private void DecodeSessionKey(Gost_R3410_KeyTransport keyTransport)
		{
			SessionEncryptedKey = new Gost_28147_89_KeyExchangeInfo
			{
				EncryptionParamSet = keyTransport.TransportParams.EncryptionParamSet.Oid.Value,
				EncryptedKey = keyTransport.SessionEncryptedKey.EncryptedKey.Value,
				Mac = keyTransport.SessionEncryptedKey.MacKey.Value,
				Ukm = keyTransport.TransportParams.Ukm.Value
			};
		}

		private void DecodePublicKey(Gost_R3410_KeyTransport keyTransport)
		{
			var publicKeyInfo = keyTransport.TransportParams.EphemeralPublicKey;
			var publicKeyAlgOid = publicKeyInfo.Algorithm.Algorithm.Oid.Value;

			if (!publicKeyAlgOid.Equals(KeyAlgorithm.Value))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlg, publicKeyAlgOid);
			}

			var choice = publicKeyInfo.Algorithm.Parameters as Asn1Choice;

			if (choice == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlgorithmParameters);
			}

			var publicKeyParams = choice.GetElement() as Gost_R3410_PublicKeyParams;

			if (publicKeyParams == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlgorithmParameters);
			}

			var asnDecoder = new Asn1BerDecodeBuffer(publicKeyInfo.SubjectPublicKey.Value);
			var publicKey = new Asn1OctetString();
			publicKey.Decode(asnDecoder);

			TransportParameters = CreateKeyExchangeParams();
			TransportParameters.DigestParamSet = publicKeyParams.DigestParamSet.Oid.Value;
			TransportParameters.PublicKeyParamSet = publicKeyParams.PublicKeyParamSet.Oid.Value;
			TransportParameters.EncryptionParamSet = publicKeyParams.EncryptionParamSet?.Oid.Value;
			TransportParameters.PublicKey = publicKey.Value;
			TransportParameters.PrivateKey = null;
		}


		/// <summary>
		/// Зашифровать информацию о ключе.
		/// </summary>
		public byte[] Encode()
		{
			var asnEncoder = new Asn1BerEncodeBuffer();
			var keyTransport = new Gost_R3410_KeyTransport();

			try
			{
				keyTransport.SessionEncryptedKey = new Gost_28147_89_EncryptedKey
				{
					EncryptedKey = new Gost_28147_89_Key(SessionEncryptedKey.EncryptedKey),
					MacKey = new Gost_28147_89_Mac(SessionEncryptedKey.Mac)
				};

				keyTransport.TransportParams = new Gost_R3410_TransportParams
				{
					EncryptionParamSet = Gost_28147_89_ParamSet.FromString(SessionEncryptedKey.EncryptionParamSet),
					EphemeralPublicKey = EncodePublicKey(TransportParameters),
					Ukm = new Asn1OctetString(SessionEncryptedKey.Ukm)
				};

				keyTransport.Encode(asnEncoder);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, nameof(Gost_R3410_KeyTransport));
			}

			return asnEncoder.MsgCopy;
		}

		private SubjectPublicKeyInfo EncodePublicKey(Gost_R3410_KeyExchangeParams transportParameters)
		{
			var asnEncoder = new Asn1BerEncodeBuffer();
			var publicKey = new Asn1OctetString(transportParameters.PublicKey);
			publicKey.Encode(asnEncoder);

			var publicKeyValue = asnEncoder.MsgCopy;

			var publicKeyInfo = new SubjectPublicKeyInfo
			{
				SubjectPublicKey = new Asn1BitString(publicKeyValue.Length * 8, publicKeyValue)
			};

			var publicKeyParams = CreatePublicKeyParams();
			publicKeyParams.PublicKeyParamSet = new Asn1ObjectIdentifier(OidValue.FromString(transportParameters.PublicKeyParamSet));
			publicKeyParams.DigestParamSet = new Asn1ObjectIdentifier(OidValue.FromString(transportParameters.DigestParamSet));
			publicKeyParams.EncryptionParamSet = Gost_28147_89_ParamSet.FromString(transportParameters.EncryptionParamSet);

			asnEncoder.Reset();
			publicKeyParams.Encode(asnEncoder);

			var publicKeyAlgOid = new Asn1ObjectIdentifier(KeyAlgorithm);
			publicKeyInfo.Algorithm = new AlgorithmIdentifier(publicKeyAlgOid, new Asn1OpenType(asnEncoder.MsgCopy));

			return publicKeyInfo;
		}
	}
}