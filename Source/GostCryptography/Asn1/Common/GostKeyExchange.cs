using System;
using System.Security.Cryptography;

using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Asn1.Encryption.GostR3410;
using GostCryptography.Asn1.PKI.Explicit88;
using GostCryptography.Asn1.PKI.GostR34102001;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Common
{
	/// <summary>
	/// Информация о зашифрованном общем секретном ключе.
	/// </summary>
	public sealed class GostKeyExchange
	{
		/// <summary>
		/// Информация о зашифрованном ключе по ГОСТ 28147.
		/// </summary>
		public GostKeyExchangeInfo SessionEncryptedKey;

		/// <summary>
		/// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
		/// </summary>
		public GostKeyExchangeParameters TransportParameters;


		public void Decode(byte[] data)
		{
			if (data == null)
			{
				throw ExceptionUtility.ArgumentNull("data");
			}

			try
			{
				var asnDecoder = new Asn1BerDecodeBuffer(data);
				var keyTransport = new GostR3410KeyTransport();
				keyTransport.Decode(asnDecoder);

				SessionEncryptedKey = DecodeSessionKey(keyTransport);
				TransportParameters = DecodePublicKey(keyTransport);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1DecodeError, typeof(GostR3410KeyTransport).FullName);
			}
		}

		private static GostKeyExchangeInfo DecodeSessionKey(GostR3410KeyTransport keyTransport)
		{
			return new GostKeyExchangeInfo
				   {
					   EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(keyTransport.TransportParameters.EncryptionParamSet),
					   EncryptedKey = keyTransport.SessionEncryptedKey.EncryptedKey.Value,
					   Mac = keyTransport.SessionEncryptedKey.MacKey.Value,
					   Ukm = keyTransport.TransportParameters.Ukm.Value,
				   };
		}

		private static GostKeyExchangeParameters DecodePublicKey(GostR3410KeyTransport keyTransport)
		{
			var publicKeyInfo = keyTransport.TransportParameters.EphemeralPublicKey;
			var publicKeyAlgOid = Asn1ObjectIdentifier.ToOidString(publicKeyInfo.Algorithm.Algorithm);

			if (!publicKeyAlgOid.Equals(GostR34102001Constants.IdGostR34102001String))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlg, publicKeyAlgOid);
			}

			var choice = publicKeyInfo.Algorithm.Parameters as Asn1Choice;

			if (choice == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlgorithmParameters);
			}

			var publicKeyParams = choice.GetElement() as GostR34102001PublicKeyParameters;

			if (publicKeyParams == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1DecodeAlgorithmParameters);
			}

			var asnDecoder = new Asn1BerDecodeBuffer(publicKeyInfo.SubjectPublicKey.Value);
			var publicKey = new Asn1OctetString();
			publicKey.Decode(asnDecoder);

			return new GostKeyExchangeParameters
				   {
					   DigestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParams.DigestParamSet),
					   PublicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParams.PublicKeyParamSet),
					   EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParams.EncryptionParamSet),
					   PublicKey = publicKey.Value,
					   PrivateKey = null
				   };
		}


		public byte[] Encode()
		{
			var asnEncoder = new Asn1BerEncodeBuffer();
			var keyTransport = new GostR3410KeyTransport();

			try
			{
				keyTransport.SessionEncryptedKey = new Gost2814789EncryptedKey
												   {
													   EncryptedKey = new Gost2814789Key(SessionEncryptedKey.EncryptedKey),
													   MacKey = new Gost2814789Mac(SessionEncryptedKey.Mac)
												   };

				keyTransport.TransportParameters = new GostR3410TransportParameters
												   {
													   Ukm = new Asn1OctetString(SessionEncryptedKey.Ukm),
													   EncryptionParamSet = CreateEncryptionParamSet(SessionEncryptedKey.EncryptionParamSet),
													   EphemeralPublicKey = EncodePublicKey(TransportParameters)
												   };

				keyTransport.Encode(asnEncoder);
			}
			catch (Exception exception)
			{
				throw ExceptionUtility.CryptographicException(exception, Resources.Asn1EncodeError, typeof(GostR3410KeyTransport).FullName);
			}

			return asnEncoder.MsgCopy;
		}

		private static SubjectPublicKeyInfo EncodePublicKey(GostKeyExchangeParameters transportParameters)
		{
			var asnEncoder = new Asn1BerEncodeBuffer();
			var publicKey = new Asn1OctetString(transportParameters.PublicKey);
			publicKey.Encode(asnEncoder);

			var publicKeyValue = asnEncoder.MsgCopy;

			var publicKeyInfo = new SubjectPublicKeyInfo
								{
									SubjectPublicKey = new Asn1BitString(publicKeyValue.Length * 8, publicKeyValue)
								};

			var publicKeyParams = new GostR34102001PublicKeyParameters
							 {
								 PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(transportParameters.PublicKeyParamSet),
								 DigestParamSet = Asn1ObjectIdentifier.FromOidString(transportParameters.DigestParamSet),
								 EncryptionParamSet = CreateEncryptionParamSet(transportParameters.EncryptionParamSet)
							 };

			asnEncoder.Reset();
			publicKeyParams.Encode(asnEncoder);

			var publicKeyAlgOid = new Asn1ObjectIdentifier(GostR34102001Constants.IdGostR34102001);
			publicKeyInfo.Algorithm = new AlgorithmIdentifier(publicKeyAlgOid, new Asn1OpenType(asnEncoder.MsgCopy));

			return publicKeyInfo;
		}

		private static Gost2814789ParamSet CreateEncryptionParamSet(string value)
		{
			return (value != null) ? new Gost2814789ParamSet(Asn1ObjectIdentifier.FromOidString(value).Value) : null;
		}
	}
}