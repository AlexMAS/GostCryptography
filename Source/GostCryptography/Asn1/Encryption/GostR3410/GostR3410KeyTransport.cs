using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Encryption.GostR3410
{
	class GostR3410KeyTransport : Asn1Type
	{
		public Gost2814789EncryptedKey SessionEncryptedKey;
		public GostR3410TransportParameters TransportParameters;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0x20, SequenceTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			SessionEncryptedKey = new Gost2814789EncryptedKey();
			SessionEncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0x80, 0x20, EocTypeCode, parsedLen, true))
			{
				TransportParameters = new GostR3410TransportParameters();
				TransportParameters.Decode(buffer, false, parsedLen.Value);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (TransportParameters != null)
			{
				var tpLength = TransportParameters.Encode(buffer, false);

				len += tpLength;
				len += buffer.EncodeTagAndLength(0x80, 0x20, EocTypeCode, tpLength);
			}

			len += SessionEncryptedKey.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			SessionEncryptedKey = null;
			TransportParameters = null;
		}
	}
}