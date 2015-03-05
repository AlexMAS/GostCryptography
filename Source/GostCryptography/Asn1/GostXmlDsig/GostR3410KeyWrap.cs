using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Asn1.Encryption.GostR3410;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.GostXmlDsig
{
	class GostR3410KeyWrap : Asn1Type
	{
		public Gost2814789EncryptedKey EncryptedKey;
		public Gost2814789KeyWrapParameters EncryptedParameters;

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

			EncryptedKey = new Gost2814789EncryptedKey();
			EncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0x20, SequenceTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptedParameters = new Gost2814789KeyWrapParameters();
			EncryptedParameters.Decode(buffer, true, parsedLen.Value);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;
			len += EncryptedParameters.Encode(buffer, true);
			len += EncryptedKey.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			EncryptedKey = null;
			EncryptedParameters = null;
		}
	}
}