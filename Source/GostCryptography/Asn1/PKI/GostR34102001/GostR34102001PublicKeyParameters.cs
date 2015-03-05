using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Encryption.Gost2814789;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.PKI.GostR34102001
{
	class GostR34102001PublicKeyParameters : Asn1Type
	{
		public Asn1ObjectIdentifier DigestParamSet;
		public Asn1ObjectIdentifier PublicKeyParamSet;
		public Gost2814789ParamSet EncryptionParamSet;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			PublicKeyParamSet = new Asn1ObjectIdentifier();
			PublicKeyParamSet.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			DigestParamSet = new Asn1ObjectIdentifier();
			DigestParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				EncryptionParamSet = new Gost2814789ParamSet();
				EncryptionParamSet.Decode(buffer, true, parsedLen.Value);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (EncryptionParamSet != null)
			{
				len += EncryptionParamSet.Encode(buffer, true);
			}

			len += DigestParamSet.Encode(buffer, true);
			len += PublicKeyParamSet.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			DigestParamSet = null;
			PublicKeyParamSet = null;
			EncryptionParamSet = null;
		}
	}
}