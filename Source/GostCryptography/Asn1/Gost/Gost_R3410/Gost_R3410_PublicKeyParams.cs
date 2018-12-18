using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_28147_89;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public abstract class Gost_R3410_PublicKeyParams : Asn1Type
	{
		public Asn1ObjectIdentifier DigestParamSet { get; set; }

		public Asn1ObjectIdentifier PublicKeyParamSet { get; set; }

		public Gost_28147_89_ParamSet EncryptionParamSet { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			DigestParamSet = null;
			PublicKeyParamSet = null;
			EncryptionParamSet = null;

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
				EncryptionParamSet = new Gost_28147_89_ParamSet();
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
	}
}