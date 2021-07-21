using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public abstract class Gost_R3410_PublicKeyParams : Asn1Type
	{
		public Asn1ObjectIdentifier PublicKeyParamSet { get; set; }

		public Asn1ObjectIdentifier DigestParamSet { get; set; }

		public Asn1ObjectIdentifier EncryptionParamSet { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			PublicKeyParamSet = null;
			DigestParamSet = null;
			EncryptionParamSet = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				PublicKeyParamSet = new Asn1ObjectIdentifier();
				PublicKeyParamSet.Decode(buffer, true, parsedLen.Value);
			}
			else
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			if (context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				DigestParamSet = new Asn1ObjectIdentifier();
				DigestParamSet.Decode(buffer, true, parsedLen.Value);
			}

			if (context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				EncryptionParamSet = new Asn1ObjectIdentifier();
				EncryptionParamSet.Decode(buffer, true, parsedLen.Value);
			}

			if (!context.Expired())
			{
				var lastTag = buffer.PeekTag();

				if (lastTag.Equals(0, 0, ObjectIdentifierTypeCode))
				{
					throw ExceptionUtility.CryptographicException(Resources.Asn1SeqOrderException);
				}
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (EncryptionParamSet != null)
			{
				len += EncryptionParamSet.Encode(buffer, true);
			}

			if (DigestParamSet != null)
			{
				len += DigestParamSet.Encode(buffer, true);
			}

			len += PublicKeyParamSet.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}
	}
}