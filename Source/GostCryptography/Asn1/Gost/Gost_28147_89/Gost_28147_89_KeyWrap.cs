using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public sealed class Gost_28147_89_KeyWrap : Asn1Type
	{
		public Gost_28147_89_EncryptedKey EncryptedKey { get; set; }

		public Gost_28147_89_KeyWrapParams EncryptedParams { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			EncryptedKey = null;
			EncryptedParams = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0x20, SequenceTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptedKey = new Gost_28147_89_EncryptedKey();
			EncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0x20, SequenceTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptedParams = new Gost_28147_89_KeyWrapParams();
			EncryptedParams.Decode(buffer, true, parsedLen.Value);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;
			len += EncryptedParams.Encode(buffer, true);
			len += EncryptedKey.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}
	}
}