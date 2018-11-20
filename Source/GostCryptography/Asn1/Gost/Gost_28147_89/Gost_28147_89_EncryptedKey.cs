using GostCryptography.Asn1.Ber;
using GostCryptography.Properties;

namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public sealed class Gost_28147_89_EncryptedKey : Asn1Type
	{
		public Gost_28147_89_Key EncryptedKey { get; set; }

		public Gost_28147_89_Mac MacKey { get; set; }

		public Gost_28147_89_Key MaskKey { get; set; }


		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			EncryptedKey = null;
			MacKey = null;
			MaskKey = null;

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			EncryptedKey = new Gost_28147_89_Key();
			EncryptedKey.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0x80, 0, EocTypeCode, parsedLen, true))
			{
				MaskKey = new Gost_28147_89_Key();
				MaskKey.Decode(buffer, false, parsedLen.Value);
			}

			if (!context.MatchElemTag(0, 0, OctetStringTypeCode, parsedLen, false))
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1MissingRequiredException, buffer.ByteCount);
			}

			MacKey = new Gost_28147_89_Mac();
			MacKey.Decode(buffer, true, parsedLen.Value);

			if (MacKey.Length != 4)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(MacKey.Length), MacKey.Length);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (MacKey.Length != 4)
			{
				throw ExceptionUtility.CryptographicException(Resources.Asn1ConsVioException, nameof(MacKey.Length), MacKey.Length);
			}

			len += MacKey.Encode(buffer, true);

			if (MaskKey != null)
			{
				var maskKeyLen = MaskKey.Encode(buffer, false);
				len += maskKeyLen;
				len += buffer.EncodeTagAndLength(0x80, 0, EocTypeCode, maskKeyLen);
			}

			len += EncryptedKey.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}
	}
}